//! Content-addressed object access for shards, weights and metrics.
//!
//! One file per object at `<cache_dir>/<hex-of-cid>`, the same layout the peer mesh
//! serves (`mesh::server`). The worker reads through [`fetch`] and publishes through
//! [`store`]:
//!
//! * the local `cache_dir` is always consulted first and always populated on a remote hit,
//!   so a node that computed an epoch can immediately serve what it committed;
//! * a `file://` DA endpoint means local-dev mode: the cache directory *is* the store;
//! * `s3://`, `gs://` and `https://` endpoints (feature `da` only) are fetched and written
//!   through `object_store`, with the byte budget enforced before the bytes are trusted.
//!
//! Nothing here interprets payloads: callers verify `keccak256(bytes)` against the CID or
//! digest the chain pinned before they decode anything.

use std::path::{Path, PathBuf};

use alloy::primitives::{keccak256, B256};

use crate::error::{Error, Result, ShardError};

/// File name of an object: hex of its CID, no extension, no directories.
fn file_name(cid: &B256) -> String {
    hex::encode(cid.as_slice())
}

/// Read a whole object from the local store, enforcing the byte budget.
///
/// A missing file is an [`std::io::Error`] with [`std::io::ErrorKind::NotFound`]: the DA
/// layer may simply not have synced yet, and the worker retries those. Anything else —
/// oversize, unreadable — is a [`ShardError`] and does not get better on retry.
pub fn read_object(cache_dir: &Path, cid: &B256, max_bytes: u64) -> Result<Vec<u8>> {
    let path = cache_dir.join(file_name(cid));
    let bytes = std::fs::read(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            Error::Io(e)
        } else {
            Error::ShardStore(ShardError::Malformed {
                offset: 0,
                reason: format!("cannot read {}: {e}", path.display()),
            })
        }
    })?;
    if bytes.len() as u64 > max_bytes {
        return Err(Error::ShardStore(ShardError::TooLarge {
            cid: *cid,
            size: bytes.len() as u64,
            max: max_bytes,
        }));
    }
    Ok(bytes)
}

/// Publish bytes to the local store under their own digest. Returns the CID.
///
/// The write is atomic (temporary file + rename) and idempotent: an existing object with
/// identical bytes is left alone, while an existing object with *different* bytes under
/// the same name is a [`ShardError::DigestMismatch`] — a hash-addressed store must never
/// silently keep the first writer's bytes.
pub fn write_object(cache_dir: &Path, bytes: &[u8], max_bytes: u64) -> Result<B256> {
    if bytes.len() as u64 > max_bytes {
        return Err(Error::ShardStore(ShardError::TooLarge {
            cid: keccak256(bytes),
            size: bytes.len() as u64,
            max: max_bytes,
        }));
    }
    std::fs::create_dir_all(cache_dir).map_err(|e| {
        Error::ShardStore(ShardError::Malformed {
            offset: 0,
            reason: format!("cannot create {}: {e}", cache_dir.display()),
        })
    })?;
    let cid = keccak256(bytes);
    let path = cache_dir.join(file_name(&cid));
    match std::fs::read(&path) {
        Ok(existing) if existing == bytes => return Ok(cid),
        Ok(existing) => {
            return Err(Error::ShardStore(ShardError::DigestMismatch {
                expected: cid,
                got: keccak256(&existing),
                len: existing.len() as u64,
            }));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(Error::ShardStore(ShardError::Malformed {
                offset: 0,
                reason: format!("cannot read {}: {e}", path.display()),
            }));
        }
    }
    let tmp = cache_dir.join(format!(".tmp-{}", file_name(&cid)));
    std::fs::write(&tmp, bytes).map_err(|e| {
        Error::ShardStore(ShardError::Malformed {
            offset: 0,
            reason: format!("cannot write {}: {e}", tmp.display()),
        })
    })?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        Error::ShardStore(ShardError::Malformed {
            offset: 0,
            reason: format!("cannot publish {}: {e}", path.display()),
        })
    })?;
    Ok(cid)
}

/// Refuse bytes that are not the object `expected` pins. The digest is recomputed locally;
/// nothing the store says about the bytes is trusted.
pub fn verify_bytes(expected: &B256, bytes: &[u8]) -> Result<()> {
    let got = keccak256(bytes);
    if got != *expected {
        return Err(Error::ShardStore(ShardError::DigestMismatch {
            expected: *expected,
            got,
            len: bytes.len() as u64,
        }));
    }
    Ok(())
}

/// The DA endpoint scheme, parsed once so the worker branches on a value, not a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// Local-dev mode: the cache directory is the store.
    File(PathBuf),
    /// Remote backends, served through `object_store` (feature `da`).
    Remote(String),
}

impl Endpoint {
    pub fn parse(da_endpoint: &str) -> Self {
        for prefix in ["file://", "file:"] {
            if let Some(rest) = da_endpoint.strip_prefix(prefix) {
                return Endpoint::File(PathBuf::from(rest));
            }
        }
        Endpoint::Remote(da_endpoint.to_string())
    }
}

/// Fetch an object: local cache first, remote backend on a miss (which then populates
/// the cache, so the mesh can serve it to peers).
pub async fn fetch(
    cache_dir: &Path,
    da_endpoint: &str,
    cid: &B256,
    max_bytes: u64,
) -> Result<Vec<u8>> {
    match read_object(cache_dir, cid, max_bytes) {
        Ok(bytes) => return Ok(bytes),
        Err(Error::Io(_)) => {}
        Err(e) => return Err(e),
    }
    match Endpoint::parse(da_endpoint) {
        Endpoint::File(_) => Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{cid:#x} is not in the local store"),
        ))),
        Endpoint::Remote(url) => {
            let bytes = fetch_remote(&url, cid, max_bytes).await?;
            // The cache write is best-effort: a full disk must not fail an epoch whose
            // bytes are already in hand.
            let _ = write_object(cache_dir, &bytes, max_bytes);
            Ok(bytes)
        }
    }
}

/// Publish bytes locally and, on a remote endpoint, to the backend. Returns the CID.
pub async fn store(
    cache_dir: &Path,
    da_endpoint: &str,
    bytes: &[u8],
    max_bytes: u64,
) -> Result<B256> {
    let cid = write_object(cache_dir, bytes, max_bytes)?;
    if let Endpoint::Remote(url) = Endpoint::parse(da_endpoint) {
        store_remote(&url, &cid, bytes).await?;
    }
    Ok(cid)
}

#[cfg(feature = "da")]
async fn store_for(url: &str) -> Result<(Box<dyn object_store::ObjectStore>, String)> {
    use object_store::aws::AmazonS3Builder;
    use object_store::gcp::GoogleCloudStorageBuilder;
    use object_store::http::HttpBuilder;

    // Bucket URLs may carry a key prefix (`s3://bucket/some/prefix`); object_store
    // builders take a bare bucket, so the prefix joins the object path instead.
    if let Some(rest) = url.strip_prefix("s3://") {
        let (bucket, prefix) = split_bucket(rest);
        let store = AmazonS3Builder::from_env()
            .with_bucket_name(bucket)
            .build()
            .map_err(|e| Error::Other(anyhow::anyhow!("da backend {url}: {e}")))?;
        return Ok((Box::new(store), prefix));
    }
    if let Some(rest) = url
        .strip_prefix("gs://")
        .or_else(|| url.strip_prefix("gcs://"))
    {
        let (bucket, prefix) = split_bucket(rest);
        let store = GoogleCloudStorageBuilder::from_env()
            .with_bucket_name(bucket)
            .build()
            .map_err(|e| Error::Other(anyhow::anyhow!("da backend {url}: {e}")))?;
        return Ok((Box::new(store), prefix));
    }
    let store = HttpBuilder::new()
        .with_url(url)
        .build()
        .map_err(|e| Error::Other(anyhow::anyhow!("da backend {url}: {e}")))?;
    Ok((Box::new(store), String::new()))
}

#[cfg(feature = "da")]
fn split_bucket(rest: &str) -> (String, String) {
    match rest.find('/') {
        Some(i) => (rest[..i].to_string(), rest[i + 1..].to_string()),
        None => (rest.to_string(), String::new()),
    }
}

#[cfg(feature = "da")]
fn object_path(prefix: &str, cid: &B256) -> object_store::path::Path {
    use object_store::path::Path as StorePath;

    let name = file_name(cid);
    if prefix.is_empty() {
        StorePath::from(name)
    } else {
        StorePath::from(format!("{}/{}", prefix.trim_matches('/'), name))
    }
}

#[cfg(feature = "da")]
async fn fetch_remote(url: &str, cid: &B256, max_bytes: u64) -> Result<Vec<u8>> {
    use object_store::ObjectStoreExt;

    let (store, prefix) = store_for(url).await?;
    let location = object_path(&prefix, cid);
    // Bound before buffering: stat the object first so a hostile backend cannot make
    // the node eat an unbounded body just to reject it afterwards. The post-read check
    // below stays as the second net for objects that grow between the two calls.
    let meta = store
        .head(&location)
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("da stat of {cid:#x} from {url}: {e}")))?;
    if meta.size as u64 > max_bytes {
        return Err(Error::ShardStore(ShardError::TooLarge {
            cid: *cid,
            size: meta.size as u64,
            max: max_bytes,
        }));
    }
    let result = store
        .get(&location)
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("da fetch of {cid:#x} from {url}: {e}")))?;
    let bytes = result
        .bytes()
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("da read of {cid:#x} from {url}: {e}")))?;
    if bytes.len() as u64 > max_bytes {
        return Err(Error::ShardStore(ShardError::TooLarge {
            cid: *cid,
            size: bytes.len() as u64,
            max: max_bytes,
        }));
    }
    Ok(bytes.to_vec())
}

#[cfg(feature = "da")]
async fn store_remote(url: &str, cid: &B256, bytes: &[u8]) -> Result<()> {
    use object_store::ObjectStoreExt;

    let (store, prefix) = store_for(url).await?;
    let location = object_path(&prefix, cid);
    store
        .put(&location, bytes.to_vec().into())
        .await
        .map_err(|e| Error::Other(anyhow::anyhow!("da store of {cid:#x} to {url}: {e}")))?;
    Ok(())
}

#[cfg(not(feature = "da"))]
async fn fetch_remote(url: &str, _cid: &B256, _max_bytes: u64) -> Result<Vec<u8>> {
    Err(remote_needs_feature(url))
}

#[cfg(not(feature = "da"))]
async fn store_remote(url: &str, _cid: &B256, _bytes: &[u8]) -> Result<()> {
    Err(remote_needs_feature(url))
}

/// The error a remote endpoint produces when this binary was built without the `da`
/// feature. Kept next to the condition so the message and the gate cannot drift apart.
#[cfg(not(feature = "da"))]
fn remote_needs_feature(url: &str) -> Error {
    Error::ShardStore(ShardError::Malformed {
        offset: 0,
        reason: format!(
            "da endpoint {url} needs remote storage, but this binary was built \
             without the `da` feature; rebuild with --features da"
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn round_trip_is_content_addressed() {
        let dir = dir();
        let bytes = b"shard bytes";
        let cid = write_object(dir.path(), bytes, 1 << 20).expect("write");
        assert_eq!(cid, keccak256(bytes));
        assert_eq!(read_object(dir.path(), &cid, 1 << 20).expect("read"), bytes);
        // Idempotent: writing the same bytes again is a no-op, not an error.
        assert_eq!(
            write_object(dir.path(), bytes, 1 << 20).expect("rewrite"),
            cid
        );
    }

    #[test]
    fn a_different_object_under_the_same_name_is_refused() {
        let dir = dir();
        let cid = write_object(dir.path(), b"first", 1 << 20).expect("write");
        // Plant conflicting bytes under the CID's file name by hand.
        std::fs::write(dir.path().join(file_name(&cid)), b"second").expect("plant");
        let err = write_object(dir.path(), b"first", 1 << 20).expect_err("must refuse");
        assert!(matches!(
            err,
            Error::ShardStore(ShardError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn budgets_are_enforced_on_both_paths() {
        let dir = dir();
        let bytes = vec![7u8; 64];
        assert!(matches!(
            write_object(dir.path(), &bytes, 8),
            Err(Error::ShardStore(ShardError::TooLarge { .. }))
        ));
        let cid = write_object(dir.path(), &bytes, 128).expect("write");
        assert!(matches!(
            read_object(dir.path(), &cid, 8),
            Err(Error::ShardStore(ShardError::TooLarge { .. }))
        ));
    }

    #[test]
    fn missing_objects_are_io_not_found() {
        let dir = dir();
        let err = read_object(dir.path(), &B256::repeat_byte(0x9), 1 << 20).expect_err("missing");
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn verification_recomputes_locally() {
        let bytes = b"pinned";
        let digest = keccak256(bytes);
        verify_bytes(&digest, bytes).expect("matches");
        assert!(verify_bytes(&B256::ZERO, bytes).is_err());
    }

    #[test]
    fn endpoints_parse_by_scheme() {
        assert!(matches!(
            Endpoint::parse("file://./data/da"),
            Endpoint::File(_)
        ));
        assert!(matches!(
            Endpoint::parse("s3://bucket/prefix"),
            Endpoint::Remote(_)
        ));
        assert!(matches!(
            Endpoint::parse("https://da.example/shards"),
            Endpoint::Remote(_)
        ));
    }

    #[cfg(feature = "da")]
    #[tokio::test]
    async fn file_backend_round_trips_through_object_store() {
        // `file://` still goes through the local cache path; a remote URL against a
        // local HTTP server would be the same `fetch`/`store` code with a network.
        let dir = dir();
        let bytes = b"through the store layer";
        let cid = store(dir.path(), "file://./data/da", bytes, 1 << 20)
            .await
            .expect("store");
        let back = fetch(dir.path(), "file://./data/da", &cid, 1 << 20)
            .await
            .expect("fetch");
        assert_eq!(back, bytes);
    }

    #[cfg(not(feature = "da"))]
    #[tokio::test]
    async fn remote_endpoints_name_the_missing_feature() {
        let dir = dir();
        let cid = B256::repeat_byte(0x1);
        let err = fetch(dir.path(), "https://da.example/shards", &cid, 1 << 20)
            .await
            .expect_err("needs the da feature");
        assert!(matches!(
            err,
            Error::ShardStore(ShardError::Malformed { .. })
        ));
    }
}
