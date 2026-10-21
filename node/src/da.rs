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
    // Stat before reading: an oversize object must be refused without being pulled into
    // memory. The remote path does the same (`head` before `get`), and the difference
    // matters: shards are fetched with a bounded concurrency, so a cache holding
    // objects larger than the current budget — an operator who lowered
    // `max_ciphertext_bytes`, or a file planted in the directory — would be read in
    // full, several at a time, before the check rejected it. The length is checked
    // again after the read, because the file may grow in between: the stat is a cheap
    // gate, not the only one.
    match std::fs::metadata(&path) {
        Ok(meta) => {
            if !meta.is_file() {
                return Err(Error::ShardStore(ShardError::Malformed {
                    offset: 0,
                    reason: format!("{} is not a regular file", path.display()),
                }));
            }
            let size = meta.len();
            if size > max_bytes {
                return Err(Error::ShardStore(ShardError::TooLarge {
                    cid: *cid,
                    size,
                    max: max_bytes,
                }));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::Io(e)),
        Err(e) => {
            return Err(Error::ShardStore(ShardError::Malformed {
                offset: 0,
                reason: format!("cannot stat {}: {e}", path.display()),
            }));
        }
    }
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
    // Idempotent fast path: the object already exists.
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
    // M14 fix: unique temp name per writer. A fixed `.tmp-<cid>` name means two stores of the
    // same cid (possible only under a keccak collision or a planted file) race on the same
    // temp file and the last writer silently wins the atomic rename. With a per-process,
    // per-call suffix each writer uses its own temp file, so the rename is a pure publishing
    // step and "last writer on the same BYTES" is idempotent.
    let tmp = cache_dir.join(format!(
        ".tmp-{}-{}-{}",
        file_name(&cid),
        std::process::id(),
        // Nanosecond timestamp: two stores from the same process in the same microsecond
        // still get distinct temp names.
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default()
    ));
    std::fs::write(&tmp, bytes).map_err(|e| {
        Error::ShardStore(ShardError::Malformed {
            offset: 0,
            reason: format!("cannot write {}: {e}", tmp.display()),
        })
    })?;
    // Sync before rename so a crash cannot leave a zero-length published object.
    if let Ok(f) = std::fs::File::open(&tmp) {
        let _ = f.sync_all();
    }
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

/// Schemes `fetch`/`store` can actually serve. Single source of truth for what
/// `shard.da_endpoint` may name: `Endpoint::parse` sends everything else down the
/// remote path, and the remote builders only know `s3://`, `gs://`/`gcs://` and
/// HTTP(S) — a typo like `s33://bucket` would otherwise pass config validation
/// and fail minutes later at the first shard fetch instead of at startup.
pub fn is_supported_endpoint(url: &str) -> bool {
    [
        "file://", "file:", "s3://", "gs://", "gcs://", "http://", "https://",
    ]
    .iter()
    .any(|prefix| url.starts_with(prefix))
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
            .map_err(|e| {
                Error::Other(anyhow::anyhow!(
                    "da backend {url}: {e}",
                    url = crate::redact::redact_endpoint(url)
                ))
            })?;
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
            .map_err(|e| {
                Error::Other(anyhow::anyhow!(
                    "da backend {url}: {e}",
                    url = crate::redact::redact_endpoint(url)
                ))
            })?;
        return Ok((Box::new(store), prefix));
    }
    let store = HttpBuilder::new().with_url(url).build().map_err(|e| {
        Error::Other(anyhow::anyhow!(
            "da backend {url}: {e}",
            url = crate::redact::redact_endpoint(url)
        ))
    })?;
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
    // Bound before buffering: stat the object first so an honest oversize
    // object fails without any body transfer.
    let meta = store.head(&location).await.map_err(|e| {
        Error::Other(anyhow::anyhow!(
            "da stat of {cid:#x} from {url}: {e}",
            url = crate::redact::redact_endpoint(url)
        ))
    })?;
    if meta.size as u64 > max_bytes {
        return Err(Error::ShardStore(ShardError::TooLarge {
            cid: *cid,
            size: meta.size as u64,
            max: max_bytes,
        }));
    }
    let result = store.get(&location).await.map_err(|e| {
        Error::Other(anyhow::anyhow!(
            "da fetch of {cid:#x} from {url}: {e}",
            url = crate::redact::redact_endpoint(url)
        ))
    })?;
    // ...but `head` is the server's own claim: stream the body and enforce the
    // cap chunk by chunk. Buffering first and checking afterwards would let a
    // backend that understates the size make the node hold an unbounded body
    // just to reject it (the same shape the SDK's readCapped guards against).
    read_capped(result.into_stream(), cid, max_bytes, url).await
}

/// Drain a byte stream enforcing the budget chunk by chunk.
///
/// Split out of `fetch_remote` so the cap logic is unit-testable without a
/// network: the security property is that an understated size never lets the
/// buffer grow past `max_bytes`, no matter what the metadata claimed.
#[cfg(feature = "da")]
async fn read_capped<S, E>(mut stream: S, cid: &B256, max_bytes: u64, url: &str) -> Result<Vec<u8>>
where
    S: futures::Stream<Item = std::result::Result<bytes::Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    use futures::StreamExt;

    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            Error::Other(anyhow::anyhow!(
                "da read of {cid:#x} from {url}: {e}",
                url = crate::redact::redact_endpoint(url)
            ))
        })?;
        // saturating: chunk lengths arrive over the network, and hostile
        // lengths must be errors, never panics.
        let grown = (bytes.len() as u64).saturating_add(chunk.len() as u64);
        if grown > max_bytes {
            return Err(Error::ShardStore(ShardError::TooLarge {
                cid: *cid,
                size: grown,
                max: max_bytes,
            }));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
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
             without the `da` feature; rebuild with --features da",
            url = crate::redact::redact_endpoint(url)
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
    fn a_cache_entry_that_is_not_a_regular_file_is_malformed() {
        // The cache is checked by stat before the read, so a directory sitting where an
        // object belongs must still read as malformed rather than as an oversize object.
        let dir = dir();
        let cid = B256::repeat_byte(0x9);
        std::fs::create_dir(dir.path().join(file_name(&cid))).expect("plant");
        let err = read_object(dir.path(), &cid, 1 << 20).expect_err("not a file");
        assert!(matches!(
            err,
            Error::ShardStore(ShardError::Malformed { .. })
        ));
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

    #[test]
    fn only_servable_schemes_pass_validation() {
        // Every scheme the remote builders understand, plus the local file form.
        for ok in [
            "file://./data/da",
            "file:./data/da",
            "s3://bucket/prefix",
            "s3://bucket",
            "gs://bucket/prefix",
            "gcs://bucket/prefix",
            "https://da.example/shards",
            "http://127.0.0.1:8080/shards",
        ] {
            assert!(
                is_supported_endpoint(ok),
                "{ok:?} must validate: the fetch path serves it"
            );
        }
        // Typos and exotic schemes: `parse` would route these to the remote path,
        // where the HTTP builder fails at the first fetch instead of at startup.
        for bad in [
            "",
            "s33://bucket",
            "ftp://example/shards",
            "FILE://./data/da",
            "S3://bucket",
            "notaurl",
            "./data/da",
        ] {
            assert!(
                !is_supported_endpoint(bad),
                "{bad:?} must not validate: nothing serves it"
            );
        }
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

    #[cfg(feature = "da")]
    #[tokio::test]
    async fn remote_body_is_stream_capped_despite_lying_metadata() {
        // The security property behind the streaming read: chunks are capped
        // as they arrive, so a backend that understated HEAD can never push
        // the buffer past max_bytes, no matter how much it sends. A synthetic
        // stream (not a socket) keeps this hermetic: CI sandboxes may proxy
        // or block even localhost HTTP.
        use futures::stream;
        let cid = B256::repeat_byte(0x4);
        let chunks: Vec<std::result::Result<bytes::Bytes, String>> = vec![
            Ok(bytes::Bytes::from_static(b"0123456789")),
            Ok(bytes::Bytes::from_static(b"0123456789")),
            Ok(bytes::Bytes::from_static(b"0123456789")),
        ];
        let err = read_capped(stream::iter(chunks), &cid, 25, "test://lying")
            .await
            .expect_err("third chunk breaks the cap");
        assert!(
            matches!(
                err,
                Error::ShardStore(ShardError::TooLarge {
                    size: 30,
                    max: 25,
                    ..
                })
            ),
            "unexpected: {err:?}"
        );
    }

    #[cfg(feature = "da")]
    #[tokio::test]
    async fn remote_small_body_streams_fine() {
        // The honest path through the same code: capped chunks assemble in order.
        use futures::stream;
        let cid = B256::repeat_byte(0x5);
        let chunks: Vec<std::result::Result<bytes::Bytes, String>> = vec![
            Ok(bytes::Bytes::from_static(b"ab")),
            Ok(bytes::Bytes::from_static(b"cd")),
            Ok(bytes::Bytes::from_static(b"")),
        ];
        let back = read_capped(stream::iter(chunks), &cid, 64, "test://honest")
            .await
            .expect("honest body");
        assert_eq!(back, b"abcd");
    }

    #[cfg(feature = "da")]
    #[tokio::test]
    async fn remote_stream_error_is_not_a_size_error() {
        // A transport failure mid-body must surface as-is, not as TooLarge,
        // so operators do not chase a byte budget for a network fault.
        use futures::stream;
        let cid = B256::repeat_byte(0x6);
        let chunks: Vec<std::result::Result<bytes::Bytes, String>> = vec![
            Ok(bytes::Bytes::from_static(b"ab")),
            Err("connection reset".to_string()),
        ];
        let err = read_capped(stream::iter(chunks), &cid, 64, "test://flaky")
            .await
            .expect_err("transport failure");
        assert!(matches!(err, Error::Other(_)), "unexpected: {err:?}");
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
