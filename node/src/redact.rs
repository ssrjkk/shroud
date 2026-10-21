//! Keeping the provider's secret out of the node's logs.
//!
//! A managed RPC URL carries the provider's API key in it, and a node logs its
//! endpoint at start-up and in every transport error it surfaces. The key is
//! the one thing in the configuration that must never reach a log line, a
//! monitoring agent, or a support bundle - and the operator still has to see
//! *which* endpoint a message is about.
//!
//! Two rules, because two kinds of endpoint are configured:
//!
//! * the **RPC endpoint** is credential-carrying: the key sits in its path, so
//!   every path segment that is not an API version is masked;
//! * a **storage endpoint** names a location (`s3://bucket/prefix`), so its
//!   path stays visible - but its query string is a presigned signature, and
//!   that goes, as do the fragment and the URL's own credentials.

use std::sync::RwLock;

use url::Url;

/// What a masked credential is replaced with.
const MASK: &str = "***";

/// The RPC endpoint whose secret must not be logged.
///
/// The node is a single-configuration process, so the secret is a process-wide
/// fact rather than a value threaded through every call site. It is registered
/// before the configuration is loaded — a configuration error quotes the
/// offending value, and the offending value may be the endpoint with its key —
/// and re-registered with the effective endpoint once the configuration is
/// known.
static RPC_SECRET: RwLock<String> = RwLock::new(String::new());

/// Register the RPC endpoint whose secret must not appear in any message.
pub fn set_rpc_secret(url: &str) {
    // A poisoned lock would mean a panic while the secret was being written; the
    // value is a plain string, so the inner value is still usable.
    *RPC_SECRET.write().unwrap_or_else(|e| e.into_inner()) = url.to_string();
}

/// The registered RPC endpoint, or an empty string when none was registered.
pub fn rpc_secret() -> String {
    RPC_SECRET.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// A path segment that describes the endpoint rather than identifying the caller.
///
/// `v1`, `v2`, `v3` are API versions and a bare number is an index; neither is
/// a credential. Everything else in the path may be the provider's key.
fn is_shape(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }
    let body = segment.strip_prefix(['v', 'V']).unwrap_or(segment);
    !body.is_empty() && body.chars().all(|c| c.is_ascii_digit())
}

/// The RPC endpoint without its secret.
///
/// The host (and its port) and the API-version segments stay visible - the
/// operator has to know *which* endpoint - and every other path segment, the
/// query string, the fragment and the URL's own credentials are masked.
pub fn redact_rpc_url(url: &str) -> String {
    redact(url, true)
}

/// A storage endpoint without its secret.
///
/// Same as [`redact_rpc_url`] except that a path is a *location* for a bucket
/// backend (`s3://bucket/prefix`), not a credential, so it stays visible. An
/// HTTP endpoint may still carry a token in its path, and that one is masked.
pub fn redact_endpoint(url: &str) -> String {
    redact(
        url,
        url.starts_with("http://") || url.starts_with("https://"),
    )
}

fn redact(url: &str, mask_path: bool) -> String {
    let Ok(mut parsed) = Url::parse(url) else {
        // Not a URL we can parse: show only the shape, never the tail.
        return "<endpoint>".to_string();
    };
    if mask_path {
        let segments: Vec<String> = parsed
            .path_segments()
            .map(|segments| {
                segments
                    .filter(|segment| !segment.is_empty())
                    .map(|segment| {
                        if is_shape(segment) {
                            segment.to_string()
                        } else {
                            MASK.to_string()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        parsed.set_path(&if segments.is_empty() {
            String::new()
        } else {
            format!("/{}", segments.join("/"))
        });
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    let _ = parsed.set_username("");
    let _ = parsed.set_password(None);
    parsed.to_string()
}

/// Remove the RPC endpoint's secret from a piece of text.
///
/// Used on every message the node logs: the text may quote the URL, or the
/// transport library may have put the URL into an error message of its own.
/// The URL is replaced by its redacted form (so the operator still sees which
/// endpoint) and the credentials themselves are replaced wherever they appear.
pub fn scrub_secret(text: &str, url: &str) -> String {
    scrub(text, url, true)
}

/// Remove a storage endpoint's secret from a piece of text.
///
/// The path is a location and stays visible; the query (a presigned signature),
/// the fragment and the URL's own credentials do not.
pub fn scrub_endpoint(text: &str, url: &str) -> String {
    scrub(text, url, false)
}

fn scrub(text: &str, url: &str, mask_path: bool) -> String {
    if text.is_empty() || url.is_empty() {
        return text.to_string();
    }
    let mut out = text.to_string();

    // The whole URL, if the text quotes it.
    if out.contains(url) {
        let replacement = if mask_path {
            redact_rpc_url(url)
        } else {
            redact_endpoint(url)
        };
        out = out.replace(url, &replacement);
    }

    let Ok(parsed) = Url::parse(url) else {
        return out;
    };

    // The credentials themselves, wherever they appear.
    let mut secrets: Vec<String> = Vec::new();
    if mask_path {
        if let Some(segments) = parsed.path_segments() {
            for segment in segments.filter(|s| !s.is_empty()) {
                if !is_shape(segment) {
                    secrets.push(segment.to_string());
                }
            }
        }
    }
    if let Some(password) = parsed.password() {
        secrets.push(password.to_string());
    }
    for (_, value) in parsed.query_pairs() {
        secrets.push(value.to_string());
    }
    for secret in secrets {
        // A short string is far more likely to be a coincidence than a key, and
        // replacing it would mangle the message without protecting anything.
        if secret.len() < 8 {
            continue;
        }
        out = out.replace(secret.as_str(), MASK);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "SuperSecretKey123";

    #[test]
    fn the_key_does_not_survive_the_redaction() {
        let redacted = redact_rpc_url(&format!("https://eth-mainnet.g.alchemy.com/v2/{KEY}"));
        assert!(!redacted.contains(KEY), "the key survived: {redacted}");
        assert!(
            redacted.contains("alchemy.com"),
            "the endpoint must stay visible: {redacted}"
        );
        assert!(
            redacted.contains("v2"),
            "the API version must stay visible: {redacted}"
        );
    }

    #[test]
    fn a_key_that_is_not_the_last_segment_does_not_survive() {
        let redacted = redact_rpc_url(&format!("https://gateway.example.com/{KEY}/v2/extra"));
        assert!(!redacted.contains(KEY), "the key survived: {redacted}");
    }

    #[test]
    fn the_query_the_fragment_and_the_credentials_do_not_survive() {
        let with_query = redact_rpc_url(&format!("https://rpc.example.com/v2?apikey={KEY}"));
        assert!(
            !with_query.contains(KEY),
            "the key survived in the query: {with_query}"
        );
        let with_fragment = redact_rpc_url(&format!("https://rpc.example.com/v2#apikey={KEY}"));
        assert!(
            !with_fragment.contains(KEY),
            "the key survived in the fragment: {with_fragment}"
        );
        let with_credentials = redact_rpc_url(&format!("https://user:{KEY}@rpc.example.com/v2"));
        assert!(
            !with_credentials.contains(KEY),
            "the key survived as a password: {with_credentials}"
        );
    }

    #[test]
    fn a_bucket_path_is_a_location_and_stays_visible() {
        let redacted = redact_endpoint("s3://my-bucket/data/shards");
        assert!(
            redacted.contains("my-bucket"),
            "the bucket must stay visible: {redacted}"
        );
        assert!(
            redacted.contains("shards"),
            "the prefix must stay visible: {redacted}"
        );
        // ...but the query of a presigned URL is a signature, and it goes.
        let presigned = redact_endpoint("s3://my-bucket/data?X-Amz-Signature=SuperSecretKey123");
        assert!(
            !presigned.contains(KEY),
            "the signature survived: {presigned}"
        );
    }

    #[test]
    fn an_http_endpoint_may_carry_a_token_in_its_path() {
        let redacted = redact_endpoint(&format!("https://da.example/{KEY}/objects"));
        assert!(!redacted.contains(KEY), "the token survived: {redacted}");
    }

    #[test]
    fn a_message_that_quotes_the_endpoint_is_scrubbed() {
        let url = format!("https://eth-mainnet.g.alchemy.com/v2/{KEY}");
        let scrubbed = scrub_secret(&format!("request to {url} failed"), &url);
        assert!(!scrubbed.contains(KEY), "the key survived: {scrubbed}");
        assert!(
            scrubbed.contains("alchemy.com"),
            "the endpoint must stay visible: {scrubbed}"
        );
    }

    #[test]
    fn a_provider_that_echoes_the_key_back_does_not_leak_it() {
        let url = format!("https://eth-mainnet.g.alchemy.com/v2/{KEY}");
        let scrubbed = scrub_secret(
            &format!("bad response (message=\"invalid key {KEY}\")"),
            &url,
        );
        assert!(!scrubbed.contains(KEY), "the key survived: {scrubbed}");
        assert!(
            scrubbed.contains("invalid key"),
            "the diagnosis must survive: {scrubbed}"
        );
    }

    #[test]
    fn a_short_segment_is_not_treated_as_a_credential() {
        let url = "https://rpc.example.com/v2/abcd";
        let message = "the node answered with abcd in it";
        assert_eq!(scrub_secret(message, url), message);
    }
}
