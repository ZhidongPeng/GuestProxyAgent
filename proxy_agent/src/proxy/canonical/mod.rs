// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Canonical request model (Innovation 2.1).
//!
//! Provides a single, total, idempotent normalization step that reduces
//! every incoming [`hyper::Uri`] (and, separately, every authorization
//! rule pattern) to the same [`CanonicalRequest`] form before they meet
//! the matcher. The goal is to eliminate the rule/request asymmetries
//! that produce SSRF-style AuthZ bypasses (pentest categories D1, C7).
//!
//! ## Pipeline
//!
//! ```text
//! hyper::Uri
//!   │
//!   ▼  parse_scheme_method   (http only; allow-list of methods)
//!   ▼  classify_destination  (IP/host -> Destination; covers numeric forms)
//!   ▼  validate_userinfo     (must be empty)
//!   ▼  decode_path_once      (single percent-decode; strict UTF-8)
//!   ▼  reject_control_chars  (no CR/LF/NUL/HTAB after decode)
//!   ▼  ascii_lowercase_path  (case-insensitive matching)
//!   ▼  split_segments        (split '/'; collapse '.'; resolve '..')
//!   ▼  strip_matrix_params   (drop `;k=v` suffix on each segment)
//!   ▼  decode_query_once     (k/v percent-decode once; lowercase keys)
//!   ▼  reject_embedded_query (decoded path must not contain literal '?')
//!   ▼  fold_into_btreemap    (group by key)
//! CanonicalRequest
//! ```
//!
//! ## Fail-closed
//!
//! Every error variant in [`CanonError`] denies the request. There is no
//! "best effort" branch.
//!
//! ## Idempotency
//!
//! `canonicalize(canonicalize(x).render()) == canonicalize(x)`. This is
//! enforced via property tests in `tests::proptests`.

pub mod destination;
pub mod path;
pub mod query;
pub mod rule;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::fmt;

use hyper::{Method, Uri};

pub use destination::{AddrFamily, Destination};
pub use rule::CanonicalPattern;

/// Fully-normalized form of an HTTP request as it is fed to the matcher.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CanonicalRequest {
    /// HTTP method, restricted to the allow-list.
    pub method: Method,

    /// Classified destination. Matching uses the typed enum only; the raw
    /// host text is never compared.
    pub destination: Destination,

    /// Canonical path segments: percent-decoded once, ASCII-lowercased,
    /// `.` collapsed, `..` resolved, matrix params stripped.
    ///
    /// Always begins with the empty root segment (so `/metadata/identity`
    /// becomes `["", "metadata", "identity"]`).
    pub path_segments: Vec<String>,

    /// Whether the original path ended in `/`. Preserved as a single bit
    /// so rules can opt to be slash-sensitive without re-introducing
    /// string-level asymmetry.
    pub trailing_slash: bool,

    /// Query parameters, canonical form: keys lowercased & decoded once,
    /// values decoded once, grouped by key. Insertion order within a key
    /// is preserved; key order is lexicographic.
    pub query: BTreeMap<String, Vec<String>>,
}

impl CanonicalRequest {
    /// Stable textual rendering. Re-parsing this string and canonicalizing
    /// it must yield the same `CanonicalRequest` (idempotency invariant).
    pub fn render(&self) -> String {
        let mut out = String::new();
        if self.path_segments.is_empty() {
            out.push('/');
        } else {
            for (i, seg) in self.path_segments.iter().enumerate() {
                if i == 0 && seg.is_empty() {
                    // root marker
                    out.push('/');
                    continue;
                }
                if i > 0 {
                    out.push('/');
                }
                out.push_str(seg);
            }
        }
        if self.trailing_slash && !out.ends_with('/') {
            out.push('/');
        }
        if !self.query.is_empty() {
            out.push('?');
            let mut first = true;
            for (k, values) in self.query.iter() {
                for v in values {
                    if !first {
                        out.push('&');
                    }
                    first = false;
                    out.push_str(k);
                    out.push('=');
                    out.push_str(v);
                }
            }
        }
        out
    }
}

impl fmt::Display for CanonicalRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.method, self.destination, self.render())
    }
}

/// Typed errors produced by the canonicalizer. All variants are
/// **fail-closed**: callers must deny the request when any of these is
/// returned.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonError {
    #[error("scheme not http")]
    SchemeNotHttp,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("userinfo present in URL")]
    UserinfoPresent,
    #[error("malformed percent-encoding")]
    MalformedPercent,
    #[error("overlong UTF-8 in path/query")]
    OverlongUtf8,
    #[error("invalid UTF-8 in path/query")]
    InvalidUtf8,
    #[error("control character in path/query")]
    ControlChar,
    #[error("path traversal past root")]
    PathUnderflow,
    #[error("embedded '?' after decoding")]
    EmbeddedQuery,
    #[error("unparseable host")]
    BadHost,
    #[error("unparseable port")]
    BadPort,
}

impl CanonError {
    /// Stable short code suitable for audit logs and pentest assertions.
    pub fn code(&self) -> &'static str {
        match self {
            CanonError::SchemeNotHttp => "CANON_SCHEME",
            CanonError::MethodNotAllowed => "CANON_METHOD",
            CanonError::UserinfoPresent => "CANON_USERINFO",
            CanonError::MalformedPercent => "CANON_PCT",
            CanonError::OverlongUtf8 => "CANON_OVERLONG",
            CanonError::InvalidUtf8 => "CANON_UTF8",
            CanonError::ControlChar => "CANON_CTRL",
            CanonError::PathUnderflow => "CANON_UNDERFLOW",
            CanonError::EmbeddedQuery => "CANON_EMBQ",
            CanonError::BadHost => "CANON_HOST",
            CanonError::BadPort => "CANON_PORT",
        }
    }
}

/// HTTP methods accepted by the canonicalizer. Anything not on this list
/// is rejected with [`CanonError::MethodNotAllowed`].
///
/// Kept in sync with `proxy_server::ProxyServer::ALLOWED_METHODS`.
const ALLOWED_METHODS: &[Method] = &[
    Method::GET,
    Method::POST,
    Method::PUT,
    Method::DELETE,
    Method::HEAD,
    Method::OPTIONS,
    Method::PATCH,
];

fn check_method(method: &Method) -> Result<(), CanonError> {
    if ALLOWED_METHODS.iter().any(|m| m == method) {
        Ok(())
    } else {
        Err(CanonError::MethodNotAllowed)
    }
}

fn check_scheme(uri: &Uri) -> Result<(), CanonError> {
    match uri.scheme_str() {
        // Hyper guarantees the connect-target form for absolute URIs has a
        // scheme; the proxy receives origin-form requests where the scheme
        // is omitted. Both cases are acceptable. A non-http scheme (https,
        // ws, gopher, ...) is a hard reject.
        None => Ok(()),
        Some(s) if s.eq_ignore_ascii_case("http") => Ok(()),
        Some(_) => Err(CanonError::SchemeNotHttp),
    }
}

/// Canonicalize a parsed request.
///
/// Returns `Ok(CanonicalRequest)` for inputs that survive every stage of
/// the pipeline, or a typed [`CanonError`] otherwise. The function is
/// **total** — every well-formed `hyper::Uri` produces exactly one of
/// these two outcomes; it never panics.
pub fn canonicalize(uri: &Uri, method: &Method) -> Result<CanonicalRequest, CanonError> {
    check_scheme(uri)?;
    check_method(method)?;

    let destination = destination::classify(uri)?;

    let (path_segments, trailing_slash) = path::canonicalize_path(uri.path())?;
    let query = query::canonicalize_query(uri.query().unwrap_or(""))?;

    Ok(CanonicalRequest {
        method: method.clone(),
        destination,
        path_segments,
        trailing_slash,
        query,
    })
}

/// Convenience: parse and canonicalize a string. Useful for tests and the
/// shadow-mode shim that takes raw URLs from telemetry replay.
#[allow(dead_code)]
pub fn canonicalize_str(url: &str) -> Result<CanonicalRequest, CanonError> {
    let uri: Uri = url.parse().map_err(|_| CanonError::BadHost)?;
    canonicalize(&uri, &Method::GET)
}
