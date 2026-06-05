// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Integration-level tests for the canonical pipeline.
//!
//! Per-helper unit tests live inside each helper module
//! (`path::path_tests`, `query::query_tests`, etc). This module hosts
//! the cross-cutting tests:
//!
//! - Golden vectors from `doc/Innovation-2.1-canonical-request.md`
//!   Appendix A.
//! - Idempotency: `canonicalize(canonicalize(x).render()) == canonicalize(x)`.
//! - Total / no-panic on adversarial inputs.

use hyper::{Method, Uri};

use super::destination::Destination;
use super::{canonicalize, canonicalize_str, CanonError};

fn canon_path(url: &str) -> String {
    let req = canonicalize_str(url).unwrap();
    req.path_segments.join("/")
}

fn canon_err(url: &str) -> CanonError {
    canonicalize_str(url).unwrap_err()
}

// -------------------------------------------------------------------
// Appendix A.1 — path vectors
// -------------------------------------------------------------------

#[test]
fn vec_a1_plain_path() {
    assert_eq!(
        canon_path("http://169.254.169.254/metadata/identity"),
        "/metadata/identity"
    );
}

#[test]
fn vec_a1_mixed_case_path() {
    assert_eq!(
        canon_path("http://169.254.169.254/Metadata/Identity"),
        "/metadata/identity"
    );
}

#[test]
fn vec_a1_double_slash() {
    assert_eq!(
        canon_path("http://169.254.169.254/metadata//identity"),
        "/metadata/identity"
    );
}

#[test]
fn vec_a1_dot_segment() {
    assert_eq!(
        canon_path("http://169.254.169.254/metadata/./identity"),
        "/metadata/identity"
    );
}

#[test]
fn vec_a1_dotdot_segment() {
    assert_eq!(
        canon_path("http://169.254.169.254/metadata/x/../identity"),
        "/metadata/identity"
    );
}

#[test]
fn vec_a1_encoded_slash_decodes() {
    assert_eq!(
        canon_path("http://169.254.169.254/metadata%2Fidentity"),
        "/metadata/identity"
    );
}

#[test]
fn vec_a1_double_encoding_decoded_once() {
    // Single decode: %252F -> %2F (literal, not a separator).
    assert_eq!(
        canon_path("http://169.254.169.254/metadata%252Fidentity"),
        "/metadata%2fidentity"
    );
}

#[test]
fn vec_a1_overlong_utf8_rejected() {
    let err = canon_err("http://169.254.169.254/metadata/%C0%AFidentity");
    assert!(matches!(
        err,
        CanonError::OverlongUtf8 | CanonError::InvalidUtf8
    ));
}

#[test]
fn vec_a1_path_underflow_rejected() {
    // The Appendix lists `/metadata/identity/../../..` as PathUnderflow.
    // /metadata/identity -> pop x2 = root; the third .. underflows.
    assert_eq!(
        canon_err("http://169.254.169.254/metadata/identity/../../.."),
        CanonError::PathUnderflow
    );
}

#[test]
fn vec_a1_matrix_param_stripped() {
    assert_eq!(
        canon_path("http://169.254.169.254/metadata/identity;jsessionid=abc"),
        "/metadata/identity"
    );
}

#[test]
fn vec_a1_embedded_query_rejected() {
    assert_eq!(
        canon_err("http://169.254.169.254/metadata/identity%3Fapi-version=2018"),
        CanonError::EmbeddedQuery
    );
}

#[test]
fn vec_a1_control_char_rejected() {
    assert_eq!(
        canon_err("http://169.254.169.254/metadata/identity%0A"),
        CanonError::ControlChar
    );
}

// -------------------------------------------------------------------
// Appendix A.2 — host vectors. All should map to Destination::Imds.
// -------------------------------------------------------------------

fn dest_of(url: &str) -> Destination {
    canonicalize_str(url).unwrap().destination
}

#[test]
fn vec_a2_dotted_quad() {
    assert_eq!(dest_of("http://169.254.169.254/x"), Destination::Imds);
}

#[test]
fn vec_a2_decimal() {
    assert_eq!(dest_of("http://2852039166/x"), Destination::Imds);
}

#[test]
fn vec_a2_hex_packed() {
    assert_eq!(dest_of("http://0xa9fea9fe/x"), Destination::Imds);
}

#[test]
fn vec_a2_octal_quad() {
    assert_eq!(
        dest_of("http://0251.0376.0251.0376/x"),
        Destination::Imds
    );
}

#[test]
fn vec_a2_ipv4_mapped_dotted() {
    assert_eq!(
        dest_of("http://[::ffff:169.254.169.254]/x"),
        Destination::Imds
    );
}

#[test]
fn vec_a2_ipv4_mapped_hex() {
    assert_eq!(dest_of("http://[::ffff:a9fe:a9fe]/x"), Destination::Imds);
}

#[test]
fn vec_a2_userinfo_rejected() {
    // hyper may refuse to parse some forms entirely; either outcome is
    // a deny.
    let r = canonicalize_str("http://user@169.254.169.254/x");
    assert!(matches!(
        r.unwrap_err(),
        CanonError::UserinfoPresent | CanonError::BadHost
    ));
}

#[test]
fn vec_a2_hostname_is_unknown_not_imds() {
    let d = dest_of("http://metadata.azure.internal/x");
    match d {
        Destination::Unknown {
            host_text: Some(s), ..
        } => assert!(s.contains("metadata.azure.internal")),
        _ => panic!("expected Unknown with host_text, got {:?}", d),
    }
}

// -------------------------------------------------------------------
// Cross-cutting invariants
// -------------------------------------------------------------------

#[test]
fn idempotent_on_typical_imds_url() {
    let url =
        "http://169.254.169.254/Metadata/Identity/oauth2/token?api-version=2018-02-01&Resource=https%3A%2F%2Fmanagement.azure.com%2F";
    let c1 = canonicalize_str(url).unwrap();

    // Render then re-parse-and-canonicalize. The host is dropped when we
    // render, so we must re-attach it; otherwise hyper would produce a
    // path-only Uri whose destination falls through to Unknown.
    let rendered = format!("http://169.254.169.254{}", c1.render());
    let c2 = canonicalize_str(&rendered).unwrap();
    assert_eq!(c1, c2);
}

#[test]
fn no_panic_on_random_uris() {
    // Sanity smoke test — proptest target lives in proptests.rs in a
    // follow-up PR; this guards against regressions for the obvious
    // adversarial shapes.
    for raw in &[
        "/",
        "//",
        "/.",
        "/..",
        "/%00",
        "/a/b/c?",
        "/?",
        "/a;",
        "/a;b;c;",
        "/%",
        "/%%",
        "/%%%",
        "/very/long/path/that/repeats/very/long/path/that/repeats",
    ] {
        let uri: Result<Uri, _> = format!("http://169.254.169.254{}", raw).parse();
        if let Ok(u) = uri {
            // Must return either Ok or a typed Err; must not panic.
            let _ = canonicalize(&u, &Method::GET);
        }
    }
}

#[test]
fn https_scheme_rejected() {
    let uri: Uri = "https://169.254.169.254/x".parse().unwrap();
    assert_eq!(
        canonicalize(&uri, &Method::GET).unwrap_err(),
        CanonError::SchemeNotHttp
    );
}

#[test]
fn connect_method_rejected() {
    let uri: Uri = "http://169.254.169.254/x".parse().unwrap();
    assert_eq!(
        canonicalize(&uri, &Method::CONNECT).unwrap_err(),
        CanonError::MethodNotAllowed
    );
}

#[test]
fn trace_method_rejected() {
    let uri: Uri = "http://169.254.169.254/x".parse().unwrap();
    assert_eq!(
        canonicalize(&uri, &Method::TRACE).unwrap_err(),
        CanonError::MethodNotAllowed
    );
}

#[test]
fn wireserver_classified() {
    assert_eq!(dest_of("http://168.63.129.16:80/x"), Destination::WireServer);
}

#[test]
fn hostga_classified() {
    assert_eq!(
        dest_of("http://168.63.129.16:32526/x"),
        Destination::HostGaPlugin
    );
}

#[test]
fn error_codes_are_stable() {
    // Stability of these strings is contract with the audit log and
    // pentest scripts. Changing one is a breaking change.
    assert_eq!(CanonError::SchemeNotHttp.code(), "CANON_SCHEME");
    assert_eq!(CanonError::MethodNotAllowed.code(), "CANON_METHOD");
    assert_eq!(CanonError::UserinfoPresent.code(), "CANON_USERINFO");
    assert_eq!(CanonError::MalformedPercent.code(), "CANON_PCT");
    assert_eq!(CanonError::OverlongUtf8.code(), "CANON_OVERLONG");
    assert_eq!(CanonError::InvalidUtf8.code(), "CANON_UTF8");
    assert_eq!(CanonError::ControlChar.code(), "CANON_CTRL");
    assert_eq!(CanonError::PathUnderflow.code(), "CANON_UNDERFLOW");
    assert_eq!(CanonError::EmbeddedQuery.code(), "CANON_EMBQ");
    assert_eq!(CanonError::BadHost.code(), "CANON_HOST");
    assert_eq!(CanonError::BadPort.code(), "CANON_PORT");
}
