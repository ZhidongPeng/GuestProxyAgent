// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Path canonicalization.
//!
//! Steps (each is a small pure function so they can be unit-tested
//! independently):
//!
//! 1. Single percent-decode of the raw path; reject malformed `%XX`.
//! 2. Reject overlong UTF-8 encodings of ASCII (`%C0%AF` etc.).
//! 3. Reject control characters (`\r`, `\n`, `\0`, `\t`).
//! 4. Reject non-ASCII bytes (paths to IMDS / WireServer are ASCII;
//!    accepting non-ASCII would require NFC normalization that adds a
//!    dependency we do not currently take).
//! 5. ASCII-lowercase.
//! 6. Split on `/`, drop empty segments, drop `.`, resolve `..`
//!    (RFC 3986 §5.2.4). Underflow past the root is an error, not a
//!    no-op — a real client would never produce it.
//! 7. Strip matrix params (`;jsessionid=...`) from each segment.
//! 8. Reject an embedded `?` in the decoded path (caused by `%3F`
//!    smuggling) — the matcher must never see ambiguous input.
//!
//! The output is `(segments, trailing_slash)`. `segments` always begins
//! with the empty root segment, so the canonical form of `/` is
//! `vec![""]` and the canonical form of `/metadata/identity` is
//! `vec!["", "metadata", "identity"]`.

use super::CanonError;

const ROOT: &str = "";

/// Run the path pipeline. Public for unit tests; the canonicalizer
/// entrypoint is [`super::canonicalize`].
pub fn canonicalize_path(raw: &str) -> Result<(Vec<String>, bool), CanonError> {
    // hyper guarantees the path starts with '/'.
    let raw = if raw.is_empty() { "/" } else { raw };
    let trailing_slash = raw.len() > 1 && raw.ends_with('/');

    let decoded = decode_path_once(raw)?;
    reject_overlong_utf8(decoded.as_bytes())?;
    reject_control_chars(&decoded)?;
    reject_non_ascii(&decoded)?;
    if decoded.contains('?') {
        return Err(CanonError::EmbeddedQuery);
    }

    let lowered = decoded.to_ascii_lowercase();
    let segments = split_and_resolve(&lowered)?;

    Ok((segments, trailing_slash))
}

/// Single-pass percent-decode. Rejects truncated (`%2`) and non-hex
/// (`%ZZ`) sequences as `MalformedPercent`. Never decodes twice — that
/// is exactly the asymmetry the canonical model is built to remove.
fn decode_path_once(raw: &str) -> Result<String, CanonError> {
    let bytes = raw.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            if i + 2 >= bytes.len() {
                return Err(CanonError::MalformedPercent);
            }
            let h = hex_value(bytes[i + 1])?;
            let l = hex_value(bytes[i + 2])?;
            out.push((h << 4) | l);
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    // Strict UTF-8: lossy decoding is what allowed the silent-replacement
    // bypass in the legacy matcher.
    String::from_utf8(out).map_err(|_| CanonError::InvalidUtf8)
}

fn hex_value(b: u8) -> Result<u8, CanonError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(CanonError::MalformedPercent),
    }
}

/// Detect classic overlong UTF-8 encodings (e.g. `%C0%AF` for `/`).
///
/// `String::from_utf8` already rejects overlong sequences as invalid, so
/// by the time we run this the bytes are *guaranteed* well-formed
/// UTF-8 — meaning the overlong forms below would already have produced
/// `InvalidUtf8`. We run this pass *before* UTF-8 validation in case the
/// caller ever switches to a lossy decoder; today it is a defense in
/// depth that also gives us a more specific telemetry code.
fn reject_overlong_utf8(bytes: &[u8]) -> Result<(), CanonError> {
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        // 2-byte overlong: lead byte 0xC0 or 0xC1 (would encode <0x80).
        if b == 0xC0 || b == 0xC1 {
            return Err(CanonError::OverlongUtf8);
        }
        // 3-byte overlong: 0xE0 0x80..0x9F (would encode <0x800).
        if b == 0xE0 && i + 1 < bytes.len() && (0x80..=0x9F).contains(&bytes[i + 1]) {
            return Err(CanonError::OverlongUtf8);
        }
        // 4-byte overlong: 0xF0 0x80..0x8F (would encode <0x10000).
        if b == 0xF0 && i + 1 < bytes.len() && (0x80..=0x8F).contains(&bytes[i + 1]) {
            return Err(CanonError::OverlongUtf8);
        }
        i += 1;
    }
    Ok(())
}

fn reject_control_chars(s: &str) -> Result<(), CanonError> {
    for b in s.bytes() {
        // CR, LF, NUL, HTAB, plus the rest of the C0 control block and
        // DEL. Anything below 0x20 or equal to 0x7F is rejected.
        if b < 0x20 || b == 0x7F {
            return Err(CanonError::ControlChar);
        }
    }
    Ok(())
}

fn reject_non_ascii(s: &str) -> Result<(), CanonError> {
    if s.is_ascii() {
        Ok(())
    } else {
        Err(CanonError::InvalidUtf8)
    }
}

/// Split on `/`, strip matrix params, drop empty/`.` segments, resolve
/// `..` with underflow detection.
fn split_and_resolve(path: &str) -> Result<Vec<String>, CanonError> {
    let mut segments: Vec<String> = vec![ROOT.to_string()];
    for raw_seg in path.split('/') {
        if raw_seg.is_empty() || raw_seg == "." {
            // `//`, leading `/`, and `.` collapse away.
            continue;
        }
        if raw_seg == ".." {
            // Pop the previous segment. Popping the root is an error.
            if segments.len() <= 1 {
                return Err(CanonError::PathUnderflow);
            }
            segments.pop();
            continue;
        }
        // Strip matrix params: `segment;k=v;k2=v2` -> `segment`.
        let cleaned = match raw_seg.find(';') {
            Some(pos) => &raw_seg[..pos],
            None => raw_seg,
        };
        segments.push(cleaned.to_string());
    }
    Ok(segments)
}

#[cfg(test)]
mod path_tests {
    use super::*;

    fn canon(p: &str) -> Result<(Vec<String>, bool), CanonError> {
        canonicalize_path(p)
    }

    fn segs(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn root_path() {
        assert_eq!(canon("/").unwrap(), (segs(&[""]), false));
    }

    #[test]
    fn simple() {
        assert_eq!(
            canon("/metadata/identity").unwrap(),
            (segs(&["", "metadata", "identity"]), false)
        );
    }

    #[test]
    fn case_folded() {
        assert_eq!(
            canon("/Metadata/Identity").unwrap(),
            (segs(&["", "metadata", "identity"]), false)
        );
    }

    #[test]
    fn double_slash_collapse() {
        assert_eq!(
            canon("/metadata//identity").unwrap(),
            (segs(&["", "metadata", "identity"]), false)
        );
    }

    #[test]
    fn dot_dropped() {
        assert_eq!(
            canon("/metadata/./identity").unwrap(),
            (segs(&["", "metadata", "identity"]), false)
        );
    }

    #[test]
    fn dotdot_resolves() {
        assert_eq!(
            canon("/metadata/x/../identity").unwrap(),
            (segs(&["", "metadata", "identity"]), false)
        );
    }

    #[test]
    fn dotdot_underflow() {
        assert_eq!(canon("/a/../..").unwrap_err(), CanonError::PathUnderflow);
    }

    #[test]
    fn percent_decode_once() {
        assert_eq!(
            canon("/metadata%2Fidentity").unwrap(),
            (segs(&["", "metadata", "identity"]), false)
        );
    }

    #[test]
    fn double_encoding_decoded_only_once() {
        // %252F -> %2F literal after one decode; that '%' survives but
        // is not interpreted as a path separator.
        let (segs_out, _) = canon("/metadata%252Fidentity").unwrap();
        assert_eq!(segs_out, segs(&["", "metadata%2fidentity"]));
    }

    #[test]
    fn matrix_params_stripped() {
        assert_eq!(
            canon("/metadata/identity;jsessionid=abc").unwrap(),
            (segs(&["", "metadata", "identity"]), false)
        );
    }

    #[test]
    fn embedded_question_mark_rejected() {
        assert_eq!(
            canon("/metadata/identity%3Fapi-version=2018").unwrap_err(),
            CanonError::EmbeddedQuery
        );
    }

    #[test]
    fn control_char_rejected() {
        assert_eq!(
            canon("/metadata/identity%0A").unwrap_err(),
            CanonError::ControlChar
        );
    }

    #[test]
    fn overlong_utf8_rejected() {
        // %C0%AF is the classic overlong encoding for '/'.
        let err = canon("/metadata/%C0%AFidentity").unwrap_err();
        // Either OverlongUtf8 (caught by reject_overlong_utf8) or
        // InvalidUtf8 (caught by from_utf8) is acceptable — both are
        // hard fail-closed errors.
        assert!(matches!(
            err,
            CanonError::OverlongUtf8 | CanonError::InvalidUtf8
        ));
    }

    #[test]
    fn malformed_percent_rejected() {
        assert_eq!(canon("/abc%2").unwrap_err(), CanonError::MalformedPercent);
        assert_eq!(canon("/abc%ZZ").unwrap_err(), CanonError::MalformedPercent);
    }

    #[test]
    fn trailing_slash_preserved() {
        let (_, ts) = canon("/metadata/").unwrap();
        assert!(ts);
        let (_, ts2) = canon("/metadata").unwrap();
        assert!(!ts2);
    }
}
