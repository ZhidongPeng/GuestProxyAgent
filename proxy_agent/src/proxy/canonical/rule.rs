// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Canonical form of a rule pattern.
//!
//! Rules go through the same pipeline as requests, with two
//! differences:
//!
//! 1. There is no scheme/method on a rule (the matcher inherits those
//!    from the request).
//! 2. A rule's destination is `RuleDestination`, which adds an `Any`
//!    variant for rules that intentionally span endpoints.
//!
//! Matching is then a pure structural comparison:
//!
//! - `Destination` must equal the rule's destination (or the rule is
//!   `Any`).
//! - The rule's path is a **prefix** of the request's canonical path,
//!   compared segment-by-segment (not character-by-character — this is
//!   what prevents `starts_with("/metadata")` from matching
//!   `/metadata-attacker`).
//! - For each query key constrained by the rule, the request must
//!   have at least one matching value (case-insensitive after the
//!   canonical pipeline already lowercased both sides).

use std::collections::BTreeMap;

use crate::key_keeper::key::Privilege;

use super::destination::Destination;
use super::path::canonicalize_path;
use super::query::canonicalize_query;
use super::{CanonError, CanonicalRequest};

/// Destination constraint on a rule.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RuleDestination {
    /// Rule applies to a single classified destination.
    Only(Destination),
    /// Rule applies regardless of destination (used for the per-endpoint
    /// rule files where the file itself already partitions the rules).
    Any,
}

/// Canonical form of an authorization rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalPattern {
    pub destination: RuleDestination,
    /// Segments to prefix-match against [`CanonicalRequest::path_segments`].
    /// Always starts with the root marker (empty string).
    pub path_prefix: Vec<String>,
    /// Required query parameters. Empty map means "no query constraint".
    /// All present keys must match at least one of the supplied values.
    pub required_query: BTreeMap<String, Vec<String>>,
}

impl CanonicalPattern {
    /// Build from a raw `Privilege` (the on-disk rule format).
    ///
    /// The privilege's path is run through the canonical path pipeline,
    /// and its query parameters are run through the canonical query
    /// pipeline. Rules that fail canonicalization are **rejected** by
    /// the loader — fail-closed.
    pub fn from_privilege(p: &Privilege) -> Result<Self, CanonError> {
        let (segments, _trailing) = canonicalize_path(&p.path)?;
        let required_query = match &p.queryParameters {
            None => BTreeMap::new(),
            Some(qp) => {
                let mut joined = String::new();
                for (k, v) in qp.iter() {
                    if !joined.is_empty() {
                        joined.push('&');
                    }
                    joined.push_str(k);
                    joined.push('=');
                    joined.push_str(v);
                }
                canonicalize_query(&joined)?
            }
        };
        Ok(CanonicalPattern {
            destination: RuleDestination::Any,
            path_prefix: segments,
            required_query,
        })
    }

    /// Structural match against a canonical request.
    pub fn matches(&self, req: &CanonicalRequest) -> bool {
        // Destination
        if let RuleDestination::Only(d) = &self.destination {
            if d != &req.destination {
                return false;
            }
        }

        // Path: segment-by-segment prefix match.
        if req.path_segments.len() < self.path_prefix.len() {
            return false;
        }
        for (i, seg) in self.path_prefix.iter().enumerate() {
            if &req.path_segments[i] != seg {
                return false;
            }
        }

        // Query: every required key must be present and at least one
        // of its required values must appear among the request's values
        // for that key.
        for (k, required_values) in &self.required_query {
            let actual = match req.query.get(k) {
                Some(v) => v,
                None => return false,
            };
            let any_match = required_values
                .iter()
                .any(|rv| actual.iter().any(|av| av == rv));
            if !any_match {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod rule_tests {
    use std::collections::HashMap;

    use hyper::{Method, Uri};

    use super::*;
    use crate::proxy::canonical::canonicalize;

    fn priv_of(path: &str, qp: Option<HashMap<String, String>>) -> Privilege {
        Privilege {
            name: "test".to_string(),
            path: path.to_string(),
            queryParameters: qp,
        }
    }

    #[test]
    fn prefix_match_segment_boundary() {
        // A rule on /metadata should NOT match /metadata-attacker because
        // segment-level prefix matching does not span segment boundaries.
        let p = CanonicalPattern::from_privilege(&priv_of("/metadata", None)).unwrap();

        let uri: Uri = "http://169.254.169.254/metadata/identity".parse().unwrap();
        let req = canonicalize(&uri, &Method::GET).unwrap();
        assert!(p.matches(&req));

        let uri2: Uri = "http://169.254.169.254/metadata-attacker/identity"
            .parse()
            .unwrap();
        let req2 = canonicalize(&uri2, &Method::GET).unwrap();
        assert!(!p.matches(&req2));
    }

    #[test]
    fn rule_path_case_insensitive() {
        let p = CanonicalPattern::from_privilege(&priv_of("/Metadata", None)).unwrap();
        let uri: Uri = "http://169.254.169.254/METADATA/Identity".parse().unwrap();
        let req = canonicalize(&uri, &Method::GET).unwrap();
        assert!(p.matches(&req));
    }

    #[test]
    fn query_constraint_required() {
        let mut qp = HashMap::new();
        qp.insert("api-version".to_string(), "2018-02-01".to_string());
        let p = CanonicalPattern::from_privilege(&priv_of("/metadata/identity", Some(qp))).unwrap();

        let ok: Uri = "http://169.254.169.254/metadata/identity?api-version=2018-02-01"
            .parse()
            .unwrap();
        assert!(p.matches(&canonicalize(&ok, &Method::GET).unwrap()));

        let bad: Uri = "http://169.254.169.254/metadata/identity?api-version=2017"
            .parse()
            .unwrap();
        assert!(!p.matches(&canonicalize(&bad, &Method::GET).unwrap()));

        let missing: Uri = "http://169.254.169.254/metadata/identity".parse().unwrap();
        assert!(!p.matches(&canonicalize(&missing, &Method::GET).unwrap()));
    }

    #[test]
    fn encoded_path_still_matches_rule() {
        // %2F is decoded once -> rule on /metadata/identity must catch it.
        let p =
            CanonicalPattern::from_privilege(&priv_of("/metadata/identity", None)).unwrap();
        let uri: Uri = "http://169.254.169.254/metadata%2Fidentity/oauth2/token"
            .parse()
            .unwrap();
        let req = canonicalize(&uri, &Method::GET).unwrap();
        assert!(p.matches(&req));
    }
}
