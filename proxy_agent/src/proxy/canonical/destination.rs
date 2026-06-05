// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

//! Destination classification.
//!
//! Maps the host+port of an incoming request to one of GPA's known
//! endpoints (IMDS, WireServer, HostGAPlugin). Numeric host forms
//! (decimal, hex, octal, IPv4-mapped IPv6, etc.) all canonicalize to the
//! same variant — this is the defense against pentest C7.
//!
//! Hostnames that are not IP literals are *not* DNS-resolved here. DNS at
//! the matcher would be a confused-deputy surface; instead we surface the
//! host text in [`Destination::Unknown`] so rule authors can write
//! explicit allow rules keyed on host text if they need it.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hyper::Uri;

use crate::common::constants;

use super::CanonError;

/// Address family of an [`Destination::Unknown`] target. Kept narrow so
/// we don't accidentally treat numeric strings as hostnames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddrFamily {
    V4,
    V6,
    Name,
}

/// Canonical destination. Matching uses the typed enum only; the raw
/// `host_text` on `Unknown` is for audit, never for matching decisions.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Destination {
    /// Instance Metadata Service: 169.254.169.254:80 in any encoding.
    Imds,
    /// Azure WireServer: 168.63.129.16:80.
    WireServer,
    /// Host GuestAgent Plugin: 168.63.129.16:32526.
    HostGaPlugin,
    /// Anything else. The matcher denies unknowns unless an explicit rule
    /// allows them.
    Unknown {
        family: AddrFamily,
        ip: Option<IpAddr>,
        port: u16,
        host_text: Option<String>,
    },
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Destination::Imds => f.write_str("imds"),
            Destination::WireServer => f.write_str("wireserver"),
            Destination::HostGaPlugin => f.write_str("hostga"),
            Destination::Unknown { .. } => f.write_str("unknown"),
        }
    }
}

/// Classify the destination of a request URI. See module docs.
pub fn classify(uri: &Uri) -> Result<Destination, CanonError> {
    // Reject userinfo (`user@host` smuggling).
    if uri
        .authority()
        .map(|a| a.as_str().contains('@'))
        .unwrap_or(false)
    {
        return Err(CanonError::UserinfoPresent);
    }

    let host = match uri.host() {
        Some(h) => h,
        // Origin-form requests (the common proxy case) have no authority.
        // We must still allow them to flow: the destination is decided by
        // the redirector at the socket layer, not by the URL.
        None => {
            return Ok(Destination::Unknown {
                family: AddrFamily::Name,
                ip: None,
                port: 0,
                host_text: None,
            });
        }
    };

    let port = uri.port_u16().unwrap_or(constants::IMDS_PORT);

    let ip = parse_host_as_ip(host)?;
    match ip {
        Some(IpAddr::V4(v4)) => Ok(known_v4(v4, port).unwrap_or(Destination::Unknown {
            family: AddrFamily::V4,
            ip: Some(IpAddr::V4(v4)),
            port,
            host_text: Some(host.to_string()),
        })),
        Some(IpAddr::V6(v6)) => {
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) projects down to IPv4 so
            // it shares the same Destination as the dotted form.
            if let Some(v4) = v6.to_ipv4_mapped() {
                if let Some(known) = known_v4(v4, port) {
                    return Ok(known);
                }
                return Ok(Destination::Unknown {
                    family: AddrFamily::V4,
                    ip: Some(IpAddr::V4(v4)),
                    port,
                    host_text: Some(host.to_string()),
                });
            }
            Ok(Destination::Unknown {
                family: AddrFamily::V6,
                ip: Some(IpAddr::V6(v6)),
                port,
                host_text: Some(host.to_string()),
            })
        }
        None => Ok(Destination::Unknown {
            family: AddrFamily::Name,
            ip: None,
            port,
            host_text: Some(host.to_string()),
        }),
    }
}

fn known_v4(v4: Ipv4Addr, port: u16) -> Option<Destination> {
    let imds: Ipv4Addr = constants::IMDS_IP.parse().ok()?;
    let wire: Ipv4Addr = constants::WIRE_SERVER_IP.parse().ok()?;

    if v4 == imds && port == constants::IMDS_PORT {
        return Some(Destination::Imds);
    }
    if v4 == wire && port == constants::WIRE_SERVER_PORT {
        return Some(Destination::WireServer);
    }
    if v4 == wire && port == constants::GA_PLUGIN_PORT {
        return Some(Destination::HostGaPlugin);
    }
    None
}

/// Parse a host string into an `IpAddr` when it is an IP literal in any
/// historical numeric form. Returns `Ok(None)` for true hostnames (i.e.
/// not an IP), which the caller treats as `Destination::Unknown`.
///
/// Supports:
///   - dotted quad   `169.254.169.254`
///   - 32-bit decimal `2852039166`
///   - 32-bit hex     `0xa9fea9fe`
///   - octal-quad     `0251.0376.0251.0376`
///   - hex-quad       `0xa9.0xfe.0xa9.0xfe`
///   - mixed forms allowed per RFC 3493 / inet_aton tradition
///   - bracketed IPv6 `[::ffff:169.254.169.254]` (brackets handled by hyper)
fn parse_host_as_ip(host: &str) -> Result<Option<IpAddr>, CanonError> {
    // Tolerate both forms (hyper strips brackets in most versions but
    // not all). Strip surrounding `[]` if present before parsing IPv6.
    let host_unbracketed = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(v6) = host_unbracketed.parse::<Ipv6Addr>() {
        return Ok(Some(IpAddr::V6(v6)));
    }
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Ok(Some(IpAddr::V4(v4)));
    }

    // Trailing dot on hostname (`metadata.azure.internal.`) — strip then
    // re-classify. A bare `.` is not a host.
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(CanonError::BadHost);
    }

    if let Some(v4) = parse_inet_aton(trimmed)? {
        return Ok(Some(IpAddr::V4(v4)));
    }

    // Not an IP literal in any supported form. Distinguish "valid
    // hostname" from "garbage": at least one ASCII alphanumeric and no
    // forbidden characters.
    if trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && trimmed.chars().any(|c| c.is_ascii_alphanumeric())
    {
        Ok(None)
    } else {
        Err(CanonError::BadHost)
    }
}

/// `inet_aton`-style numeric IPv4 parser.
///
/// Implemented by hand (rather than calling out to libc) because
/// `inet_aton` behavior is platform-dependent: glibc accepts `0x` and
/// leading-zero octal; musl is stricter; Windows differs again. A
/// hand-rolled parser keeps Linux and Windows builds identical.
fn parse_inet_aton(input: &str) -> Result<Option<Ipv4Addr>, CanonError> {
    // Must look numeric. Reject early if it has any character outside the
    // numeric/separator set so we don't shadow a legitimate hostname.
    if input.is_empty() {
        return Err(CanonError::BadHost);
    }
    let looks_numeric = input
        .chars()
        .all(|c| c.is_ascii_hexdigit() || c == 'x' || c == 'X' || c == '.');
    if !looks_numeric {
        return Ok(None);
    }

    let parts: Vec<&str> = input.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return Err(CanonError::BadHost);
    }
    // Empty parts (e.g. trailing dot already stripped, double dot here)
    // are illegal.
    if parts.iter().any(|p| p.is_empty()) {
        return Err(CanonError::BadHost);
    }

    let nums: Vec<u32> = parts
        .iter()
        .map(|p| parse_numeric_octet(p))
        .collect::<Result<Vec<_>, _>>()?;

    let addr: u32 = match nums.len() {
        // single 32-bit number: maps directly
        1 => nums[0],
        // a.b => a in top 8 bits, b in low 24
        2 => {
            if nums[0] > 0xFF || nums[1] > 0x00FF_FFFF {
                return Err(CanonError::BadHost);
            }
            (nums[0] << 24) | nums[1]
        }
        // a.b.c => a,b top 16 bits, c low 16
        3 => {
            if nums[0] > 0xFF || nums[1] > 0xFF || nums[2] > 0xFFFF {
                return Err(CanonError::BadHost);
            }
            (nums[0] << 24) | (nums[1] << 16) | nums[2]
        }
        // a.b.c.d => standard dotted quad
        4 => {
            if nums.iter().any(|&n| n > 0xFF) {
                return Err(CanonError::BadHost);
            }
            (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
        }
        _ => return Err(CanonError::BadHost),
    };

    Ok(Some(Ipv4Addr::from(addr)))
}

fn parse_numeric_octet(s: &str) -> Result<u32, CanonError> {
    // 0x... => hex
    if let Some(rest) = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
    {
        if rest.is_empty() || rest.len() > 8 {
            return Err(CanonError::BadHost);
        }
        return u32::from_str_radix(rest, 16).map_err(|_| CanonError::BadHost);
    }
    // 0... (and not just "0") => octal
    if s.len() > 1 && s.starts_with('0') {
        return u32::from_str_radix(&s[1..], 8).map_err(|_| CanonError::BadHost);
    }
    // decimal
    s.parse::<u32>().map_err(|_| CanonError::BadHost)
}
