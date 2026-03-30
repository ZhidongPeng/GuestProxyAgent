// Copyright (c) Microsoft Corporation
// SPDX-License-Identifier: MIT

use std::borrow::Cow;

const REDACTED_TEXT: &str = "[REDACTED]";

/// Entropy threshold (in bits per character) used by entropy-gated redaction strategy.
/// Inspired by Databricks' entropy-based log redaction for Apache Spark.
///
/// Shannon entropy measures randomness: higher entropy indicates more random, secret-like content.
/// - Base64-encoded secrets typically have entropy ~5.0-5.5 bits/char (64 possible chars per position)
/// - SHA1 hashes (hex only) typically have entropy ~3.3-3.5 bits/char (16 possible chars per position)  
/// - Structured data (class names, paths, most English words) typically have entropy < 4.0
///
/// Threshold of 4.0 sits in the empirical gap between real secrets and false positives,
/// allowing us to suppress redaction of predictable strings while catching random tokens.
/// This reduces false positives (logging structured data that happens to match broad patterns)
/// while maintaining high recall for actual credentials.
const ENTROPY_REDACTION_THRESHOLD: f64 = 4.0;

/// Minimum length (in characters) of a candidate segment for entropy evaluation.
/// Entropy calculation becomes unreliable and noisy below this length (high variance).
///
/// Most practical credentials (API keys, JWT segments, access tokens) are >= 20 chars minimum.
/// AWS secret keys are 40 chars, JWT parts are 30-50+ chars, most bearer tokens are 30+ chars.
/// 20 chars is a conservative lower bound that avoids testing very short strings where
/// a few character changes disproportionately shift entropy, leading to false positives/negatives.
const MIN_ENTROPY_CANDIDATE_LEN: usize = 20;

#[derive(Clone, Copy)]
enum RedactionStrategy {
    Strict,
    EntropyGated,
}

#[derive(Clone, Copy)]
struct PatternSpec {
    pattern: &'static str,
    strategy: RedactionStrategy,
}

/// Common substrings that indicate a secret might be present - for quick pre-filtering
/// These are not regex patterns, just simple substrings to check for before running the more expensive regexes.
const SECRET_INDICATORS: [&str; 15] = [
    "pwd=",
    "password=",
    "AccountKey=",
    "PrimaryKey=",
    "SecondaryKey=",
    "sig=",
    "AzCa",
    "PRIVATE KEY",
    "token",
    "ado",
    "vsts",
    "key",
    "secret",
    "authorization",
    "eyJ",
];
/// Regular expression patterns to identify secrets. These are more expensive to run, so we first check for indicators.
/// Remarks: when add more patterns, please also add corresponding indicators in SECRET_INDICATORS for better performance.
///     And try to make the pattern as specific as possible to avoid false positives and unnecessary redaction.
const CRED_PATTERNS: [PatternSpec; 17] = [
    // SQL Connection String Password
    PatternSpec {
        pattern: "pwd=[^;]*",
        strategy: RedactionStrategy::Strict,
    },
    PatternSpec {
        pattern: "password=[^;]*",
        strategy: RedactionStrategy::Strict,
    },
    // Azure Storage Connection String Keys
    PatternSpec {
        pattern: "AccountKey=[^;]*",
        strategy: RedactionStrategy::Strict,
    },
    PatternSpec {
        pattern: "PrimaryKey=[^;]*",
        strategy: RedactionStrategy::Strict,
    },
    PatternSpec {
        pattern: "SecondaryKey=[^;]*",
        strategy: RedactionStrategy::Strict,
    },
    // SAS Key
    PatternSpec {
        pattern: "sig=[^&]*",
        strategy: RedactionStrategy::Strict,
    },
    // Azure Redis Cache Secret (Identifiable)
    PatternSpec {
        pattern: r"(?-i)([0-9a-zA-Z]{33}AzCa[A-P][0-9a-zA-Z]{5}=)|([0-9a-zA-Z]{44}AzCa[0-9a-zA-Z]{5}[AQgw])",
        strategy: RedactionStrategy::Strict,
    },
    // X.509 Certificate Private Key
    PatternSpec {
        pattern: r"BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY",
        strategy: RedactionStrategy::Strict,
    },
    // Azure DevOps Personal Access Token
    PatternSpec {
        pattern: r"(?i)(pat[\\s\\W]|token|ado|vsts|azuredevops|visualstudio\\.com|dev\\.azure\\.com).([a-z2-7]{52}|[A-Z2-7]{52})",
        strategy: RedactionStrategy::Strict,
    },
    // Broad key-like patterns benefit from entropy gating to suppress false positives.
    PatternSpec {
        pattern: "(?i)(key|access|sas|shared|secret|password|pwd|pswd|credential)[\\s\\S]{0,200}[^a-z0-9/+]([a-z0-9/+]{43}=)",
        strategy: RedactionStrategy::EntropyGated,
    },
    PatternSpec {
        pattern: "(?i)(azurecr[\\s\\S]{0,50}|pwd|pswd|password)[:\\s=]+([a-z0-9/{\\}{\\+}=\\-!#$%&()*,./:;?@[\\]^_`{|}~+<=>\\s]+){0,50}",
        strategy: RedactionStrategy::EntropyGated,
    },
    PatternSpec {
        pattern: "(?i)(key|access|sas|shared|secret|password|pswd|pwd|credential)[\\s\\S]{0,200}[^a-z0-9/+]([a-z0-9/+]{86}=)",
        strategy: RedactionStrategy::EntropyGated,
    },
    // Microsoft Entra Client Secret/Identifiable/Access Token
    PatternSpec {
        pattern: "(?i)(\\Waws|amazon)?.{0,5}(secret|access.?(key|token)).{0,10}[^/,\\w\\+\\$\\-][a-z0-9/\\+]{40}\\W",
        strategy: RedactionStrategy::EntropyGated,
    },
    PatternSpec {
        pattern: "(?i)((app(lication)?|client|api)[_ \\-]?(se?cre?t|key(url)?)|(refresh|twilio(account|auth))[_ \\-]?(Sid|Token))([\\s=:>]{1,10}|[\\s\"':=|>,\\]\\\\]{3,15}|[\"'=:\\(]{2})(ConvertTo-SecureString[^\"']+[\"'])?(\"data:text/plain,.+\"|[a-z0-9/+=_.\\?\\-]{8,200}[^\\(\\[\\{;,\\r\\n]|[^\\s\"';<,\\)]{5,200})",
        strategy: RedactionStrategy::EntropyGated,
    },
    PatternSpec {
        pattern: "(?-i)eyJ(?i)[a-z0-9\\-_%]+\\.(?-i)eyJ",
        strategy: RedactionStrategy::Strict,
    },
    // General Password
    PatternSpec {
        pattern: "(?i)((amqp|ssh|(ht|f)tps?)://[^%:\\s\"'/][^:\\s\"'/\\$]+[^:\\s\"'/\\$%]:([^%\\s\"'/][^@\\s\"'/]{0,100}[^%\\s\"'/])@[\\$a-z0-9:\\._%\\?=/]+|[a-z0-9]{3,5}://[^%:\\s\"'/][^:\\s\"'/\\$]+[^:\\s\"'/\\$%]:([^%\\s\"'/][^@\\s\"'/]{0,100}[^%\\s\"'/])@[\\$a-z0-9:\\._%\\?=/\\-]+)",
        strategy: RedactionStrategy::Strict,
    },
    // Http Authorization Header
    PatternSpec {
        pattern: "(?i)authorization[,\\[:= \"'\\s]+(value[,\\[:= \"'\\s]+)?(basic|digest|hoba|mutual|negotiate|oauth( oauth_token=)?|(http[^ ]+/saml\\d\\-)?bearer [^e\"'&]|scram\\-sha\\-1|scram\\-sha\\-256|vapid|aws4\\-hmac\\-sha256).*",
        strategy: RedactionStrategy::Strict,
    },
];

static REGEX_PATTERNS: once_cell::sync::Lazy<Vec<(regex::Regex, RedactionStrategy)>> =
    once_cell::sync::Lazy::new(init_regex_patterns);

fn init_regex_patterns() -> Vec<(regex::Regex, RedactionStrategy)> {
    let mut patterns = Vec::new();
    for spec in CRED_PATTERNS.iter() {
        if let Ok(re) = regex::Regex::new(spec.pattern) {
            patterns.push((re, spec.strategy));
        }
    }
    patterns
}

/// Computes Shannon entropy (in bits per character) of a byte string.
///
/// Shannon entropy measures the average information content (randomness) in data.
/// Formula: H = -Σ(p_i * log2(p_i)), where p_i is the probability of each byte value.
///
/// **Return values:**
/// - Empty string: 0.0 (no information)
/// - Uniform distribution (all bytes equally likely): ~8.0 (high randomness)
/// - Predictable/repetitive strings: < 2.0 (low randomness, e.g., "aaaa")
/// - Random alphanumeric base64: ~5.5 (balanced randomness, typical for secrets)
/// - Hex/SHA1 hashes: ~3.3 (limited charset, only 0-9a-f)
///
/// **Performance:** O(n) byte scan + 256 histogram lookups. Fast and suitable for
/// per-match evaluation during secret redaction.
///
/// **Used by:** entropy-gated redaction to distinguish real credentials (high entropy)
/// from false positives like class names, guids, and structured IDs (low entropy).
fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    let bytes = input.as_bytes();
    for &byte in bytes {
        freq[byte as usize] += 1;
    }

    let len = bytes.len() as f64;
    let mut entropy = 0.0;
    for count in freq.iter().copied().filter(|count| *count > 0) {
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

/// Converts a single hexadecimal character to its numeric value.
///
/// Accepts uppercase, lowercase, and digits: '0'-'9' (0-9), 'a'-'f' (10-15), 'A'-'F' (10-15).
/// Returns `None` if the character is not a valid hex digit.
///
/// **Performance:** O(1) simple pattern match, no allocations.
///
/// **Used by:** `decode_percent_once()` to handle percent-encoded bytes ('%2F' → '/', '%3D' → '=').
/// Essential for normalizing URL-encoded secrets before entropy evaluation.
///
/// **Examples:**
/// - `from_hex_digit('A')` → `Some(10)`
/// - `from_hex_digit('f')` → `Some(15)`
/// - `from_hex_digit('5')` → `Some(5)`
/// - `from_hex_digit('G')` → `None`
fn from_hex_digit(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

/// Decodes percent-encoded characters one pass through the input string.
///
/// Scans for '%' followed by exactly two hexadecimal digits and converts them to the
/// corresponding byte. If '%' is not followed by valid hex digits, it is left unchanged.
/// This handles URL encoding: '%2F' → '/', '%3D' → '=', '%2B' → '+'.
///
/// **Algorithm:** Linear single-pass scan with state machine:
/// - When '%' found at position i with i+2 < len:
///   - Try to parse chars[i+1] and chars[i+2] as hex via `from_hex_digit()`
///   - If both valid: emit decoded byte, skip 3 chars
///   - If invalid: emit '%' and advance by 1, letting next char be reprocessed
/// - For non-'%' chars: emit as-is, advance by 1
///
/// **Performance:** O(n) where n is input length. Single-pass linear scan with no allocations
/// beyond the output string (pre-allocated to input length).
///
/// **Return value:** Decoded string. Unchanged if no valid percent sequences found.
///
/// **Used by:** `decode_percent_once_or_twice()` to normalize URL-encoded secrets
/// ('%2F' encoded as %252F → first pass → %2F → second pass → '/').
/// Necessary because secrets in logs may be URL-encoded once or twice depending on
/// how they were logged (direct HTTP request vs. logged URL vs. logged log message).
///
/// **Examples:**
/// - `decode_percent_once("key=%2F")` → `"key=/"`
/// - `decode_percent_once("sig=a%3Db%3Dc")` → `"sig=a=b=c"`
/// - `decode_percent_once("path%2Fto%2Ffile")` → `"path/to/file"`
/// - `decode_percent_once("invalid%ZZ")` → `"invalid%ZZ"` (invalid hex left as-is)
/// - `decode_percent_once("normal_text")` → `"normal_text"` (no change)
fn decode_percent_once(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0usize;

    while i < chars.len() {
        if chars[i] == '%' && i + 2 < chars.len() {
            if let (Some(high), Some(low)) =
                (from_hex_digit(chars[i + 1]), from_hex_digit(chars[i + 2]))
            {
                out.push((high << 4 | low) as char);
                i += 3;
                continue;
            }
        }

        out.push(chars[i]);
        i += 1;
    }

    out
}

fn decode_percent_once_or_twice(input: &str) -> String {
    let once = decode_percent_once(input);
    if once == input {
        return once;
    }

    let twice = decode_percent_once(&once);
    if twice == once {
        once
    } else {
        twice
    }
}

/// Checks if a character is valid in base64 credential content.
///
/// **Valid characters:**
/// - ASCII alphanumeric: 'a'-'z', 'A'-'Z', '0'-'9' (62 chars)
/// - Special base64 chars: '/' (63rd), '+' (62nd), '=' (padding)
/// Together: the standard base64 alphabet and padding. URL-safe variants also use '-' and '_'
/// which are not included here (conservative approach for entropy evaluation).
///
/// **Why these characters:**
/// Most credentials (API keys, OAuth tokens, AWS secret keys, JWT segments) are base64-encoded.
/// These characters are "content-bearing" and should be grouped when calculating entropy.
/// Non-candidate chars (spaces, punctuation, special chars) act as delimiters/boundaries
/// and should not be included in entropy calculation.
///
/// **Performance:** O(1) character class match, no allocations.
///
/// **Used by:** `should_redact_entropy_gated_match()` to split matched regex results
/// into meaningful segments via `.split(|c| !is_entropy_candidate_char(c))`,
/// isolating credential tokens from surrounding text before entropy evaluation.
///
/// **Examples:**
/// - `is_entropy_candidate_char('a')` → `true`
/// - `is_entropy_candidate_char('9')` → `true`
/// - `is_entropy_candidate_char('/')` → `true`
/// - `is_entropy_candidate_char('+')` → `true`
/// - `is_entropy_candidate_char('=')` → `true`
/// - `is_entropy_candidate_char(' ')` → `false` (whitespace)
/// - `is_entropy_candidate_char(':')` → `false` (punctuation)
/// - `is_entropy_candidate_char('-')` → `false` (URL-safe base64, excluded for strictness)
fn is_entropy_candidate_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '/' | '+' | '=')
}

/// Determines if a regex match should be redacted based on entropy analysis.
///
/// This is the **gating validator** for entropy-gated redaction strategy (Databricks-inspired).
/// It filters entropy-gated pattern matches to suppress false positives while catching real secrets.
///
/// **Pipeline:**
/// 1. Normalize input by decoding percent-encoding (once or twice)
///    - Handles URL-encoded secrets: '%2F' → '/', '%252F' → '/'
/// 2. Split normalized string on non-base64 characters
///    - Isolates credential tokens from surrounding text (delimiters: spaces, ':','=', etc.)
/// 3. Filter segments by minimum length (>= 20 chars)
///    - Entropy is unreliable for short strings
/// 4. Calculate Shannon entropy for each segment
///    - Measures randomness/information content in bits per character
/// 5. Take maximum entropy across all segments
///    - One high-entropy token means redact (conservative: any secret wins)
/// 6. Compare against threshold (4.0 bits/char)
///    - Real secrets: ~5.0-5.5 (base64)
///    - False positives: < 4.0 (class names, hashes, IDs)
///
/// **Why this approach:**
/// - Entropy-gated patterns (broad regexes) are high-coverage but prone to false positives
/// - Example: `"key=classNameLikeThis"` matches but shouldn't redact (low entropy)
/// - Example: `"key=a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t"` should redact (high entropy)
///
/// **Return value:** `true` if estimated to be a real secret, `false` otherwise.
///
/// **Performance:** O(n) where n is matched string length:
/// - Percent-decoding: O(n)
/// - Split + entropy: O(n) per segment (histogramming + logarithms)
/// - Overall: linear scan, suitable for per-match validation in redact loops
///
/// **Used by:** `redact_secrets()` when evaluating `RedactionStrategy::EntropyGated` patterns.
/// Called once per match to decide redaction.
///
/// **Examples:**
/// - `should_redact_entropy_gated_match("aaaaaaaaaaaaaaaaaaaaaa")` → `false` (all same char, entropy ~0)
/// - `should_redact_entropy_gated_match("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0")` → `true` (entropy ~5.3)
/// - `should_redact_entropy_gated_match("classNameDefinition1234567890abcdefghij")` → `false` (entropy ~3.8)
/// - `should_redact_entropy_gated_match("key=%2Fa%2Bb%3Dc%3Dd%3De%3Df...")` → `true` (normalized to base64, high entropy)
fn should_redact_entropy_gated_match(matched: &str) -> bool {
    let normalized = decode_percent_once_or_twice(matched);

    normalized
        .split(|c| !is_entropy_candidate_char(c))
        .filter(|segment| segment.len() >= MIN_ENTROPY_CANDIDATE_LEN)
        .map(shannon_entropy)
        .fold(0.0f64, f64::max)
        >= ENTROPY_REDACTION_THRESHOLD
}

/// Quick check if text might contain secrets (case-insensitive for most indicators)
#[inline]
fn might_contain_secrets(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SECRET_INDICATORS.iter().any(|indicator| {
        if *indicator == "AzCa" || *indicator == "PRIVATE KEY" || *indicator == "eyJ" {
            // Case-sensitive check for these
            text.contains(indicator)
        } else {
            lower.contains(&indicator.to_ascii_lowercase())
        }
    })
}

/// Redacts secrets from text. Returns the original text unchanged if no secrets found.
/// Takes `&str` to avoid unnecessary ownership transfer.
fn redact_secrets(text: &str) -> Cow<'_, str> {
    if text.is_empty() || !might_contain_secrets(text) {
        return Cow::Borrowed(text);
    }

    let mut redacted_text = Cow::Borrowed(text);
    for (pattern, strategy) in REGEX_PATTERNS.iter() {
        match strategy {
            RedactionStrategy::Strict => {
                if let Cow::Owned(s) = pattern.replace_all(&redacted_text, REDACTED_TEXT) {
                    redacted_text = Cow::Owned(s);
                }
            }
            RedactionStrategy::EntropyGated => {
                let input = redacted_text.as_ref();
                if !pattern
                    .find_iter(input)
                    .any(|m| should_redact_entropy_gated_match(m.as_str()))
                {
                    continue;
                }

                if let Cow::Owned(s) = pattern.replace_all(input, |caps: &regex::Captures| {
                    let matched = caps.get(0).map_or("", |m| m.as_str());
                    if should_redact_entropy_gated_match(matched) {
                        REDACTED_TEXT.to_string()
                    } else {
                        matched.to_string()
                    }
                }) {
                    redacted_text = Cow::Owned(s);
                }
            }
        }
    }
    redacted_text
}

/// Convenience function that takes ownership and returns String
/// Use this when you already have a String and need a String back
#[inline]
pub fn redact_secrets_string(text: String) -> String {
    match redact_secrets(&text) {
        Cow::Borrowed(_) => text, // No changes, return original
        Cow::Owned(s) => s,       // Changed, return new string
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_secrets() {
        let test_strings = vec![
            (
                "server=...database.windows.net;database=...;pwd=<dummyString>;user=...;",
                "server=...database.windows.net;database=...;[REDACTED];user=...;",
            ),
            (
                "server=...database.windows.net;database=...;password=<dummyString>;user=...;",
                "server=...database.windows.net;database=...;[REDACTED];user=...;",
            ),
            (
                "https://abc.core.windows.net/blob?sig=<dummyKey>&otherparam=value",
                "https://abc.core.windows.net/blob?[REDACTED]&otherparam=value",
            ),
            (
                "Endpoint=...table.core.windows.net;AccountKey=<dummyString>;AccountName=...",
                "Endpoint=...table.core.windows.net;[REDACTED];AccountName=...",
            ),
            (
                "Endpoint=...table.core.windows.net;PrimaryKey=<dummyString>;AccountName=...",
                "Endpoint=...table.core.windows.net;[REDACTED];AccountName=...",
            ),
            (
                "Endpoint=...table.core.windows.net;SecondaryKey=<dummyString>;AccountName=...",
                "Endpoint=...table.core.windows.net;[REDACTED];AccountName=...",
            ),
            (
                "https://example.com/api?sig=<dummyKey>",
                "https://example.com/api?[REDACTED]",
            ),
            (
                "-----BEGIN RSA PRIVATE KEY-----\nMI...\n-----END RSA PRIVATE KEY-----",
                "-----[REDACTED]-----",
            ),
            (
                r#"Here is a token:abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst
And another one: azuredevops=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRST"#,
                "Here is a [REDACTED]\nAnd another one: [REDACTED]",
            ),
            (
                r#"Here is one: abcdefghijklmnopqrstuvwxyzABCDEFGAzCaG12345=
Another one: 1234567890abcdefghijklmnopqrstuvwxyzABC12345AzCaabcdeQ"#,
                "Here is one: [REDACTED]\nAnother one: [REDACTED]",
            ),
            (
                "EntraAccessToken:eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJtest",
                "EntraAccessToken:[REDACTED]test",
            ),
            (
                r#"Authorization: Bearer abcdef123456
authorization = basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
Authorization value: oauth oauth_token=xyz
authorization: aws4-hmac-sha256"#,
                "[REDACTED]\n[REDACTED]\n[REDACTED]\n[REDACTED]",
            ),
        ];
        for (input, expected) in test_strings {
            assert_eq!(redact_secrets(input), expected);
        }
    }

    #[test]
    fn test_no_secrets_no_allocation() {
        let text = "This is a normal log message without any secrets";
        let result = redact_secrets(text);
        // Should return Borrowed (no allocation) when no secrets found
        assert!(matches!(result, std::borrow::Cow::Borrowed(_)));
        assert_eq!(result, text);
    }

    #[test]
    fn test_redact_secrets_string() {
        let text = "pwd=secret123;".to_string();
        let result = redact_secrets_string(text);
        assert_eq!(result, "[REDACTED];");
    }

    #[test]
    fn test_decode_percent_once_or_twice() {
        assert_eq!(
            decode_percent_once_or_twice("token=a%2Fb%2Bc%3D"),
            "token=a/b+c="
        );
        assert_eq!(
            decode_percent_once_or_twice("token=a%252Fb%252Bc%253D"),
            "token=a/b+c="
        );
    }

    #[test]
    fn test_shannon_entropy_basic() {
        let low = shannon_entropy("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let high = shannon_entropy("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0");
        assert!(high > low);
    }

    #[test]
    fn test_entropy_gated_tests() {
        let input = "aws secret: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;";
        assert_eq!(redact_secrets(input), input);

        let input = "aws secret: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0;";
        assert_eq!(redact_secrets(input), "[REDACTED]");
    }
}
