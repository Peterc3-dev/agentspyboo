// Scope guard — glob-based allowlist for targets, hosts, and URLs.
//
// Hand-rolled matcher: supports a single leading "*." wildcard, or bare host
// match. Matches case-insensitively. Strips scheme + port + path from `host`
// before comparing.

/// Returns true if `host` (raw, possibly a URL) matches any pattern in `patterns`.
pub fn host_in_scope(host: &str, patterns: &[String]) -> bool {
    let h = normalize_host(host);
    for p in patterns {
        if let Some(suffix) = p.strip_prefix("*.") {
            if h == suffix || h.ends_with(&format!(".{suffix}")) {
                return true;
            }
        } else if h == *p {
            return true;
        }
    }
    false
}

pub fn normalize_host(raw: &str) -> String {
    let mut s = raw.trim().to_lowercase();
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest.to_string();
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest.to_string();
    }
    if let Some(idx) = s.find('/') {
        s.truncate(idx);
    }
    if let Some(idx) = s.rfind(':') {
        // only strip if after last ':' looks like a port
        if s[idx + 1..].chars().all(|c| c.is_ascii_digit()) {
            s.truncate(idx);
        }
    }
    s
}
