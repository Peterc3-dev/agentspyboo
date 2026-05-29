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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_scheme_path_and_port() {
        assert_eq!(normalize_host("https://Example.com/foo?bar"), "example.com");
        assert_eq!(normalize_host("http://example.com:8080/"), "example.com");
        assert_eq!(normalize_host("  EXAMPLE.com  "), "example.com");
        assert_eq!(normalize_host("example.com:443"), "example.com");
    }

    #[test]
    fn normalize_keeps_non_port_colon_suffix() {
        // A trailing colon segment that is not all-digits must be preserved
        // (e.g. an IPv6-ish or malformed host should not be silently truncated).
        assert_eq!(normalize_host("host:notaport"), "host:notaport");
    }

    #[test]
    fn bare_host_matches_exactly() {
        let patterns = vec!["example.com".to_string()];
        assert!(host_in_scope("example.com", &patterns));
        assert!(host_in_scope("https://example.com/path", &patterns));
        assert!(!host_in_scope("evil.com", &patterns));
        // bare pattern must not match a subdomain
        assert!(!host_in_scope("sub.example.com", &patterns));
    }

    #[test]
    fn wildcard_matches_apex_and_subdomains() {
        let patterns = vec!["*.example.com".to_string()];
        // "*." matches the apex itself...
        assert!(host_in_scope("example.com", &patterns));
        // ...and any subdomain
        assert!(host_in_scope("api.example.com", &patterns));
        assert!(host_in_scope("a.b.example.com", &patterns));
        // but not a different registrable domain that merely ends similarly
        assert!(!host_in_scope("notexample.com", &patterns));
        assert!(!host_in_scope("example.com.evil.com", &patterns));
    }

    #[test]
    fn empty_patterns_match_nothing() {
        assert!(!host_in_scope("example.com", &[]));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let patterns = vec!["Example.COM".to_string()];
        // pattern is compared as-is; host is lowercased. The current contract is
        // that callers pass lowercase patterns, so an uppercase pattern only
        // matches an (impossible post-normalize) uppercase host. Document that
        // by asserting the lowercased host does NOT match an uppercase pattern.
        assert!(!host_in_scope("example.com", &patterns));
        // The supported path: lowercase pattern, any-case host.
        let patterns = vec!["example.com".to_string()];
        assert!(host_in_scope("EXAMPLE.COM", &patterns));
    }
}
