use std::collections::HashSet;

use crate::findings::models::Finding;

/// Deduplicate a list of findings based on their dedup key (tool + title + target).
/// Returns the deduplicated list with the `deduplicated` flag set on removed entries.
pub fn deduplicate(findings: &[Finding]) -> Vec<Finding> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut result = Vec::new();

    for finding in findings {
        let key = finding.dedup_key();
        if seen.contains(&key) {
            continue;
        }
        seen.insert(key);
        result.push(finding.clone());
    }

    result
}

/// Correlate findings from different tools that refer to the same vulnerability.
/// Groups findings by target and looks for overlapping descriptions.
pub fn correlate(findings: &[Finding]) -> Vec<CorrelationGroup> {
    let mut groups: Vec<CorrelationGroup> = Vec::new();

    for finding in findings {
        let mut matched = false;
        for group in &mut groups {
            if group.target == finding.target && titles_overlap(&group.primary_title, &finding.title)
            {
                group.related.push(finding.clone());
                matched = true;
                break;
            }
        }

        if !matched {
            groups.push(CorrelationGroup {
                target: finding.target.clone(),
                primary_title: finding.title.clone(),
                primary: finding.clone(),
                related: Vec::new(),
            });
        }
    }

    groups
}

#[derive(Debug, Clone)]
pub struct CorrelationGroup {
    pub target: String,
    pub primary_title: String,
    pub primary: Finding,
    pub related: Vec<Finding>,
}

/// Simple heuristic: two titles overlap if they share significant words.
fn titles_overlap(a: &str, b: &str) -> bool {
    let a_words: HashSet<&str> = a
        .split_whitespace()
        .filter(|w| w.len() > 3)
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .collect();
    let b_words: HashSet<&str> = b
        .split_whitespace()
        .filter(|w| w.len() > 3)
        .map(|w| w.trim_matches(|c: char| !c.is_alphanumeric()))
        .collect();

    let intersection = a_words.intersection(&b_words).count();
    let min_len = a_words.len().min(b_words.len());

    if min_len == 0 {
        return false;
    }

    // Consider overlapping if >50% of shorter title's significant words match
    (intersection as f64 / min_len as f64) > 0.5
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::findings::models::Severity;

    #[test]
    fn test_deduplicate() {
        let findings = vec![
            Finding::new("nuclei", Severity::High, "CVE-2024-1234", "desc", "evidence", "example.com"),
            Finding::new("nuclei", Severity::High, "CVE-2024-1234", "desc", "evidence", "example.com"),
            Finding::new("nmap", Severity::Medium, "Open SSH", "desc", "evidence", "example.com"),
        ];

        let deduped = deduplicate(&findings);
        assert_eq!(deduped.len(), 2);
    }

    #[test]
    fn test_titles_overlap() {
        assert!(titles_overlap(
            "Exposed MySQL service on port 3306",
            "MySQL service exposed on 3306/tcp"
        ));
        assert!(!titles_overlap(
            "Open SSH on port 22",
            "SQL injection in login form"
        ));
    }
}
