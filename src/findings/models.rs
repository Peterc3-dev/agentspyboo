// Finding data types.

use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_str_loose(s: &str) -> Severity {
        match s.trim().to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "moderate" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }
    pub fn icon(&self) -> &'static str {
        match self {
            Severity::Info => "ℹ️",
            Severity::Low => "🔵",
            Severity::Medium => "🟡",
            Severity::High => "🟠",
            Severity::Critical => "🔴",
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub kind: String,
    pub target: String,
    pub details: String,
    #[serde(default = "chrono::Utc::now")]
    pub first_seen: chrono::DateTime<chrono::Utc>,
}

impl Finding {
    pub fn new(
        severity: Severity,
        kind: impl Into<String>,
        target: impl Into<String>,
        details: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            kind: kind.into(),
            target: target.into(),
            details: details.into(),
            first_seen: chrono::Utc::now(),
        }
    }
}

/// Deduped view of findings. Identical (kind, details) tuples are folded
/// into one entry with all observed targets and a source count.
#[derive(Debug, Clone, Serialize)]
pub struct DedupedFinding {
    pub severity: Severity,
    pub kind: String,
    pub targets: Vec<String>,
    pub details: String,
    pub count: usize,
    pub first_seen: chrono::DateTime<chrono::Utc>,
}

/// Fold a flat findings list into deduped entries. Grouping key is
/// (kind, details) — severity is promoted to the max of grouped rows, targets
/// are collected (dedup-preserving insertion order), count reflects source
/// count, first_seen is the earliest timestamp across the group.
pub fn dedup_findings(raw: &[Finding]) -> Vec<DedupedFinding> {
    use std::collections::BTreeMap;
    let mut groups: BTreeMap<(String, String), DedupedFinding> = BTreeMap::new();
    let mut order: Vec<(String, String)> = Vec::new();
    for f in raw {
        let key = (f.kind.clone(), f.details.clone());
        if let Some(entry) = groups.get_mut(&key) {
            if !entry.targets.contains(&f.target) {
                entry.targets.push(f.target.clone());
            }
            if f.severity > entry.severity {
                entry.severity = f.severity;
            }
            if f.first_seen < entry.first_seen {
                entry.first_seen = f.first_seen;
            }
            entry.count += 1;
        } else {
            order.push(key.clone());
            groups.insert(
                key,
                DedupedFinding {
                    severity: f.severity,
                    kind: f.kind.clone(),
                    targets: vec![f.target.clone()],
                    details: f.details.clone(),
                    count: 1,
                    first_seen: f.first_seen,
                },
            );
        }
    }
    let mut out: Vec<DedupedFinding> = order
        .into_iter()
        .filter_map(|k| groups.remove(&k))
        .collect();
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.count.cmp(&a.count)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_low_to_high() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn from_str_loose_handles_aliases_and_unknowns() {
        assert_eq!(Severity::from_str_loose("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::from_str_loose(" high "), Severity::High);
        assert_eq!(Severity::from_str_loose("moderate"), Severity::Medium);
        assert_eq!(Severity::from_str_loose("medium"), Severity::Medium);
        assert_eq!(Severity::from_str_loose("low"), Severity::Low);
        // anything unrecognized falls back to Info
        assert_eq!(Severity::from_str_loose("bogus"), Severity::Info);
        assert_eq!(Severity::from_str_loose(""), Severity::Info);
    }

    #[test]
    fn dedup_folds_identical_kind_and_details() {
        let raw = vec![
            Finding::new(Severity::Low, "http-probe", "a.example.com", "same"),
            Finding::new(Severity::High, "http-probe", "b.example.com", "same"),
            Finding::new(Severity::Low, "http-probe", "a.example.com", "same"),
        ];
        let deduped = dedup_findings(&raw);
        assert_eq!(deduped.len(), 1);
        let d = &deduped[0];
        // severity promoted to the max of the group
        assert_eq!(d.severity, Severity::High);
        // count reflects number of source rows, not unique targets
        assert_eq!(d.count, 3);
        // targets deduped, insertion order preserved
        assert_eq!(
            d.targets,
            vec!["a.example.com".to_string(), "b.example.com".to_string()]
        );
    }

    #[test]
    fn dedup_keeps_distinct_groups_and_sorts_by_severity() {
        let raw = vec![
            Finding::new(Severity::Info, "http-probe", "x", "low-thing"),
            Finding::new(Severity::Critical, "nuclei", "y", "bad-thing"),
        ];
        let deduped = dedup_findings(&raw);
        assert_eq!(deduped.len(), 2);
        // sorted severity desc -> Critical first
        assert_eq!(deduped[0].severity, Severity::Critical);
        assert_eq!(deduped[1].severity, Severity::Info);
    }

    #[test]
    fn dedup_empty_input_yields_empty() {
        assert!(dedup_findings(&[]).is_empty());
    }
}
