use chrono::{DateTime, Utc};
use colored::Colorize;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" | "med" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Info,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn colored_label(&self) -> String {
        match self {
            Severity::Critical => "CRITICAL".bright_red().bold().to_string(),
            Severity::High => "HIGH".red().bold().to_string(),
            Severity::Medium => "MEDIUM".yellow().bold().to_string(),
            Severity::Low => "LOW".blue().to_string(),
            Severity::Info => "INFO".dimmed().to_string(),
        }
    }

    /// Numeric score for sorting (higher = more severe).
    pub fn score(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub tool_source: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub target: String,
    pub timestamp: DateTime<Utc>,
    pub deduplicated: bool,
}

impl Finding {
    pub fn new(
        tool_source: &str,
        severity: Severity,
        title: &str,
        description: &str,
        evidence: &str,
        target: &str,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            tool_source: tool_source.to_string(),
            severity,
            title: title.to_string(),
            description: description.to_string(),
            evidence: evidence.to_string(),
            target: target.to_string(),
            timestamp: Utc::now(),
            deduplicated: false,
        }
    }

    /// Generate a deduplication key based on tool + title + target.
    pub fn dedup_key(&self) -> String {
        format!("{}:{}:{}", self.tool_source, self.title, self.target)
    }
}
