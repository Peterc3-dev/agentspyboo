use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use super::models::{Finding, Severity};

/// SQLite-backed findings database.
pub struct FindingsDb {
    conn: Connection,
}

impl FindingsDb {
    pub fn new(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("Failed to open findings database")?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                tool_source TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                deduplicated INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
            CREATE INDEX IF NOT EXISTS idx_findings_dedup ON findings(title, target, tool_source);
            ",
        )
        .context("Failed to initialize findings schema")?;

        Ok(Self { conn })
    }

    /// Insert a finding, skipping if a duplicate already exists.
    pub fn insert(&self, finding: &Finding) -> Result<bool> {
        // Check for duplicates first
        let exists: bool = self
            .conn
            .query_row(
                "SELECT COUNT(*) > 0 FROM findings WHERE title = ?1 AND target = ?2 AND tool_source = ?3",
                params![finding.title, finding.target, finding.tool_source],
                |row| row.get(0),
            )
            .unwrap_or(false);

        if exists {
            tracing::debug!("Duplicate finding skipped: {}", finding.title);
            return Ok(false);
        }

        self.conn
            .execute(
                "INSERT INTO findings (id, tool_source, severity, title, description, evidence, target, timestamp, deduplicated)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    finding.id,
                    finding.tool_source,
                    finding.severity.as_str(),
                    finding.title,
                    finding.description,
                    finding.evidence,
                    finding.target,
                    finding.timestamp.to_rfc3339(),
                    finding.deduplicated as i32,
                ],
            )
            .context("Failed to insert finding")?;

        Ok(true)
    }

    /// Count total findings.
    pub fn count(&self) -> Result<usize> {
        let count: usize = self
            .conn
            .query_row("SELECT COUNT(*) FROM findings", [], |row| row.get(0))
            .context("Failed to count findings")?;
        Ok(count)
    }

    /// Get all findings, ordered by severity (most severe first).
    pub fn all(&self) -> Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, tool_source, severity, title, description, evidence, target, timestamp, deduplicated
             FROM findings
             ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END",
        )?;

        let findings = stmt
            .query_map([], |row| {
                let severity_str: String = row.get(2)?;
                let timestamp_str: String = row.get(7)?;
                let dedup: i32 = row.get(8)?;

                Ok(Finding {
                    id: row.get(0)?,
                    tool_source: row.get(1)?,
                    severity: Severity::from_str(&severity_str),
                    title: row.get(3)?,
                    description: row.get(4)?,
                    evidence: row.get(5)?,
                    target: row.get(6)?,
                    timestamp: chrono::DateTime::parse_from_rfc3339(&timestamp_str)
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                        .unwrap_or_else(|_| chrono::Utc::now()),
                    deduplicated: dedup != 0,
                })
            })?
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to query findings")?;

        Ok(findings)
    }

    /// Get findings filtered by severity.
    pub fn by_severity(&self, severity: Severity) -> Result<Vec<Finding>> {
        let all = self.all()?;
        Ok(all.into_iter().filter(|f| f.severity == severity).collect())
    }

    /// Get count by severity for summary stats.
    pub fn severity_counts(&self) -> Result<SeverityCounts> {
        let all = self.all()?;
        Ok(SeverityCounts {
            critical: all.iter().filter(|f| f.severity == Severity::Critical).count(),
            high: all.iter().filter(|f| f.severity == Severity::High).count(),
            medium: all.iter().filter(|f| f.severity == Severity::Medium).count(),
            low: all.iter().filter(|f| f.severity == Severity::Low).count(),
            info: all.iter().filter(|f| f.severity == Severity::Info).count(),
        })
    }
}

#[derive(Debug)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}
