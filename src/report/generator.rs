use anyhow::Result;
use chrono::Utc;

use crate::findings::dedup;
use crate::findings::models::{Finding, Severity};
use super::templates;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a full Markdown report from a list of findings.
    pub fn generate(&self, target: &str, findings: &[Finding]) -> Result<String> {
        let deduped = dedup::deduplicate(findings);

        let critical = deduped.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = deduped.iter().filter(|f| f.severity == Severity::High).count();
        let medium = deduped.iter().filter(|f| f.severity == Severity::Medium).count();
        let low = deduped.iter().filter(|f| f.severity == Severity::Low).count();
        let info = deduped.iter().filter(|f| f.severity == Severity::Info).count();
        let total = deduped.len();

        let executive_summary = self.generate_executive_summary(target, critical, high, medium, low, info);

        let mut report = templates::REPORT_HEADER
            .replace("{date}", &Utc::now().format("%Y-%m-%d %H:%M UTC").to_string())
            .replace("{target}", target)
            .replace("{executive_summary}", &executive_summary)
            .replace("{critical}", &critical.to_string())
            .replace("{high}", &high.to_string())
            .replace("{medium}", &medium.to_string())
            .replace("{low}", &low.to_string())
            .replace("{info}", &info.to_string())
            .replace("{total}", &total.to_string());

        // Add individual findings
        for (i, finding) in deduped.iter().enumerate() {
            let entry = templates::FINDING_ENTRY
                .replace("{index}", &(i + 1).to_string())
                .replace("{severity}", &finding.severity.as_str().to_uppercase())
                .replace("{title}", &finding.title)
                .replace("{tool}", &finding.tool_source)
                .replace("{target}", &finding.target)
                .replace("{timestamp}", &finding.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .replace("{description}", &finding.description)
                .replace("{evidence}", &finding.evidence);

            report.push_str(&entry);
        }

        report.push_str(templates::REPORT_FOOTER);

        Ok(report)
    }

    fn generate_executive_summary(
        &self,
        target: &str,
        critical: usize,
        high: usize,
        medium: usize,
        low: usize,
        info: usize,
    ) -> String {
        let total = critical + high + medium + low + info;

        if total == 0 {
            return format!(
                "An automated penetration test of **{}** was conducted. No findings were identified during the assessment.",
                target
            );
        }

        let risk_level = if critical > 0 {
            "CRITICAL"
        } else if high > 0 {
            "HIGH"
        } else if medium > 0 {
            "MEDIUM"
        } else {
            "LOW"
        };

        let mut summary = format!(
            "An automated penetration test of **{}** identified **{} unique findings**. \
             The overall risk level is **{}**.",
            target, total, risk_level
        );

        if critical > 0 {
            summary.push_str(&format!(
                "\n\n**{} critical finding(s)** require immediate attention and should be remediated as a priority.",
                critical
            ));
        }

        if high > 0 {
            summary.push_str(&format!(
                "\n\n**{} high severity finding(s)** should be addressed in the near term.",
                high
            ));
        }

        if medium > 0 {
            summary.push_str(&format!(
                "\n\n**{} medium severity finding(s)** represent moderate risk and should be planned for remediation.",
                medium
            ));
        }

        summary
    }
}
