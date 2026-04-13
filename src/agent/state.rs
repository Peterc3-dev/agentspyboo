use std::fmt;

use colored::Colorize;

/// Phases the agent progresses through during an engagement.
/// The LLM can request transitions back to earlier phases if
/// new attack surface is discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Phase {
    Recon,
    Enumerate,
    VulnScan,
    Exploit,
    Report,
}

impl fmt::Display for Phase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Phase::Recon => write!(f, "RECON"),
            Phase::Enumerate => write!(f, "ENUMERATE"),
            Phase::VulnScan => write!(f, "VULN_SCAN"),
            Phase::Exploit => write!(f, "EXPLOIT"),
            Phase::Report => write!(f, "REPORT"),
        }
    }
}

impl Phase {
    pub fn colored_label(&self) -> String {
        match self {
            Phase::Recon => "RECON".bright_blue().bold().to_string(),
            Phase::Enumerate => "ENUMERATE".bright_cyan().bold().to_string(),
            Phase::VulnScan => "VULN_SCAN".bright_yellow().bold().to_string(),
            Phase::Exploit => "EXPLOIT".bright_red().bold().to_string(),
            Phase::Report => "REPORT".bright_green().bold().to_string(),
        }
    }

    /// Suggest the next phase in the default pipeline order.
    pub fn next(&self) -> Option<Phase> {
        match self {
            Phase::Recon => Some(Phase::Enumerate),
            Phase::Enumerate => Some(Phase::VulnScan),
            Phase::VulnScan => Some(Phase::Exploit),
            Phase::Exploit => Some(Phase::Report),
            Phase::Report => None,
        }
    }
}

/// Mutable state carried across ReAct iterations.
#[derive(Debug, Clone)]
pub struct AgentState {
    pub phase: Phase,
    pub step: usize,
    pub target: String,
    /// Accumulates observations for the LLM context window.
    pub observations: Vec<Observation>,
    /// Subdomains, URLs, ports, etc. discovered so far.
    pub discovered_assets: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Observation {
    pub step: usize,
    pub tool: String,
    pub input_summary: String,
    pub output_summary: String,
}

impl AgentState {
    pub fn new(target: &str) -> Self {
        Self {
            phase: Phase::Recon,
            step: 0,
            target: target.to_string(),
            observations: Vec::new(),
            discovered_assets: Vec::new(),
        }
    }

    pub fn set_phase(&mut self, phase: Phase) {
        tracing::info!("Phase transition: {} -> {}", self.phase, phase);
        self.phase = phase;
    }

    pub fn add_observation(&mut self, tool: &str, input: &str, output: &str) {
        self.observations.push(Observation {
            step: self.step,
            tool: tool.to_string(),
            input_summary: input.to_string(),
            output_summary: truncate(output, 2000),
        });
    }

    pub fn add_asset(&mut self, asset: String) {
        if !self.discovered_assets.contains(&asset) {
            self.discovered_assets.push(asset);
        }
    }

    /// Build a context summary for the LLM, keeping token count manageable.
    pub fn context_summary(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Target: {}\n", self.target));
        s.push_str(&format!("Current Phase: {}\n", self.phase));
        s.push_str(&format!("Step: {}\n", self.step));

        if !self.discovered_assets.is_empty() {
            s.push_str(&format!(
                "Discovered Assets ({}):\n",
                self.discovered_assets.len()
            ));
            for asset in &self.discovered_assets {
                s.push_str(&format!("  - {}\n", asset));
            }
        }

        // Include last N observations to stay within context limits
        let recent: Vec<_> = self
            .observations
            .iter()
            .rev()
            .take(10)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        if !recent.is_empty() {
            s.push_str("\nRecent Observations:\n");
            for obs in recent {
                s.push_str(&format!(
                    "  [Step {}] {} -> {}: {}\n",
                    obs.step,
                    obs.tool,
                    obs.input_summary,
                    truncate(&obs.output_summary, 500)
                ));
            }
        }

        s
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}... [truncated]", &s[..max_len])
    }
}
