use crate::agent::state::{AgentState, Phase};

/// Suggests which tools are most relevant for the current phase.
/// The LLM still makes the final decision, but this narrows the focus.
pub fn suggest_tools_for_phase(phase: &Phase) -> Vec<&'static str> {
    match phase {
        Phase::Recon => vec!["subfinder", "findomain", "gau"],
        Phase::Enumerate => vec!["httpx", "naabu", "nmap"],
        Phase::VulnScan => vec!["nuclei", "ffuf"],
        Phase::Exploit => vec!["nuclei", "ffuf", "nmap"],
        Phase::Report => vec![],
    }
}

/// Decide whether to suggest a phase transition based on current state.
pub fn should_transition(state: &AgentState) -> Option<Phase> {
    let phase = state.phase;
    let obs_in_phase: Vec<_> = state
        .observations
        .iter()
        .filter(|o| {
            let tools = suggest_tools_for_phase(&phase);
            tools.iter().any(|t| *t == o.tool)
        })
        .collect();

    // Simple heuristic: if we have >= 3 observations in the current phase,
    // suggest moving to the next one. The LLM can override this.
    if obs_in_phase.len() >= 3 {
        return phase.next();
    }

    None
}

/// Build a planning prompt hint for the LLM based on current state.
pub fn planning_hint(state: &AgentState) -> String {
    let suggested = suggest_tools_for_phase(&state.phase);
    let transition = should_transition(state);

    let mut hint = format!(
        "You are in the {} phase. Suggested tools: [{}].",
        state.phase,
        suggested.join(", ")
    );

    if let Some(next) = transition {
        hint.push_str(&format!(
            " Consider transitioning to {} phase — you have enough data from the current phase.",
            next
        ));
    }

    if !state.discovered_assets.is_empty() {
        hint.push_str(&format!(
            " You have {} discovered assets to work with.",
            state.discovered_assets.len()
        ));
    }

    hint
}
