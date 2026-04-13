use serde_json::Value;

use crate::agent::state::Phase;

/// Represents what the LLM wants to do on this turn.
#[derive(Debug)]
pub enum LlmAction {
    /// Call a tool with given arguments
    ToolCall {
        name: String,
        arguments: Value,
        thought: Option<String>,
    },
    /// Request a phase transition
    PhaseTransition { phase: Phase, reason: String },
    /// Engagement is complete
    Done { summary: String },
    /// LLM is just thinking (no action)
    Think { thought: String },
    /// Failed to parse
    Error { message: String },
}

/// Parse an LLM response string into an action.
/// Handles both clean JSON and JSON embedded in markdown code blocks.
pub fn parse_llm_response(response: &str) -> LlmAction {
    let cleaned = extract_json(response);

    let json: Value = match serde_json::from_str(&cleaned) {
        Ok(v) => v,
        Err(_) => {
            // Try to find JSON anywhere in the response
            if let Some(action) = try_extract_from_text(response) {
                return action;
            }
            return LlmAction::Error {
                message: format!("No valid JSON found in response: {}", &response[..response.len().min(200)]),
            };
        }
    };

    parse_json_action(&json)
}

/// Parse a serde_json::Value into an LlmAction.
fn parse_json_action(json: &Value) -> LlmAction {
    let thought = json.get("thought").and_then(|v| v.as_str()).map(String::from);

    // Check for "done"
    if let Some(done) = json.get("done") {
        if done.as_bool().unwrap_or(false) {
            let summary = json
                .get("summary")
                .and_then(|v| v.as_str())
                .unwrap_or("Engagement complete")
                .to_string();
            return LlmAction::Done { summary };
        }
    }

    // Check for tool_call
    if let Some(tool_call) = json.get("tool_call") {
        let name = tool_call
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let arguments = tool_call
            .get("arguments")
            .cloned()
            .unwrap_or(Value::Object(serde_json::Map::new()));

        if !name.is_empty() {
            return LlmAction::ToolCall {
                name,
                arguments,
                thought,
            };
        }
    }

    // Check for OpenAI function-calling format (tool_calls array)
    if let Some(tool_calls) = json.get("tool_calls") {
        if let Some(first) = tool_calls.as_array().and_then(|a| a.first()) {
            if let Some(function) = first.get("function") {
                let name = function
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let arguments_str = function
                    .get("arguments")
                    .and_then(|v| v.as_str())
                    .unwrap_or("{}");
                let arguments: Value =
                    serde_json::from_str(arguments_str).unwrap_or(Value::Object(serde_json::Map::new()));

                if !name.is_empty() {
                    return LlmAction::ToolCall {
                        name,
                        arguments,
                        thought,
                    };
                }
            }
        }
    }

    // Check for phase_transition
    if let Some(transition) = json.get("phase_transition") {
        let phase_str = transition
            .get("phase")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let reason = transition
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("No reason given")
            .to_string();

        if let Some(phase) = parse_phase(phase_str) {
            return LlmAction::PhaseTransition { phase, reason };
        }
    }

    // If there's just a thought, return that
    if let Some(thought) = thought {
        return LlmAction::Think { thought };
    }

    LlmAction::Error {
        message: "Unrecognized response format".to_string(),
    }
}

/// Extract JSON from a response that may contain markdown code blocks.
fn extract_json(response: &str) -> String {
    let trimmed = response.trim();

    // Try to extract from ```json ... ``` blocks
    if let Some(start) = trimmed.find("```json") {
        let after = &trimmed[start + 7..];
        if let Some(end) = after.find("```") {
            return after[..end].trim().to_string();
        }
    }

    // Try to extract from ``` ... ``` blocks
    if let Some(start) = trimmed.find("```") {
        let after = &trimmed[start + 3..];
        if let Some(end) = after.find("```") {
            let content = after[..end].trim();
            // Skip language identifier on first line if present
            if let Some(newline) = content.find('\n') {
                let first_line = &content[..newline];
                if !first_line.starts_with('{') {
                    return content[newline + 1..].trim().to_string();
                }
            }
            return content.to_string();
        }
    }

    // Try to find raw JSON object
    if let Some(start) = trimmed.find('{') {
        if let Some(end) = trimmed.rfind('}') {
            return trimmed[start..=end].to_string();
        }
    }

    trimmed.to_string()
}

/// Attempt to extract an action from freeform text (fallback).
fn try_extract_from_text(text: &str) -> Option<LlmAction> {
    let lower = text.to_lowercase();

    if lower.contains("done") && (lower.contains("complete") || lower.contains("finished")) {
        return Some(LlmAction::Done {
            summary: text.to_string(),
        });
    }

    None
}

fn parse_phase(s: &str) -> Option<Phase> {
    match s.to_uppercase().as_str() {
        "RECON" => Some(Phase::Recon),
        "ENUMERATE" => Some(Phase::Enumerate),
        "VULN_SCAN" | "VULNSCAN" => Some(Phase::VulnScan),
        "EXPLOIT" => Some(Phase::Exploit),
        "REPORT" => Some(Phase::Report),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tool_call() {
        let response = r#"{"thought": "Starting recon", "tool_call": {"name": "subfinder", "arguments": {"domain": "example.com"}}}"#;
        match parse_llm_response(response) {
            LlmAction::ToolCall { name, arguments, thought } => {
                assert_eq!(name, "subfinder");
                assert_eq!(arguments["domain"], "example.com");
                assert_eq!(thought.unwrap(), "Starting recon");
            }
            other => panic!("Expected ToolCall, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_done() {
        let response = r#"{"done": true, "summary": "Found 3 vulns"}"#;
        match parse_llm_response(response) {
            LlmAction::Done { summary } => {
                assert_eq!(summary, "Found 3 vulns");
            }
            other => panic!("Expected Done, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_code_block() {
        let response = "Here's what I'll do:\n```json\n{\"tool_call\": {\"name\": \"nmap\", \"arguments\": {\"target\": \"10.0.0.1\"}}}\n```";
        match parse_llm_response(response) {
            LlmAction::ToolCall { name, .. } => {
                assert_eq!(name, "nmap");
            }
            other => panic!("Expected ToolCall, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_openai_format() {
        let response = r#"{"tool_calls": [{"function": {"name": "httpx", "arguments": "{\"urls\": [\"example.com\"]}"}}]}"#;
        match parse_llm_response(response) {
            LlmAction::ToolCall { name, arguments, .. } => {
                assert_eq!(name, "httpx");
                assert!(arguments.get("urls").is_some());
            }
            other => panic!("Expected ToolCall, got {:?}", other),
        }
    }
}
