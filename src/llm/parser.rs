// Parse the LLM's response into a structured AgentAction.
//
// The LLM returns natural text that may include <think>...</think> blocks,
// markdown code fences, and prose before/after a JSON object. We strip the
// think blocks, find the first balanced JSON object, and match it against
// either a tool-call schema or a done-signal schema.

use serde_json::{json, Value};

#[derive(Debug)]
pub enum AgentAction {
    Tool {
        name: String,
        args: Value,
    },
    Done {
        summary: String,
        next_steps: Vec<String>,
    },
}

pub fn strip_think(s: &str) -> String {
    let mut out = s.to_string();
    while let Some(start) = out.find("<think>") {
        if let Some(end) = out[start..].find("</think>") {
            let end_abs = start + end + "</think>".len();
            out.replace_range(start..end_abs, "");
        } else {
            out.replace_range(start.., "");
            break;
        }
    }
    out
}

fn extract_json(text: &str) -> Option<Value> {
    let cleaned = strip_think(text)
        .replace("```json", "```")
        .split("```")
        .find(|chunk| chunk.contains('{'))
        .map(|s| s.to_string())
        .unwrap_or_else(|| strip_think(text));

    let bytes = cleaned.as_bytes();
    let mut depth = 0i32;
    let mut start: Option<usize> = None;
    let mut best: Option<Value> = None;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'{' => {
                if depth == 0 {
                    start = Some(i);
                }
                depth += 1;
            }
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        let slice = &cleaned[s..=i];
                        if let Ok(v) = serde_json::from_str::<Value>(slice) {
                            best = Some(v);
                            break;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    best
}

pub fn parse_action(raw: &str) -> Option<AgentAction> {
    let v = extract_json(raw)?;

    if let Some(action) = v.get("action").and_then(|a| a.as_str()) {
        if action == "done" || action == "stop" || action == "finish" {
            let summary = v
                .get("summary")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .to_string();
            let next_steps = v
                .get("next_steps")
                .and_then(|n| n.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            return Some(AgentAction::Done {
                summary,
                next_steps,
            });
        }
    }

    if let Some(tool) = v.get("tool").and_then(|t| t.as_str()) {
        let args = v
            .get("arguments")
            .or_else(|| v.get("args"))
            .cloned()
            .unwrap_or(json!({}));
        return Some(AgentAction::Tool {
            name: tool.to_string(),
            args,
        });
    }

    if let Some(calls) = v.get("tool_calls").and_then(|t| t.as_array()) {
        if let Some(first) = calls.first() {
            let func = first.get("function").unwrap_or(first);
            let name = func
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            let args_raw = func.get("arguments").cloned().unwrap_or(json!({}));
            let args = match args_raw {
                Value::String(s) => serde_json::from_str::<Value>(&s).unwrap_or(json!({})),
                v => v,
            };
            if !name.is_empty() {
                return Some(AgentAction::Tool { name, args });
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_think_removes_balanced_blocks() {
        let s = "before<think>reasoning here</think>after";
        assert_eq!(strip_think(s), "beforeafter");
    }

    #[test]
    fn strip_think_handles_multiple_blocks() {
        let s = "<think>a</think>keep1<think>b</think>keep2";
        assert_eq!(strip_think(s), "keep1keep2");
    }

    #[test]
    fn strip_think_truncates_unclosed_block() {
        let s = "keep<think>never closed";
        assert_eq!(strip_think(s), "keep");
    }

    #[test]
    fn parse_tool_call_simple_schema() {
        let raw = r#"{"tool":"subfinder","arguments":{"domain":"example.com"}}"#;
        match parse_action(raw) {
            Some(AgentAction::Tool { name, args }) => {
                assert_eq!(name, "subfinder");
                assert_eq!(args["domain"], "example.com");
            }
            other => panic!("expected Tool, got {other:?}"),
        }
    }

    #[test]
    fn parse_tool_call_accepts_args_alias() {
        let raw = r#"{"tool":"httpx","args":{"cap":10}}"#;
        match parse_action(raw) {
            Some(AgentAction::Tool { name, args }) => {
                assert_eq!(name, "httpx");
                assert_eq!(args["cap"], 10);
            }
            other => panic!("expected Tool, got {other:?}"),
        }
    }

    #[test]
    fn parse_tool_call_strips_think_and_code_fence() {
        let raw = "<think>I should run subfinder first.</think>\nHere is my action:\n```json\n{\"tool\":\"subfinder\",\"arguments\":{\"domain\":\"example.com\"}}\n```\n";
        match parse_action(raw) {
            Some(AgentAction::Tool { name, .. }) => assert_eq!(name, "subfinder"),
            other => panic!("expected Tool, got {other:?}"),
        }
    }

    #[test]
    fn parse_openai_tool_calls_with_stringified_args() {
        let raw = r#"{"tool_calls":[{"function":{"name":"nuclei","arguments":"{\"urls\":[\"https://example.com\"]}"}}]}"#;
        match parse_action(raw) {
            Some(AgentAction::Tool { name, args }) => {
                assert_eq!(name, "nuclei");
                assert_eq!(args["urls"][0], "https://example.com");
            }
            other => panic!("expected Tool, got {other:?}"),
        }
    }

    #[test]
    fn parse_done_action_with_next_steps() {
        let raw = r#"{"action":"done","summary":"All done.","next_steps":["rescan","report"]}"#;
        match parse_action(raw) {
            Some(AgentAction::Done {
                summary,
                next_steps,
            }) => {
                assert_eq!(summary, "All done.");
                assert_eq!(next_steps, vec!["rescan", "report"]);
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn parse_done_accepts_stop_and_finish_aliases() {
        for action in ["stop", "finish"] {
            let raw = format!(r#"{{"action":"{action}","summary":"x"}}"#);
            assert!(matches!(parse_action(&raw), Some(AgentAction::Done { .. })));
        }
    }

    #[test]
    fn parse_returns_none_for_unparseable() {
        assert!(parse_action("no json here at all").is_none());
        assert!(parse_action("").is_none());
        // valid JSON but no recognized schema
        assert!(parse_action(r#"{"foo":"bar"}"#).is_none());
    }

    #[test]
    fn extract_json_picks_first_balanced_object_amid_prose() {
        let raw = "Sure! {\"tool\":\"subfinder\",\"arguments\":{}} -- let me know.";
        match parse_action(raw) {
            Some(AgentAction::Tool { name, .. }) => assert_eq!(name, "subfinder"),
            other => panic!("expected Tool, got {other:?}"),
        }
    }
}
