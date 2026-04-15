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
