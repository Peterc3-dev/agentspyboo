use std::collections::HashMap;
use std::time::Duration;

use anyhow::{bail, Result};
use serde_json::Value;

use super::{Tool, ToolOutput};

/// Registry of available tools, indexed by name.
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Create a registry with all default tools registered.
    pub fn new_with_defaults(timeout: Duration) -> Self {
        let mut registry = Self::new();

        registry.register(Box::new(super::subfinder::Subfinder::new(timeout)));
        registry.register(Box::new(super::httpx::Httpx::new(timeout)));
        registry.register(Box::new(super::nuclei::Nuclei::new(timeout)));
        registry.register(Box::new(super::naabu::Naabu::new(timeout)));
        registry.register(Box::new(super::ffuf::Ffuf::new(timeout)));
        registry.register(Box::new(super::gau::Gau::new(timeout)));
        registry.register(Box::new(super::findomain::Findomain::new(timeout)));
        registry.register(Box::new(super::nmap::Nmap::new(timeout)));

        registry
    }

    pub fn register(&mut self, tool: Box<dyn Tool>) {
        let name = tool.name().to_string();
        self.tools.insert(name, tool);
    }

    pub fn tool_count(&self) -> usize {
        self.tools.len()
    }

    pub fn tool_names(&self) -> Vec<String> {
        let mut names: Vec<_> = self.tools.keys().cloned().collect();
        names.sort();
        names
    }

    /// Get all tool schemas as a JSON string for the LLM prompt.
    pub fn schemas_json(&self) -> String {
        let schemas: Vec<Value> = self
            .tools
            .values()
            .map(|t| {
                serde_json::json!({
                    "name": t.name(),
                    "description": t.description(),
                    "parameters": t.schema(),
                })
            })
            .collect();

        serde_json::to_string_pretty(&schemas).unwrap_or_else(|_| "[]".to_string())
    }

    /// Execute a tool by name with the given arguments.
    pub async fn execute(&self, name: &str, params: Value) -> Result<ToolOutput> {
        let tool = self
            .tools
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("Unknown tool: {}", name))?;

        tracing::info!("Executing tool: {}", name);
        let result = tool.execute(params).await;

        match &result {
            Ok(output) => {
                tracing::debug!(
                    "Tool {} completed (exit_code={}, stdout_len={}, assets={})",
                    name,
                    output.exit_code,
                    output.stdout.len(),
                    output.discovered_assets.len()
                );
            }
            Err(e) => {
                tracing::warn!("Tool {} failed: {}", name, e);
            }
        }

        result
    }
}
