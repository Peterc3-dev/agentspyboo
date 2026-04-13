use anyhow::{Context, Result};
use colored::Colorize;

use crate::agent::planner;
use crate::agent::state::{AgentState, Phase};
use crate::config::Config;
use crate::findings::db::FindingsDb;
use crate::findings::models::Finding;
use crate::llm::client::LlmClient;
use crate::llm::parser::{self, LlmAction};
use crate::llm::prompt;
use crate::tools::registry::ToolRegistry;

/// The core ReAct (Observe -> Think -> Act -> Repeat) loop.
pub struct ReactLoop {
    config: Config,
    llm: LlmClient,
    tools: ToolRegistry,
    db: FindingsDb,
    state: AgentState,
}

impl ReactLoop {
    pub fn new(config: Config, llm: LlmClient, tools: ToolRegistry, db: FindingsDb) -> Self {
        let state = AgentState::new(&config.target);
        Self {
            config,
            llm,
            tools,
            db,
            state,
        }
    }

    /// Run the full ReAct loop until completion or max steps.
    pub async fn run(&mut self) -> Result<Vec<Finding>> {
        for step in 0..self.config.max_steps {
            self.state.step = step;

            println!(
                "\n{} Step {}/{} | Phase: {} | Findings: {}",
                "[>]".bright_magenta(),
                step + 1,
                self.config.max_steps,
                self.state.phase.colored_label(),
                self.db.count()?.to_string().bright_white(),
            );

            // 1. Build the prompt with current context
            let system = prompt::system_prompt();
            let tool_schemas = self.tools.schemas_json();
            let context = self.state.context_summary();
            let hint = planner::planning_hint(&self.state);

            let user_message = format!(
                "{}\n\nPlanning hint: {}\n\nAvailable tools:\n{}\n\nWhat is your next action? \
                 Respond with a tool call or say DONE if the engagement is complete.",
                context, hint, tool_schemas
            );

            // 2. Query the LLM
            tracing::debug!("Sending prompt to LLM...");
            let response = self
                .llm
                .chat(&system, &user_message)
                .await
                .context("LLM request failed")?;

            tracing::debug!("LLM response: {}", &response);

            // 3. Parse LLM response into an action
            let action = parser::parse_llm_response(&response);

            match action {
                LlmAction::ToolCall {
                    name,
                    arguments,
                    thought,
                } => {
                    if let Some(thought) = &thought {
                        println!(
                            "  {} {}",
                            "Think:".bright_yellow(),
                            thought.bright_white()
                        );
                    }

                    println!(
                        "  {} {} with {}",
                        "Act:".bright_cyan(),
                        name.bright_green(),
                        serde_json::to_string(&arguments)
                            .unwrap_or_default()
                            .dimmed()
                    );

                    // 4. Execute the tool
                    match self.tools.execute(&name, arguments.clone()).await {
                        Ok(output) => {
                            let output_str = output.to_display_string();
                            let preview = if output_str.len() > 200 {
                                format!("{}...", &output_str[..200])
                            } else {
                                output_str.clone()
                            };
                            println!(
                                "  {} {}",
                                "Observe:".bright_blue(),
                                preview.dimmed()
                            );

                            // Record observation
                            self.state.add_observation(
                                &name,
                                &serde_json::to_string(&arguments).unwrap_or_default(),
                                &output_str,
                            );

                            // Extract and store any findings from the output
                            if let Some(findings) = output.findings {
                                for finding in findings {
                                    println!(
                                        "  {} [{}] {}",
                                        "Finding:".bright_red().bold(),
                                        finding.severity.colored_label(),
                                        finding.title.bright_white()
                                    );
                                    self.db.insert(&finding)?;
                                }
                            }

                            // Extract discovered assets
                            for asset in &output.discovered_assets {
                                self.state.add_asset(asset.clone());
                            }
                        }
                        Err(e) => {
                            let err_msg = format!("Tool error: {}", e);
                            println!(
                                "  {} {}",
                                "Error:".bright_red(),
                                err_msg.bright_red()
                            );
                            self.state.add_observation(&name, "", &err_msg);
                        }
                    }

                    // 5. Check if planner suggests phase transition
                    if let Some(next_phase) = planner::should_transition(&self.state) {
                        println!(
                            "  {} Transitioning to {}",
                            "[~]".bright_yellow(),
                            next_phase.colored_label()
                        );
                        self.state.set_phase(next_phase);
                    }
                }

                LlmAction::PhaseTransition { phase, reason } => {
                    println!(
                        "  {} LLM requests phase change to {}: {}",
                        "[~]".bright_yellow(),
                        phase.colored_label(),
                        reason.bright_white()
                    );
                    self.state.set_phase(phase);
                }

                LlmAction::Done { summary } => {
                    println!(
                        "\n{} {}",
                        "[+]".bright_green().bold(),
                        "Agent reports engagement complete.".bright_green()
                    );
                    println!("  {}", summary.bright_white());
                    break;
                }

                LlmAction::Think { thought } => {
                    println!(
                        "  {} {}",
                        "Think:".bright_yellow(),
                        thought.bright_white()
                    );
                    // No action taken, loop continues
                }

                LlmAction::Error { message } => {
                    tracing::warn!("Failed to parse LLM response: {}", message);
                    println!(
                        "  {} Could not parse LLM response, retrying...",
                        "[!]".bright_red()
                    );
                    self.state.add_observation(
                        "llm_parse_error",
                        "",
                        &format!("Parse error: {}", message),
                    );
                }
            }
        }

        // Return all findings
        self.db.all()
    }
}
