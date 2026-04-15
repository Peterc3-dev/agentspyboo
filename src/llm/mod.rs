// LLM integration: OpenAI-compatible chat client, response parser, prompts.

pub mod client;
pub mod parser;
pub mod prompt;

pub use client::{ChatMessage, LlmClient};
pub use parser::{parse_action, strip_think, AgentAction};
pub use prompt::system_prompt;
