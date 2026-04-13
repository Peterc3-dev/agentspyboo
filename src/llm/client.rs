use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// OpenAI-compatible chat completion client.
/// Works with FastFlowLM, Ollama, vLLM, or any local server
/// that exposes the /v1/chat/completions endpoint.
pub struct LlmClient {
    base_url: String,
    model: String,
    client: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<Message>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Message {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: ResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ResponseMessage {
    content: Option<String>,
}

impl LlmClient {
    pub fn new(base_url: &str, model: &str) -> Self {
        let base_url = base_url.trim_end_matches('/').to_string();
        Self {
            base_url,
            model: model.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(120))
                .build()
                .expect("Failed to build HTTP client"),
        }
    }

    /// Send a chat completion request with system and user messages.
    pub async fn chat(&self, system: &str, user: &str) -> Result<String> {
        let url = format!("{}/chat/completions", self.base_url);

        let request = ChatRequest {
            model: self.model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: system.to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: user.to_string(),
                },
            ],
            temperature: 0.1,
            max_tokens: 2048,
        };

        tracing::debug!("POST {} (model: {})", url, self.model);

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to connect to LLM endpoint")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!(
                "LLM API returned {} — {}",
                status,
                &body[..body.len().min(500)]
            );
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .context("Failed to parse LLM response JSON")?;

        let content = chat_response
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();

        Ok(content)
    }

    /// Send a multi-turn conversation (for follow-up within a single step).
    pub async fn chat_multi(&self, messages: Vec<(String, String)>) -> Result<String> {
        let url = format!("{}/chat/completions", self.base_url);

        let msgs: Vec<Message> = messages
            .into_iter()
            .map(|(role, content)| Message { role, content })
            .collect();

        let request = ChatRequest {
            model: self.model.clone(),
            messages: msgs,
            temperature: 0.1,
            max_tokens: 2048,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .context("Failed to connect to LLM endpoint")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            bail!("LLM API returned {} — {}", status, &body[..body.len().min(500)]);
        }

        let chat_response: ChatResponse = response
            .json()
            .await
            .context("Failed to parse LLM response JSON")?;

        let content = chat_response
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();

        Ok(content)
    }
}
