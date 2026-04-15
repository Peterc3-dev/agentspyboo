// OpenAI-compatible chat client. Talks to Lemonade Server or any other
// OpenAI-shaped endpoint.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    temperature: f32,
    max_tokens: u32,
    stream: bool,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<Choice>,
}

#[derive(Debug, Deserialize)]
struct Choice {
    message: RespMsg,
}

#[derive(Debug, Deserialize)]
struct RespMsg {
    content: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    reasoning_content: Option<String>,
}

pub struct LlmClient {
    base: String,
    model: String,
    key: String,
    http: reqwest::Client,
}

impl LlmClient {
    pub fn new(base: &str, model: &str, key: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            model: model.to_string(),
            key: key.to_string(),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(300))
                .build()
                .expect("reqwest client"),
        }
    }

    pub async fn chat(&self, messages: &[ChatMessage]) -> Result<String> {
        let url = format!("{}/chat/completions", self.base);
        let req = ChatRequest {
            model: &self.model,
            messages,
            temperature: 0.1,
            max_tokens: 1024,
            stream: false,
        };
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&self.key)
            .json(&req)
            .send()
            .await
            .context("LLM request failed to send")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            bail!("LLM {} — {}", status, &body[..body.len().min(600)]);
        }
        let parsed: ChatResponse = resp.json().await.context("bad JSON from LLM")?;
        let content = parsed
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .ok_or_else(|| anyhow!("LLM returned no content"))?;
        Ok(content)
    }
}
