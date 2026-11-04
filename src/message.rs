use crate::config::Config;
use anyhow::{Result, ensure};
use lettre::{
    Address, Message,
    message::{MultiPart, SinglePart},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    VerifyEmail,
    ResetPassword,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Submission {
    pub to: String,
    pub kind: Kind,
    pub url: String,
    pub expires_at: i64,
}

pub struct Prepared {
    pub id: String,
    pub key: String,
    pub hash: Vec<u8>,
    pub recipient_hash: Vec<u8>,
    pub recipient: String,
    pub raw: Vec<u8>,
    pub expires_at: i64,
}

pub fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub fn action_url(value: &str, origin: &Url) -> Result<Url> {
    ensure!(value.len() <= 2048, "Action URL is too long");
    let url = Url::parse(value)?;
    ensure!(
        url.origin() == origin.origin()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "Use an action URL on the configured app origin"
    );
    Ok(url)
}

pub fn prepare(config: &Config, submission: Submission, key: String, now: i64) -> Result<Prepared> {
    ensure!(
        submission.to.len() <= 254 && !submission.to.chars().any(char::is_control),
        "Invalid recipient"
    );
    let recipient: Address = submission.to.parse()?;
    ensure!(
        crate::config::dns_name(recipient.domain()),
        "Recipient must use a public mail domain"
    );
    let url = action_url(&submission.url, &config.app_url)?;
    ensure!(
        submission.expires_at >= now + 30 && submission.expires_at <= now + 86460,
        "expires_at must be between 30 seconds and 24 hours from now"
    );
    let id = uuid::Uuid::new_v4().to_string();
    let (action, intro) = match submission.kind {
        Kind::VerifyEmail => (
            "Verify your email",
            "One quick check and you’re in. Use the link below to verify your email address.",
        ),
        Kind::ResetPassword => (
            "Reset your password",
            "Want to set a new password? Use the link below to get started.",
        ),
    };
    let text = format!(
        "{action} — {}\n\n{intro}\n\n{url}\n\nThis link is time-limited. If you didn’t ask for this, you can ignore this email.",
        config.app_name
    );
    let html = format!(
        "<!doctype html><html lang=\"en\"><body style=\"margin:0;padding:32px 20px;background:#f5f5f7;color:#202127;font-family:Arial,sans-serif\"><main style=\"max-width:480px;margin:auto;background:white;border:1px solid #e1e1e6;border-radius:16px;padding:28px\"><p style=\"color:#666;font-size:14px\">{}</p><h1 style=\"font-size:25px\">{action}</h1><p style=\"line-height:1.6\">{intro}</p><p style=\"margin:28px 0\"><a href=\"{}\" style=\"display:inline-block;background:#25262c;color:white;text-decoration:none;border-radius:10px;padding:14px 20px\">{action}</a></p><p style=\"font-size:13px;color:#666;line-height:1.6\">This link is time-limited. If you didn’t ask for this, you can ignore this email.</p><p style=\"font-size:12px;word-break:break-all\">Button not opening? Copy this link:<br><a href=\"{}\">{}</a></p></main></body></html>",
        escape(&config.app_name),
        escape(url.as_str()),
        escape(url.as_str()),
        escape(url.as_str())
    );
    let mut message = Message::builder()
        .from(config.from.clone())
        .to(recipient.clone().into())
        .message_id(Some(format!("<{id}@{}>", config.helo)))
        .subject(format!("{action} — {}", config.app_name))
        .multipart(
            MultiPart::alternative()
                .singlepart(SinglePart::plain(text))
                .singlepart(SinglePart::html(html)),
        )?;
    message.sign(&config.dkim);
    Ok(Prepared {
        id,
        key,
        hash: Sha256::digest(serde_json::to_vec(&submission)?).to_vec(),
        recipient_hash: Sha256::digest(recipient.to_string().to_lowercase().as_bytes()).to_vec(),
        recipient: recipient.to_string(),
        raw: message.formatted(),
        expires_at: submission.expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confines_links_to_the_app() {
        let origin = Url::parse("https://example.com").unwrap();
        assert!(action_url("https://example.com/reset-password?token=abc", &origin).is_ok());
        for url in [
            "https://evil.test/reset",
            "https://example.com.evil.test/",
            "http://example.com/",
            "https://u:p@example.com/",
            "https://example.com:444/",
            "javascript:alert(1)",
        ] {
            assert!(action_url(url, &origin).is_err());
        }
    }
    #[test]
    fn escapes_html_including_link_queries() {
        assert_eq!(escape("<a\"&'"), "&lt;a&quot;&amp;&#39;");
    }
}
