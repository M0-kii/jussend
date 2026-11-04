use crate::config::Config;
use anyhow::{Result, ensure};
use lettre::{
    Address, Message,
    message::{Attachment, MultiPart, SinglePart, header::ContentType},
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_expires_at: Option<i64>,
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

fn validate_code(submission: &Submission, now: i64) -> Result<()> {
    match (&submission.code, submission.code_expires_at) {
        (None, None) => Ok(()),
        (Some(code), Some(expires)) => {
            ensure!(
                matches!(submission.kind, Kind::VerifyEmail),
                "Codes are only supported for email verification"
            );
            ensure!(
                code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()),
                "Use a six-digit verification code"
            );
            ensure!(
                expires >= now + 30 && expires <= now + 600 && expires <= submission.expires_at,
                "Code must expire within ten minutes and before the link"
            );
            Ok(())
        }
        _ => anyhow::bail!("Provide both code and code_expires_at"),
    }
}

fn email_html(
    app_name: &str,
    action: &str,
    title: &str,
    intro: &str,
    url: &Url,
    code: Option<&str>,
    mascot: bool,
) -> String {
    let code_section = code.map(|code| format!(r#"
      <tr><td style="padding:0 32px 30px;text-align:center">
        <p style="margin:0 0 12px;color:#c8c6d2;font-size:13px">Or enter this code in My account → Email verification</p>
        <div style="padding:20px 12px;border-top:1px solid #474550;border-bottom:1px solid #474550;color:#ffffff;font-family:Consolas,monospace;font-size:34px;font-weight:700;letter-spacing:8px;line-height:1.3">{code}</div>
        <p style="margin:12px 0 0;color:#b5b2c2;font-size:12px">This code expires in 10 minutes.</p>
      </td></tr>"#, code=escape(code))).unwrap_or_default();
    let artwork = if mascot {
        format!(
            r#"<img src="cid:brand-mascot@jussend" width="144" height="118" alt="{} mascot" style="display:block;margin:0 auto 22px;border:0;max-width:100%;height:auto">"#,
            escape(app_name)
        )
    } else {
        String::new()
    };
    format!(
        include_str!("templates/account.html"),
        app = escape(app_name),
        action = escape(action),
        title = escape(title),
        intro = escape(intro),
        url = escape(url.as_str()),
        origin = escape(url.origin().ascii_serialization().as_str()),
        artwork = artwork,
        code_section = code_section
    )
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
    validate_code(&submission, now)?;
    let id = uuid::Uuid::new_v4().to_string();
    let (action, title, intro) = match submission.kind {
        Kind::VerifyEmail => (
            "Verify your email",
            "You’re almost here.",
            "Your people are waiting. Confirm your email address and get back to the good stuff.",
        ),
        Kind::ResetPassword => (
            "Reset your password",
            "Let’s get you back in.",
            "A fresh password, then back to your people. Use the button below to choose a new one.",
        ),
    };
    let mut text = format!(
        "{action} — {}\n\n{intro}\n\n{url}\n\nThis link is time-limited. If you didn’t ask for this, you can ignore this email.",
        config.app_name
    );
    if let Some(code) = &submission.code {
        text.push_str(&format!("\n\nOr enter this code in My account → Email verification: {code}\nThe code expires in 10 minutes. Using the link or code completes the same verification."));
    }
    let html = email_html(
        &config.app_name,
        action,
        title,
        intro,
        &url,
        submission.code.as_deref(),
        config.mascot.is_some(),
    );
    let parts = if let Some(mascot) = &config.mascot {
        MultiPart::alternative()
            .singlepart(SinglePart::plain(text))
            .multipart(
                MultiPart::related()
                    .singlepart(SinglePart::html(html))
                    .singlepart(
                        Attachment::new_inline("brand-mascot@jussend".into())
                            .body(mascot.clone(), ContentType::parse("image/png")?),
                    ),
            )
    } else {
        MultiPart::alternative()
            .singlepart(SinglePart::plain(text))
            .singlepart(SinglePart::html(html))
    };
    let mut message = Message::builder()
        .from(config.from.clone())
        .to(recipient.clone().into())
        .message_id(Some(format!("<{id}@{}>", config.helo)))
        .subject(format!("{action} — {}", config.app_name))
        .multipart(parts)?;
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
    #[test]
    fn codes_are_optional_but_bounded_and_paired() {
        let mut submission: Submission = serde_json::from_value(serde_json::json!({"to":"user@example.net","kind":"verify_email","url":"https://example.com/verify-email","expires_at":4600})).unwrap();
        assert!(validate_code(&submission, 1000).is_ok());
        submission.code = Some("012345".into());
        assert!(validate_code(&submission, 1000).is_err());
        submission.code_expires_at = Some(1600);
        assert!(validate_code(&submission, 1000).is_ok());
        submission.code_expires_at = Some(1601);
        assert!(validate_code(&submission, 1000).is_err());
        submission.code_expires_at = Some(1600);
        submission.kind = Kind::ResetPassword;
        assert!(validate_code(&submission, 1000).is_err());
    }
    #[test]
    fn renders_embedded_artwork_and_escapes_app_and_link() {
        let html = email_html(
            "<App>",
            "Verify",
            "Almost there",
            "Welcome",
            &Url::parse("https://example.com/verify?a=1&b=2").unwrap(),
            Some("012345"),
            true,
        );
        assert!(html.contains("cid:brand-mascot@jussend"));
        assert!(html.contains("012345"));
        assert!(html.contains("&lt;App&gt;"));
        assert!(html.contains("a=1&amp;b=2"));
        assert!(!html.contains("<App>"));
        let without = email_html(
            "App",
            "Reset",
            "Welcome",
            "Hello",
            &Url::parse("https://example.com").unwrap(),
            None,
            false,
        );
        assert!(!without.contains("cid:"));
        assert!(!without.contains("verification code"));
    }
}
