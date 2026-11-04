use anyhow::{Context, Result, ensure};
use lettre::{
    Address,
    message::{
        Mailbox,
        dkim::{DkimConfig, DkimSigningAlgorithm, DkimSigningKey},
    },
};
use sha2::{Digest, Sha256};
use std::{env, net::SocketAddr, path::PathBuf};
use url::Url;

pub struct Config {
    pub bind: SocketAddr,
    pub api_key_hash: [u8; 32],
    pub from: Mailbox,
    pub return_path: Address,
    pub app_name: String,
    pub app_url: Url,
    pub helo: String,
    pub dkim: DkimConfig,
    pub db: PathBuf,
}

fn required(name: &str) -> Result<String> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .with_context(|| format!("Set {name}"))
}

pub fn dns_name(value: &str) -> bool {
    value.len() <= 253
        && value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && value.parse::<std::net::IpAddr>().is_err()
}

impl Config {
    pub fn load() -> Result<Self> {
        let bind: SocketAddr = env::var("JUSSEND_BIND")
            .unwrap_or_else(|_| "127.0.0.1:3025".into())
            .parse()
            .context("Invalid JUSSEND_BIND")?;
        ensure!(
            bind.ip().is_loopback(),
            "Bind jussend to loopback; expose it through an authenticated HTTPS reverse proxy if needed"
        );
        let key = required("JUSSEND_API_KEY")?;
        ensure!(
            key.len() == 64 && key.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "JUSSEND_API_KEY must be 64 random hex characters"
        );
        let from: Mailbox = required("JUSSEND_FROM")?
            .parse()
            .context("Invalid JUSSEND_FROM")?;
        let return_path: Address = required("JUSSEND_RETURN_PATH")?
            .parse()
            .context("Invalid JUSSEND_RETURN_PATH")?;
        ensure!(dns_name(from.email.domain()), "Use a public sending domain");
        ensure!(
            return_path
                .domain()
                .eq_ignore_ascii_case(from.email.domain()),
            "Return path and sender must use the same domain"
        );
        let app_url =
            Url::parse(&required("JUSSEND_APP_URL")?).context("Invalid JUSSEND_APP_URL")?;
        ensure!(
            app_url.scheme() == "https"
                && app_url.host_str().is_some()
                && app_url.username().is_empty()
                && app_url.password().is_none(),
            "JUSSEND_APP_URL must be an HTTPS URL without credentials"
        );
        let app_name = required("JUSSEND_APP_NAME")?;
        ensure!(
            app_name.len() <= 80 && !app_name.chars().any(char::is_control),
            "Invalid JUSSEND_APP_NAME"
        );
        let helo = required("JUSSEND_HELO")?;
        ensure!(
            dns_name(&helo),
            "JUSSEND_HELO must be a public mail hostname"
        );
        let selector = env::var("JUSSEND_DKIM_SELECTOR").unwrap_or_else(|_| "jussend".into());
        ensure!(
            !selector.is_empty()
                && selector.len() <= 63
                && selector
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'),
            "Invalid DKIM selector"
        );
        let pem = std::fs::read_to_string(required("JUSSEND_DKIM_KEY")?)
            .context("Could not read DKIM key")?;
        let signing_key = DkimSigningKey::new(&pem, DkimSigningAlgorithm::Rsa)
            .map_err(|_| anyhow::anyhow!("Invalid RSA DKIM private key"))?;
        Ok(Self {
            bind,
            api_key_hash: Sha256::digest(key.as_bytes()).into(),
            dkim: DkimConfig::default_config(
                selector,
                from.email.domain().to_lowercase(),
                signing_key,
            ),
            from,
            return_path,
            app_name,
            app_url,
            helo,
            db: env::var_os("JUSSEND_DB")
                .map(PathBuf::from)
                .unwrap_or_else(|| "data/queue.sqlite3".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::dns_name;
    #[test]
    fn validates_helo_names() {
        assert!(dns_name("mail.example.com"));
        for bad in [
            "localhost",
            "127.0.0.1",
            "mail.example.com\r\nMAIL",
            "-mail.example.com",
        ] {
            assert!(!dns_name(bad));
        }
    }
}
