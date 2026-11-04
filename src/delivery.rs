use crate::{
    config::Config,
    queue::{Job, Queue, now},
};
use hickory_resolver::{
    TokioResolver,
    net::{NetError, error::DnsError},
    proto::{
        op::ResponseCode,
        rr::{RData, Record},
    },
};
use lettre::{
    Address,
    address::Envelope,
    transport::smtp::{
        client::{AsyncSmtpConnection, TlsParameters},
        extension::ClientId,
    },
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::sync::watch;

pub struct Failure {
    pub code: &'static str,
    pub permanent: bool,
}
fn temporary(code: &'static str) -> Failure {
    Failure {
        code,
        permanent: false,
    }
}
fn permanent(code: &'static str) -> Failure {
    Failure {
        code,
        permanent: true,
    }
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast()
                || ip.is_documentation()
                || a == 0
                || a >= 240
                || (a == 100 && (64..=127).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 88 && c == 99))
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(mapped));
            }
            let parts = ip.segments();
            (parts[0] & 0xe000) == 0x2000
                && !(parts[0] == 0x2001 && (parts[1] < 0x200 || parts[1] == 0xdb8))
                && parts[0] != 0x2002
                && !(parts[0] == 0x3fff && parts[1] < 0x1000)
        }
    }
}

fn mx_destinations(records: &[Record]) -> Result<Vec<(u16, String)>, Failure> {
    let mut destinations = Vec::new();
    for record in records {
        if let RData::MX(mx) = &record.data {
            if mx.exchange().is_root() {
                return Err(permanent("domain_rejects_mail"));
            }
            destinations.push((
                mx.preference(),
                mx.exchange().to_utf8().trim_end_matches('.').to_owned(),
            ));
        }
    }
    Ok(destinations)
}

async fn send(config: &Config, resolver: &TokioResolver, job: &Job) -> Result<(), Failure> {
    let recipient: Address = job
        .recipient
        .parse()
        .map_err(|_| permanent("invalid_recipient"))?;
    let domain = recipient.domain();
    let mut mx = match resolver.mx_lookup(domain).await {
        Ok(records) => mx_destinations(records.answers())?,
        Err(NetError::Dns(DnsError::NoRecordsFound(records))) => match records.response_code {
            ResponseCode::NXDomain => return Err(permanent("domain_not_found")),
            ResponseCode::NoError => vec![(0, domain.to_owned())],
            _ => return Err(temporary("dns_unavailable")),
        },
        Err(_) => return Err(temporary("dns_unavailable")),
    };
    mx.sort_by_key(|(priority, _)| *priority);
    let hello = ClientId::Domain(config.helo.clone());
    let envelope = Envelope::new(Some(config.return_path.clone()), vec![recipient.clone()])
        .map_err(|_| permanent("invalid_envelope"))?;
    let mut failure = temporary("mx_unavailable");
    for (_, host) in mx.into_iter().take(8) {
        let Ok(addresses) = resolver.lookup_ip(&host).await else {
            continue;
        };
        for ip in addresses.iter().filter(|ip| public_ip(*ip)).take(16) {
            // Connect to the checked address, while validating TLS against the MX hostname.
            let Ok(mut connection) = AsyncSmtpConnection::connect_tokio1(
                SocketAddr::new(ip, 25),
                Some(Duration::from_secs(15)),
                &hello,
                None,
                None,
            )
            .await
            else {
                continue;
            };
            if !connection.can_starttls() {
                failure = temporary("tls_required");
                continue;
            }
            let tls = TlsParameters::new(host.clone()).map_err(|_| permanent("invalid_mx"))?;
            if connection.starttls(tls, &hello).await.is_err() {
                failure = temporary("tls_failed");
                continue;
            }
            match connection.send(&envelope, &job.raw).await {
                Ok(_) => {
                    let _ = tokio::time::timeout(Duration::from_secs(3), connection.quit()).await;
                    return Ok(());
                }
                Err(error) if error.is_permanent() => {
                    return Err(permanent("recipient_or_message_rejected"));
                }
                Err(_) => {
                    failure = temporary("smtp_unavailable");
                }
            }
        }
    }
    Err(failure)
}

pub async fn worker(
    config: Arc<Config>,
    queue: Queue,
    mut stop: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let resolver = TokioResolver::builder_tokio()?.build()?;
    while !*stop.borrow() {
        if let Some(job) = queue.claim().await? {
            let remaining = job.expires_at.saturating_sub(now());
            let result = if remaining <= 0 {
                Err(temporary("expired"))
            } else {
                tokio::time::timeout(
                    Duration::from_secs(remaining.min(120) as u64),
                    send(&config, &resolver, &job),
                )
                .await
                .unwrap_or_else(|_| Err(temporary("delivery_timeout")))
            };
            queue.finish(job, result).await?;
        }
        tokio::select! { _=tokio::time::sleep(Duration::from_secs(1))=>{}, _=stop.changed()=>{} }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::{
        Name,
        rdata::{CNAME, MX},
    };

    #[test]
    fn mx_answers_ignore_aliases_and_honor_null_mx() {
        let domain = Name::from_ascii("example.com.").unwrap();
        let mx = Record::from_rdata(
            domain.clone(),
            60,
            RData::MX(MX::new(10, Name::from_ascii("mail.example.com.").unwrap())),
        );
        let alias = Record::from_rdata(domain.clone(), 60, RData::CNAME(CNAME(domain.clone())));
        let destinations = mx_destinations(&[alias, mx]).unwrap_or_else(|_| panic!("valid MX"));
        assert_eq!(destinations, vec![(10, "mail.example.com".to_owned())]);
        let null = Record::from_rdata(domain, 60, RData::MX(MX::new(0, Name::root())));
        assert!(matches!(
            mx_destinations(&[null]),
            Err(Failure {
                code: "domain_rejects_mail",
                permanent: true
            })
        ));
    }

    #[test]
    fn prevents_private_and_special_destinations() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.168.1.1",
            "100.64.0.1",
            "198.19.1.1",
            "192.0.2.1",
            "240.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "2002:7f00:1::1",
        ] {
            assert!(!public_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(public_ip(address.parse().unwrap()));
        }
    }
}
