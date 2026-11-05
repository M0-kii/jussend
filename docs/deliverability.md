# When Gmail puts a message in spam

An `accepted` receipt means the recipient's SMTP server took the message. It does not tell us whether Gmail chose Inbox, Spam, or another category. Repeatedly resending the same verification email is not a useful placement check.

Start with the sending identity:

- The sending IP's PTR should name the HELO hostname, and that hostname must resolve back to the same IP. Check every address family the server can actually send from.
- SPF must authorize the actual sending IP for the return-path domain.
- Publish the public key matching the configured DKIM selector and private key. Use a 2048-bit RSA key; don't rotate a working key just because a message went to spam.
- The visible From domain must align with SPF or DKIM for DMARC. Gmail accepts a DMARC policy of `p=none`; changing it to `reject` does not make authenticated messages land in Inbox.
- Keep STARTTLS required. Don't rewrite signed messages or remove the plain-text alternative.

Riscord's November 5, 2026 check found matching forward/reverse DNS, IPv4 SPF, a matching 2048-bit DKIM key, and an aligned DMARC record. The VPS had no global IPv6 address or default IPv6 route. The message builder adds Date, Message-ID, MIME-Version and text/HTML alternatives before signing. No message-format defect was established, and no test email was sent.

## Get the missing evidence

Ask the affected recipient to open the message in Gmail, choose **More → Show original**, and share only the SPF, DKIM and DMARC results plus Gmail's **Why is this message in spam?** explanation. Don't collect addresses, action links, codes, complete message bodies or other private headers in an issue.

If authentication passes, investigate domain/IP reputation and recipient feedback rather than randomly changing DNS or headers. The recipient can choose **Not spam** for a legitimate requested message. That is feedback for their mailbox, not a guaranteed fix for every recipient.

For ongoing visibility, add the sending domain to [Google Postmaster Tools](https://postmaster.google.com/), verify it using Google's provided DNS TXT record, and keep that record. Add a new TXT record; preserve SPF, DKIM, DMARC and website records. Review authentication, reputation and delivery errors when Google has enough traffic to show data. Low-volume domains may not have a report yet; no report is not proof of healthy reputation.

If direct delivery remains unreliable after the evidence is collected, use a reputable authenticated delivery provider. Riscord retains its existing provider integration for a deliberate cutover; do not silently retry through a second sender after an uncertain SMTP submission.

[Gmail sender requirements](https://support.google.com/mail/answer/81126) · [Postmaster Tools setup](https://support.google.com/mail/answer/9981691)
