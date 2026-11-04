# jussend 📮

You’ve got a verification link. You just need it in someone’s inbox.

jussend is a small outbound mail service written in Rust. Your app hands it a verification or password-reset link, and it queues the email, signs it with DKIM, and talks directly to the recipient’s mail server.

One binary. A SQLite queue. Runs on your own server.

## What’s in the box

- Plain-text and HTML emails for email verification and password resets.
- A persistent queue, so a restart doesn’t throw away accepted requests.
- Idempotency keys for safe submission retries.
- Bounded retries, backoff, expiry, and a status endpoint.
- DKIM signing and required STARTTLS with certificate validation.
- Fixed sender identity and action links restricted to your app’s origin.
- A loopback-only API with bearer authentication. Message bodies and action links stay out of logs.

It’s built for transactional app mail. Mailboxes, newsletters, attachments, and an admin dashboard are outside its scope.

## Get it running

You’ll need Rust 1.90+ to build from source. The manual **Build jussend** GitHub workflow also produces a Linux x64 binary and checksums. It builds without running tests.

```sh
cargo build --release --locked
cp .env.example .env
openssl rand -hex 32
```

Put the generated value in `JUSSEND_API_KEY`, then fill in the rest of `.env`. Keep that file private.

Generate an RSA key for DKIM:

```sh
umask 077
openssl genrsa -traditional -out dkim.key 2048
openssl rsa -in dkim.key -pubout -outform DER | openssl base64 -A
```

The second command prints the **public** key for your DNS record. Keep `dkim.key` to yourself. Use a PKCS#1 PEM key, starting with `BEGIN RSA PRIVATE KEY`.

```sh
./target/release/jussend
```

jussend reads `.env` in its working directory. Service managers can pass the same settings as environment variables.

## The bit code can’t do for you

Direct delivery needs a sending domain and a server allowed to connect to **outbound TCP port 25**. jussend doesn’t need an inbound SMTP port. Check the outbound restriction with your hosting provider before moving real mail over.

For a sender such as `hello@example.com` and a mail hostname such as `mail.example.com`, set up:

| Record | What to put there |
| --- | --- |
| `mail.example.com` A | Your server’s public IPv4 address |
| Reverse DNS / PTR | Ask your host to point that address back to `mail.example.com` |
| `example.com` TXT | SPF authorizing your sending IP, for example `v=spf1 ip4:YOUR_SERVER_IP -all` |
| `jussend._domainkey.example.com` TXT | `v=DKIM1; k=rsa; p=YOUR_PUBLIC_KEY` |
| `_dmarc.example.com` TXT | Start with a policy you can monitor, such as `v=DMARC1; p=none` |

**Update an existing SPF record instead of adding a second one.** Keep any other legitimate senders authorized. Your HELO hostname, forward DNS, and reverse DNS should agree. If your server uses IPv6 for delivery, configure its forward/reverse DNS and SPF authorization too, or disable outbound IPv6 at the host until it’s ready.

`JUSSEND_RETURN_PATH` must use the same domain as the sender. Point that address at a mailbox you monitor; jussend does not receive or automatically process bounces. Your mail domain’s MX records belong to whoever receives its incoming mail—don’t replace them just to use jussend.

Domain setup and IP reputation matter. A successful SMTP handoff can still end up in spam. jussend requires STARTTLS and a valid MX certificate; a destination that can’t meet that requirement will be retried, then fail or expire. MTA-STS, DANE, automatic bounce suppression, and feedback-loop processing aren’t implemented in this version.

## Send an email

`POST /v1/emails`

```sh
export JUSSEND_API_KEY='your-64-character-key'
EXPIRES_AT=$(( $(date +%s) + 3600 ))

curl http://127.0.0.1:3025/v1/emails \
  -H "Authorization: Bearer $JUSSEND_API_KEY" \
  -H 'Idempotency-Key: password-reset-request-123' \
  -H 'Content-Type: application/json' \
  -d "{
    \"to\": \"person@example.net\",
    \"kind\": \"reset_password\",
    \"url\": \"https://example.com/reset-password?token=YOUR_APP_TOKEN\",
    \"expires_at\": $EXPIRES_AT
  }"
```

The two kinds are `verify_email` and `reset_password`. `expires_at` is a Unix timestamp between 30 seconds and roughly 24 hours from submission. Set it to the actual expiry of the token your app created. Your app still owns token generation, validation, and one-time use.

The action URL must use the configured `JUSSEND_APP_URL` origin, including the scheme and port. You can’t change the sender or submit arbitrary HTML through this endpoint.

A new request returns **202**:

```json
{
  "id": "9dbb8f8e-a80c-4824-b8d6-8e99958b9f07",
  "status": "queued",
  "attempts": 0,
  "expires_at": 1900000000,
  "error": null
}
```

Reuse the **same idempotency key and identical JSON field values** when retrying an uncertain submission. A replay returns **200** with its existing receipt. Reusing a key for different content returns **409**. Generate a new key for a genuinely new email. Idempotency receipts are retained for up to 24 hours from creation.

The queue accepts up to 1,000 active emails, 60 new emails per minute, and one new email per recipient per minute. An idempotent replay doesn’t spend those limits. A full queue returns **503**; rate limits return **429** with `Retry-After: 60`. Request bodies are limited to 12 KiB.

## Did it send?

```sh
curl http://127.0.0.1:3025/v1/emails/EMAIL_ID \
  -H "Authorization: Bearer $JUSSEND_API_KEY"
```

| Status | Meaning |
| --- | --- |
| `queued` | Waiting for an attempt or retry |
| `sending` | Talking to a recipient mail server |
| `accepted` | The recipient’s SMTP server accepted the email |
| `failed` | A permanent rejection or the retry limit was reached |
| `expired` | The action link expired before delivery completed |

**`accepted` means SMTP acceptance, not confirmed inbox delivery.** There are up to eight attempts, with backoff starting at 30 seconds and capped at 30 minutes. Messages aren’t sent after their action link expires. A stable Message-ID is kept across retries.

Like other queued senders, a crash after SMTP acceptance but before the local receipt is saved can cause a duplicate. Submission deduplication doesn’t turn SMTP into exactly-once delivery.

## Leave it running

There’s a resource-limited systemd unit in [`deploy/jussend.service`](deploy/jussend.service).

```sh
sudo useradd --system --home /var/lib/jussend --shell /usr/sbin/nologin jussend
sudo install -d -m 0750 -o root -g jussend /etc/jussend
sudo install -m 0755 target/release/jussend /usr/local/bin/jussend
sudo install -m 0640 -o root -g jussend .env /etc/jussend/jussend.env
sudo install -m 0640 -o root -g jussend dkim.key /etc/jussend/dkim.key
sudo install -m 0644 deploy/jussend.service /etc/systemd/system/jussend.service
```

Set `JUSSEND_DKIM_KEY=/etc/jussend/dkim.key` in the installed environment file. The unit stores the queue in `/var/lib/jussend`, uses a private umask, and gives an in-flight send time to finish during shutdown.

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now jussend
curl http://127.0.0.1:3025/health
```

The API binds to loopback on purpose. For an app on another machine, put an HTTPS reverse proxy with request limits in front of it, keep bearer authentication enabled, and restrict access to that app’s network. Don’t publish an unencrypted API port.

Run one process per queue file. jussend locks the queue against a second process and recovers interrupted sends after restart. SQLite uses WAL and full synchronous commits, with a 64 MiB database-page cap. Treat the database, WAL, backups, and signing key as sensitive: queued emails contain live action links. Completed payloads are removed from records, but this is not a guarantee of physical erasure from disk or backups. Back up SQLite using its backup facility, or stop the service before copying the database and its sidecars together.

The included tests cover link restrictions, destination-address filtering, queue deduplication, rate limits, and payload removal. Run `cargo test --locked` when you want to run them. A build alone doesn’t prove real-world mail delivery; check DNS, SMTP handoff, and inbox placement before a production cutover.

## Using it with Riscord

See [`docs/riscord.md`](docs/riscord.md). The integration keeps account checks and one-time token handling in Riscord and uses jussend for delivery.

## License

MIT. Build something useful with it. 💌
