# jussend

Standalone Rust application. Keep it separate from Riscord's repositories and runtime.

- Keep the service small: authenticated HTTP submission, SQLite queue, direct outbound SMTP, verification and password-reset templates.
- Preserve fixed sender identity, same-origin action links, DKIM signing, required STARTTLS, public-only pinned MX destinations, queue bounds, token expiry, idempotency, and graceful shutdown.
- Do not log addresses, action URLs, message bodies, private keys, or authorization headers. SMTP acceptance does not prove inbox delivery.
- The current user requests no tests or live account/email checks. Add focused regression coverage without running it. Do not start services or heavy builds locally. Use the build-only GitHub workflow for compilation.
- Format with `cargo fmt`. Commit Cargo.lock. Never commit .env, private signing keys, queue data, or build output.
- Keep the README casual, concrete, and honest about what has actually been verified. Never claim measured size, memory use, deliverability, or production validation without evidence.
- Publishing this repository does not authorize unrelated changes to Riscord or an unverified mail cutover. Follow the parent workspace deployment rules when integrating with Riscord.

