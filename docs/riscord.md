# Hooking it up to Riscord

Keep the account logic where it is. Riscord creates and validates the verification and reset tokens; jussend sends their links.

The Riscord backend uses these settings:

```dotenv
JUSSEND_URL=http://127.0.0.1:3025
JUSSEND_API_KEY=YOUR_RANDOM_64_CHARACTER_KEY
```

The URL should point to the service root. Use HTTPS if it is on another host. An HTTP URL is accepted only for a literal loopback address. Credentials and query strings in this URL are rejected.

On jussend’s side, use the same key, `JUSSEND_APP_URL=https://riscord.ir`, a sender on your verified sending domain, and its DKIM key. Keep the API bound to loopback when the two services share a server.

Riscord submits `verify_email` links with its existing 24-hour expiry and `reset_password` links with the existing one-hour expiry. Its user/account rate limits and non-enumerating reset response remain in place. It derives the idempotency key from the purpose and the already-hashed token, and reuses it for an uncertain submission retry.

Verification submissions also carry `code` and `code_expires_at`. Riscord generates and checks the code, stores only its account/challenge-bound MAC, limits guesses, and atomically consumes link and code together. Codes expire after ten minutes; the link keeps its 24-hour lifetime. jussend only renders the supplied code and delivers it. Old submissions without code fields remain valid.

For Riscord artwork, set `JUSSEND_MASCOT_PATH=/etc/jussend/mascot.png`. Use the PNG exported from Riscord’s shared brand source, with root ownership and group read access for jussend. The image is embedded in the email; recipients do not need to load it from the website.

When `JUSSEND_URL` is configured, Riscord uses jussend exclusively. A delivery error does not silently switch providers and risk a duplicate email. Without `JUSSEND_URL`, the existing Resend configuration remains available for rollback.

Before enabling it for users:

1. Finish sending-domain DNS and confirm outbound port 25 is available.
2. Start jussend and check its health endpoint.
3. Verify a real verification/reset delivery when account-based checks are authorized.
4. Configure Riscord and activate the backend separately from the web release. Keep active calls in mind: the current API process also owns live voice sessions.

Changing a mail environment file does not update a running Riscord API. Keep the previous environment and backend binary available for rollback. Never point Riscord at an unconfigured or unreachable jussend instance.
