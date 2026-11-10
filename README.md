# Reboot Syndicate — Lead Rescue

A runnable missed-call lead capture and review-request **MVP**. Includes a responsive multi-tenant dashboard, lead pipeline, conversation history, consent recording, Twilio inbound voice/SMS webhooks with signature validation, STOP/START handling, simulated SMS, and manual review-request sending. **Not a complete billing / AI receptionist platform**: subscriptions, AI triage, automatic reminders, multi-location user management, recording retrieval, and message status callbacks are future work.

## Local run with Docker

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))' # put output in APP_SECRET
# Set ADMIN_EMAIL and a unique ADMIN_PASSWORD with at least 12 characters
# Keep SMS_MODE=demo.
docker compose up -d --build
docker compose logs -f web
```

Open the UI via an SSH tunnel (recommended while demoing):

```bash
ssh -L 8135:127.0.0.1:8135 ray@yeet
```

Then visit `http://localhost:8135` and sign in with the ADMIN credentials in `.env`.

For a local Python run (without Docker), set environment variables from `.env` manually; start `uvicorn app.main:app --reload --port 8135`. The default database is `data/lead_rescue.sqlite3`.

**Do not commit `.env` or a populated database.** Change admin credentials through a secured maintenance process; changing `ADMIN_PASSWORD` in `.env` does **not** rotate an existing account password. This app is one account per business in the initial version; additional tenant accounts require provisioning and operational controls.

## Demo workflow

1. In Settings, fill in the business name and a real Google review URL (`https://...`).
2. On Overview, simulate a missed call from `+13215550123`.
3. Open the contact and mark consent as obtained, recording how/when and by whom.
4. In Settings, enable automatic missed-call response.
5. Simulate the call again, and inspect the conversation. Outbound messages are logged as **demo-only**, never sent.
6. Test manual reply, simulated inbound STOP, and review request. Outbound buttons disable for opted-out contacts.

## Real Twilio mode — deployment checklist

Live mode is intentionally fail-closed. Before turning it on:

- Choose a properly registered, SMS-capable Twilio local number and confirm A2P 10DLC approval, appropriate use cases, applicable messaging rules, and whether consent is sufficient for your planned texts. A missed call does not by itself prove consent to marketing texts.
- Deploy behind a stable **public HTTPS endpoint** with correct proxy configuration. Home-hosted services may lose access during ISP outages; a cloud VPS is recommended for production.
- Set `SMS_MODE=live`, `PUBLIC_BASE_URL=https://your-real-domain.example`, a strong `APP_SECRET`, `COOKIE_SECURE=true`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, and `TWILIO_PHONE_NUMBER=+1...` in `.env`. Set business Twilio number in Settings to the same number.
- In Twilio's number settings, set **Voice - A call comes in** to `https://your-real-domain.example/webhooks/twilio/voice` (HTTP POST), and **Messaging - A message comes in** to `https://your-real-domain.example/webhooks/twilio/sms` (HTTP POST). Signature validation uses the exact public URL; misconfigured host, path, forwarded TLS, or query string causes legitimate requests to be rejected.
- The voice endpoint records a voicemail *at Twilio*, but this MVP does not access/store recordings or expose a voicemail inbox. Decide on local call recording consent and retention before allowing recordings for customers. If not appropriate, remove `response.record(...)` from the source.
- Verify that conditional call forwarding on the **actual carrier and account** forwards unanswered calls and preserves the **original caller's number**. Don't rely on any universal star-code. In the current MVP, the Twilio voice webhook logs forwarded calls; it does **not** independently detect whether a call was missed versus deliberately forwarded.
- Test delivery behavior, STOP handling and Twilio's provider-level opt-out behavior on real devices. START clears local opt-out but does not automatically grant promotional consent.
- Review the site's privacy notice, data processing agreements, messaging consent, automated call/text laws, records retention, incident response, customer support, rate limits and abuse controls. Require a separate review before making the service generally available.
- Back up the DB, use Postgres for production, and configure firewall, rate limiting at reverse proxy, WAF, alerting, regular upgrades and secure secrets handling. Limit admin permissions and provide a secure password reset/rotation flow. Don't expose port 8135 publicly.

**Note:** This MVP has no background queue, retries, automatic delayed follow-ups, AI qualification, account self-signup, or Stripe billing. Logs are not delivery receipts. A successful provider API call is just `submitted`, not proven delivered.

## Tests

```bash
pip install -r requirements.txt
pytest -q
```

## Routes

- `GET /health`: basic health
- `GET /`: authenticated lead dashboard
- `GET /settings`: business configuration
- `GET /leads/{id}`: contact, SMS log, consent, review-request action
- `POST /webhooks/twilio/voice`: verified inbound voice webhook
- `POST /webhooks/twilio/sms`: verified inbound SMS webhook

## Security boundaries

Tenant scoping is enforced on dashboard queries, individual lead lookups and messages. Forms require a session-bound CSRF token. Authentication uses salted PBKDF2 hashes and signed, HttpOnly session cookies; set HTTPS-only cookies in production. Webhooks refuse demo-mode external requests and require Twilio signatures in live mode. Provider SID deduplication is included for inbound events. This is an MVP and needs penetration testing and a security review before handling real clients.
