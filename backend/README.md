# NEXA Backend

The current gateway is a development-only relay prototype.

Endpoints:
- GET /health
- POST /v1/relay — accepts an encrypted protocol envelope
- GET /v1/relay/{device_id} — drains queued ciphertext for a device

The relay stores bounded ciphertext in memory and does not decrypt message content.

## Not production-ready

The prototype intentionally has no authentication, durable storage, abuse prevention, rate limits, TLS termination, multi-region operation or persistence. Do not expose it to the public Internet.

Production must add authenticated device sessions, replay/idempotency controls, rate limiting, encrypted durable storage, privacy-minimized observability, TLS/certificate management and independent security review.
