# NEXA Core Session

This crate contains the first staged session-establishment primitive.

## Current boundary

- Validates protocol version.
- Validates the recipient identity key and signed prekey binding.
- Uses fresh X25519 initiator ephemeral material.
- Supports optional one-time prekey contribution.
- Derives a 32-byte session root with HKDF-SHA256 and explicit NEXA domain separation.
- Zeroizes intermediate DH material and the resulting session root container.

## Not yet production E2EE

This is **not** the final messaging protocol. It does not yet implement the
full Double Ratchet, authenticated transcript binding for every handshake
field, skipped-message-key handling, replay protection, session persistence,
multi-device trust state, or production key storage.

Those pieces must be implemented and reviewed before this primitive is exposed
as a public security feature.
