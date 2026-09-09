# NEXA Protocol Specification — v0 design

## Security goals
NEXA must provide confidentiality, authenticity/integrity, forward secrecy, post-compromise recovery, explicit identity-change handling and multi-device support.

## Non-negotiable rule
The server never needs message plaintext, attachment plaintext, or wallet private keys for normal operation.

## Cryptographic policy
Do not invent a new cipher, KDF, ratchet or signature scheme. Use established constructions through maintained libraries. Candidate components include modern authenticated key exchange, digital signatures, AEAD, prekeys and a Double-Ratchet-style session design. Final algorithms and parameters are subject to security review.

## Identity
Each account has a long-lived identity key. Each device has its own device key and signed device record. The UI exposes verification state and does not silently accept identity changes.

## Session lifecycle
1. Generate keys locally.
2. Publish only required public key material.
3. Authenticate the peer/device identity.
4. Establish an encrypted session.
5. Encrypt each message locally.
6. Advance ratchet/session state.
7. Reject/review unexpected key changes.
8. Revoke compromised devices.

## Message envelope
The wire envelope is versioned and carries routing identifiers plus ciphertext. Plaintext content is never a protocol requirement.

## Attachments
Files are encrypted locally with fresh content keys before upload. Recipients receive the encrypted object and the securely protected content key.

## Push
Push notifications must not contain plaintext message bodies. Push should wake the client or carry an opaque identifier.

## Calls
WebRTC is transport, not a complete security protocol. Before production, NEXA must specify media-key establishment, identity binding, downgrade protection and group-call key management.

## Wallet
Wallets are non-custodial. Seed/private-key material remains on-device. Public blockchain transactions are not private merely because the wallet is embedded in NEXA.

## Versioning
Protocol changes require a version bump, migration plan, interoperability tests, downgrade analysis and security review.
