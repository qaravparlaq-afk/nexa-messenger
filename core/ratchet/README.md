# NEXA Ratchet

This crate adds the first message-key/chain-key building block.

Properties:
- domain-separated HKDF-SHA256 derivation;
- fresh per-message key;
- monotonically advancing send counter;
- ChaCha20-Poly1305 authenticated encryption;
- AAD authentication;
- tamper detection;
- zeroized chain state.

The complete production protocol still needs a peer receive state, skipped-key
handling, replay/idempotency policy, header encryption, ratchet DH steps,
session persistence and multi-device synchronization.