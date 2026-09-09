# NEXA Cryptography Review Checklist

Before public beta:

- [ ] Protocol transcript is formally specified.
- [ ] Identity authentication is verified against a known threat model.
- [ ] KDF domain separation is specified.
- [ ] Session key erasure is reviewed.
- [ ] Ratchet state transitions are deterministic and tested.
- [ ] Skipped-key limits prevent unbounded memory growth.
- [ ] Replay handling is explicit.
- [ ] Multi-device trust changes are visible to users.
- [ ] Attachments use independently authenticated encryption.
- [ ] Calls use an independently reviewed media/signaling design.
- [ ] Wallet signing keys never enter backend processes.
- [ ] Fuzzing covers message parsing and state transitions.
- [ ] External security audit completed.
- [ ] Reproducible release builds are documented.

## Rule

NEXA must never market a prototype primitive as "unbreakable encryption".
Security claims must match independently reviewed implementation behavior.
