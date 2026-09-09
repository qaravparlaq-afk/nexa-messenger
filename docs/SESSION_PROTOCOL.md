# NEXA Session Protocol — staged design

This document defines the next security boundary. It is deliberately a design
document, not a claim that the current repository implements a complete
production E2EE protocol.

## Session inputs

A client selects a recipient device prekey bundle containing:

- identity signing public key
- signed prekey public key + signature
- optional one-time prekey public key

The client verifies the signed-prekey signature against the identity key before
using it.

## Session establishment

The eventual session handshake must:

1. authenticate the recipient prekey;
2. generate fresh ephemeral X25519 material;
3. derive a shared secret through a transcript-bound KDF;
4. bind identity/device identifiers and protocol version into the transcript;
5. establish independent sending/receiving chain keys;
6. support forward secrecy and post-compromise recovery through ratcheting;
7. record the selected one-time-prekey identifier for atomic server consumption.

## Message layer

Every message will carry a compact ratchet header plus authenticated
ciphertext. Associated data must bind protocol version, conversation/device
context and message identifiers without exposing plaintext.

## Replay and ordering

The implementation must explicitly handle:

- duplicate message identifiers;
- out-of-order messages;
- skipped message keys;
- stale sessions;
- concurrent device sessions.

No server-side ordering guarantee is treated as a cryptographic guarantee.

## Release gate

A complete session implementation requires protocol tests, interoperability
tests, fuzzing, abuse testing and independent cryptographic review before
public release.
