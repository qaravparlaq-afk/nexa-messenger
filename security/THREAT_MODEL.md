# NEXA Threat Model

## Assets
Message plaintext, attachment plaintext, identity/device keys, session state, wallet private keys, recovery material and required delivery metadata.

## Adversaries
- Network observer
- Malicious or compromised relay
- Compromised endpoint
- Malicious contact/spammer
- Malicious blockchain/RPC endpoint

## Controls
Authenticated encryption, ratcheting, replay protection, secure platform key storage, device revocation, rate limiting, abuse controls, explicit payment confirmation and validated network/chain state.

## Important limits
E2EE does not hide all metadata. It does not make a public blockchain private. It does not protect a fully compromised endpoint.

## Production gate
Security claims must track verified implementation and independent review. Documentation alone is not evidence of security.
