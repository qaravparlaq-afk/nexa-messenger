# NEXA Messenger — Architecture

**Status:** initial architecture baseline. Not production-ready and not security-audited.

## Security boundary

The server is not trusted with message plaintext, attachment plaintext, or wallet private keys.

```text
Device A
  -> local protocol/crypto core
  -> encrypted payload
  -> Internet / relay
  -> encrypted payload
  -> Device B
  -> local protocol/crypto core
  -> plaintext only on the endpoint
```

## Planned clients

- Android: Kotlin + Jetpack Compose
- iOS: Swift + SwiftUI
- Shared security/protocol core: Rust

## Backend

- API gateway
- identity/device directory
- prekey distribution
- message relay
- encrypted attachment storage
- push notification service
- rate limiting and abuse controls

## Wallet

Non-custodial. Private keys and transaction signing remain on the user's device. Public blockchain data is not private merely because it is used inside an E2EE messenger.

## Production rule

NEXA must not claim production-grade security until protocol review, implementation review, penetration testing, dependency review, and an independent security audit are complete.
