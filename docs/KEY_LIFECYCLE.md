# NEXA Key Lifecycle v1

## Goals

NEXA separates long-lived identity keys from rotating session material.

### Device identity key
- Generated locally.
- Stored in platform secure storage.
- Public key may be published to the service.
- Used to authenticate signed prekeys and device identity.

### Signed prekey
- Generated locally.
- Public portion is signed by the device identity key.
- Public bundle may be cached by the service.
- Private portion never leaves the device.
- Rotation is required by policy; old keys remain valid only for the protocol-defined transition window.

### One-time prekeys
The next implementation phase will add a pool of one-time X25519 prekeys. Each prekey must be single-use and atomically reserved by the service.

## Important

This document is a design boundary, not a claim of production-grade E2EE. The complete session protocol must be reviewed and independently audited before public deployment.
