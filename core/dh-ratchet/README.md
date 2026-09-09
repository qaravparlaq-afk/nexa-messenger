# NEXA DH Ratchet

Staged asymmetric ratchet primitive for rotating the root key with fresh
X25519 public material.

This is not yet the complete production Double Ratchet. The surrounding
protocol must authenticate the ratchet header and bind it to the session
transcript before this state transition is exposed on the network.