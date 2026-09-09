# NEXA Envelope

Canonical binary wire envelope for already-encrypted messages.

The envelope contains identifiers, an opaque ratchet header and ciphertext.
It deliberately contains no plaintext fields.

The current format is a transport boundary, not a privacy guarantee by itself:
the server can still observe routing metadata unless the future transport
layer adds padding, batching, relay separation and stronger metadata privacy.