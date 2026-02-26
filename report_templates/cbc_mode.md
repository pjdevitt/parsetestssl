# CBC Mode

CBC-mode suites are present. CBC has a history of protocol and implementation attacks, especially in older TLS stacks.

Recommended actions:
- Prefer AEAD suites (AES-GCM or ChaCha20-Poly1305).
- Disable legacy CBC suites where compatibility allows.
- Remove TLS 1.0/1.1 if still enabled.
