# 3DES / SWEET32

3DES is vulnerable to SWEET32-style risks due to its 64-bit block size.

Recommended actions:
- Disable 3DES suites.
- Prefer AES-GCM or ChaCha20-Poly1305.
- Confirm scanners no longer report 3DES acceptance.
