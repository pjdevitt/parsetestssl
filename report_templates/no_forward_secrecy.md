# No Forward Secrecy

The server allows cipher suites without forward secrecy. If the long-term private key is compromised, previously captured sessions can be decrypted.

Recommended actions:
- Prefer ECDHE or DHE suites.
- Disable static RSA key exchange suites.
- Prioritize modern TLS 1.2/1.3 forward-secret suites.
