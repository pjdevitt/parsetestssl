# Codex Project Context

This document is a fast handoff for future Codex sessions.

## Project Purpose

`ParseTestSSL` is a Go web app that ingests `testssl.sh` JSON and renders an actionable HTML report focused on TLS/security weaknesses.

Primary audience: operators/security engineers reviewing TLS posture across one or more hosts.

## Current Runtime Model

- Entrypoint: `main.go`
- Server: `net/http`, single route (`/`) and static assets under `/static/`
- Template: `templates/index.html`
- Styling: `static/styles.css`
- Port: `:8080` by default, overridden by `PORT`

## Input Handling

- Supports:
  - `multipart/form-data` (file upload `jsonFile`)
  - URL-encoded form post (`jsonText`)
- Hard request size cap via `http.MaxBytesReader` (`maxRequestBytes = 12MB`)
- Minimum severity selector: `LOW | MEDIUM | HIGH | CRITICAL` (default `MEDIUM`)

## Parsing + Normalization

- JSON is parsed into `any` and recursively walked (`walk`)
- Finding extraction is resilient to variant keys:
  - ID: `id | check | test | finding_id`
  - Severity: `severity | level | risk | rating`
  - Text: `finding | result | issue | description`
  - Host: `fqdn | host | ip`
- Unknown severities normalize to `UNKNOWN`

## Report Sections (Current UI)

1. Summary
- Parsed finding count and post-filter security finding count.

2. Security Findings
- De-duplicated and severity-sorted rows.

3. Recommended Ciphers
- Lists only strong cipher suites.
- Global dedupe by cipher suite (no host/port columns shown).
- Columns:
  - `Cipher`
  - `Why Recommended`
  - `TLS 1.0`, `TLS 1.1`, `TLS 1.2`, `TLS 1.3` flags
- TLS flags are merged across all hosts/ports.

4. Issue Matrix
- Rows: issues, columns: hosts/IPs, cell value is max severity seen for that host/issue.

5. Weak Ciphers
- Host/IP risk summary matrix at top of section:
  - rows = hosts
  - columns = risk types
  - checkmark indicates at least one weak cipher on host with that risk
- Detailed per-host weak cipher tables:
  - Columns include dynamic risk-type columns with checkmarks
  - Does not include ID column

6. Cipher Weakness Report
- One subsection per detected cipher risk.
- Loads markdown body from `report_templates/<slug>.md`

## Important Business Rules Added

- Category classification uses ordered rules (deterministic; no map iteration randomness).
- Cipher detection is stricter than earlier versions.
- `cipherlist_OBSOLETED` is intentionally excluded from:
  - Weak Ciphers
  - Cipher Weakness Report
- Weak-cipher risk typing currently includes:
  - No Forward Secrecy
  - CBC Mode
  - SHA-1 MAC
  - 3DES / SWEET32
  - RC4
  - Export-grade Cipher
  - NULL / Anonymous Cipher
  - Obsoleted Cipher
  - Other Cipher Weakness

## Template Naming Convention

Cipher weakness markdown files are loaded by slugified risk name:

- Example: `3DES / SWEET32` -> `report_templates/3des_sweet32.md`

Missing template behavior:
- Section still renders, with fallback text: `Template not found: <file>`

## Testing Status

- Unit tests in `main_test.go`
- Current coverage emphasis:
  - categorization determinism
  - cipher/weakness detection
  - dedupe + threshold filtering
  - nested JSON parsing
  - request oversize handling
  - risk-column annotation
  - host risk summary matrix
  - recommended cipher aggregation + protocol flags

Run tests:

```bash
go test ./...
```

## Known Gaps / Future Work

- No markdown-to-HTML rendering for report templates (currently displayed as plain preformatted text).
- No persistence/auth; single-process in-memory request handling only.
- No integration/e2e tests for full HTML output.
- Recommended-cipher policy is heuristic and may need organization-specific tuning.

