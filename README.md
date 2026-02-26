# ParseTestSSL

A Golang web app that parses `testssl.sh` JSON output and renders an HTML report focused on security-related issues.

## Features

- Accepts uploaded JSON file or pasted JSON text
- Enforces a 12MB request size cap for uploads/body content
- Extracts findings from flat or nested JSON structures
- Filters by minimum severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`)
- Removes duplicates and sorts highest-severity first
- Categorizes findings (protocol weakness, cipher weakness, known vulnerabilities, certificate risk, hardening)
- Includes a `Recommended Ciphers` summary with TLS version presence flags
- Includes weak-cipher host/risk matrices with per-risk checkmark columns
- Appends a cipher weakness report section with text loaded from `report_templates/*.md`

## Generate Input from testssl.sh

```bash
testssl.sh --jsonfile out.json <host-or-url>
```

Then upload `out.json` in the web UI.

## Run

```bash
go run .
```

Open:

`http://localhost:8080`

## Docker

Build the image:

```bash
docker build -t parsetestssl:latest .
```

Run the container:

```bash
docker run --rm -p 8080:8080 parsetestssl:latest
```

Open:

`http://localhost:8080`

## Notes

- This tool intentionally focuses on actionable security findings and excludes informational/OK checks.
- Parser is resilient to different key naming styles (`id`, `check`, `finding`, `result`, `severity`, etc.).
- Cipher weakness report templates are loaded by slugged weakness name (for example `3DES / SWEET32` -> `report_templates/3des_sweet32.md`).
- `cipherlist_OBSOLETED` is intentionally excluded from weak-cipher tables/report.

## Project Context for Codex

For a focused technical handoff (architecture, current behavior, key rules, and known gaps), see:

- `docs/CODEX_CONTEXT.md`
