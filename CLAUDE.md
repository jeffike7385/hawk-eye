# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

Hawk Scan is a standalone Windows CLI tool for scanning domain-joined endpoints for PII, secrets, and classified data via WinRM/SMB or local filesystem access. Built for enterprise admins who need to check devices before international travel — no software installed on the target endpoint.

### Build & Run Commands

```bash
# Install in dev mode
cd hawk_scan && pip install -e ".[dev]"

# Run tests
cd hawk_scan && pytest tests/ -v

# Run a single test file
cd hawk_scan && pytest tests/test_engine.py -v

# Run a specific test
cd hawk_scan && pytest tests/test_engine.py::test_engine_finds_ssn -v

# Build + sign Windows exe (must run on Windows)
cd hawk_scan && .\build.ps1                    # full build + sign
cd hawk_scan && .\build.ps1 -SkipSign          # build only

# Run the CLI (dev mode)
hawk_scan WORKSTATION-01 --connection connection.yml
hawk_scan WORKSTATION-01 --transport smb --redact --report-format html

# Local scan (no network transport)
hawk_scan --local
hawk_scan localhost
```

### Architecture

Four-layer design with clean separation:

**`hawk_scan/remote/`** — Transport abstraction for file access
- `transport.py` — `Transport` ABC with `copies_files` property, `Credentials` dataclass, `negotiate_transport()` auto-negotiation (local for localhost, SMB primary for remote, WinRM fallback)
- `local_transport.py` — Direct local filesystem access via `os.scandir()` — no network, no temp copies, no credential prompts
- `winrm_transport.py` — PowerShell remoting via `pypsrp` (PSRP/SPNEGO) for file enumeration (`Get-ChildItem`) and base64 retrieval
- `smb_transport.py` — Admin share access (`\\host\C$`) via `smbprotocol` for enumeration and file copy

**`hawk_scan/scanner/`** — Content analysis (no knowledge of where files come from)
- `engine.py` — `ScanEngine` compiles YAML fingerprint regexes at init, runs them against text content, supports redaction and context-keyword confidence scoring
- `readers.py` — File content extractors dispatched by extension: plain text, PDF (PyPDF2), Word (python-docx), Excel (openpyxl), PowerPoint (python-pptx), images (pytesseract OCR with OpenCV enhancement)
- `orchestrator.py` — `ScanOrchestrator` coordinates: enumerate via transport → check size limits → retrieve to temp → read content → scan → collect `Finding`/`SkippedFile` results → cleanup temp files

**`hawk_scan/report/`** — Output generation
- `generator.py` — `generate_html_report()` and `generate_json_report()` producing self-contained report files
- `template.html` — Jinja2 template with inlined CSS, severity-sorted findings table, skip list

**`hawk_scan/cli.py`** — Entry point tying all layers together with argparse, `rich` progress bar, and secure credential handling

### Key Design Decisions

- Transport abstraction is the critical boundary: `orchestrator.py` calls `transport.enumerate()` and `transport.retrieve()` without knowing WinRM vs SMB vs local
- `Transport.copies_files` property controls whether orchestrator deletes files after scanning (True for SMB/WinRM temp copies, False for local where files are read in place)
- Fingerprint patterns are YAML dicts with `pattern`, `severity`, `category`, and optional `context_keywords` — not bare regex strings like Hawk Eye
- Patterns compile once at `ScanEngine.__init__()`, not per-file like Hawk Eye
- All temp files are cleaned up in `finally` blocks

### Configuration

- **`fingerprints/default.yml`** — Ships with the tool: US PII (SSN, passport, ITIN, credit card, etc.) + Azure/M365/Power Platform/Dynamics secrets
- **`config.yml.sample`** — Reference config for default scan paths, exclude patterns, report settings
- Custom fingerprints loaded via `--custom-fingerprints` flag, merged with defaults at runtime

### Version

`hawk_scan/__init__.py` — `__version__ = "0.1.0"`

### Design Spec & Plan

- Design spec: `docs/superpowers/specs/2026-04-29-hawk-scan-remote-endpoint-scanner-design.md`
- Implementation plan: `docs/superpowers/plans/2026-04-29-hawk-scan.md`

---

## Lineage

This project was forked from [rohitcoder/hawk-eye](https://github.com/rohitcoder/hawk-eye), a multi-source PII/secrets scanner. The original `hawk_scanner/` code has been removed. Hawk Scan extracts and improves the scanning core (regex engine, file readers, OCR pipeline) while replacing everything else with purpose-built remote endpoint scanning infrastructure.
