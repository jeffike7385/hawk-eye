# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This repository contains two related projects:

1. **Hawk Eye** (`hawk_scanner/`) — The upstream open-source multi-source PII/secrets scanner (S3, MySQL, PostgreSQL, MongoDB, etc.)
2. **Hawk Scan** (`hawk_scan/`) — A purpose-built fork that extracts Hawk Eye's scanning core into a standalone Windows CLI tool for remotely scanning domain-joined endpoints via WinRM/SMB

Active development is on **Hawk Scan**. Hawk Eye serves as the upstream reference.

## Hawk Scan (`hawk_scan/`)

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

# Build Windows exe (must run on Windows)
cd hawk_scan && pip install pyinstaller && pyinstaller hawk_scan.spec

# Run the CLI (dev mode)
hawk_scan WORKSTATION-01 --connection connection.yml
hawk_scan WORKSTATION-01 --transport smb --redact --report-format html
```

### Architecture

Four-layer design with clean separation:

**`hawk_scan/remote/`** — Transport abstraction for remote file access
- `transport.py` — `Transport` ABC, `Credentials` dataclass, `negotiate_transport()` auto-negotiation (WinRM primary, SMB fallback)
- `winrm_transport.py` — PowerShell remoting via `pywinrm` for file enumeration (`Get-ChildItem`) and base64 retrieval
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

- Transport abstraction is the critical boundary: `orchestrator.py` calls `transport.enumerate()` and `transport.retrieve()` without knowing WinRM vs SMB
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

## Hawk Eye (`hawk_scanner/`) — Upstream Reference

### Entry Point

`hawk_scanner/main.py` — Dispatches to command modules via `importlib.import_module(f"hawk_scanner.commands.{command}")`. The `all` command iterates over all source keys in the connection file.

### Internals (`hawk_scanner/internals/system.py`)

Monolithic module with config loading, regex matching (`match_strings()`), file readers (`scan_file()`, `read_pdf()`, `read_office_document()`, `enhance_and_ocr()`), redaction (`RedactData()`), Slack/Jira notifications, and severity evaluation via JMESPath.

### Command Modules (`hawk_scanner/commands/`)

Each exports `execute(args)` → list of result dicts. Supports: s3, mysql, postgresql, mongodb, couchdb, redis, firebase, gcs, fs, gdrive, gdrive_workspace, slack, text.

### Config

- `connection.yml` — Source credentials, notification settings, severity rules
- `fingerprint.yml` — Bare regex patterns (no severity/category metadata)

### Version

`setup.py` — `VERSION = "0.3.39"`

### CI/CD

- Docker build (`.github/workflows/build.yml`): pushes to Docker Hub on main
- PyPI publish (`.github/workflows/pypi.yml`): on GitHub release
