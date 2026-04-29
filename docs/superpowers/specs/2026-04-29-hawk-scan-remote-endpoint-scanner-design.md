# Hawk Scan: Remote Endpoint PII Scanner

**Date:** 2026-04-29
**Status:** Implemented
**Approach:** New project extracting hawk-eye's scanning core (Approach 2)

## Overview

Hawk Scan is a standalone Windows CLI tool for enterprise administrators to remotely scan domain-joined Windows endpoints for PII and classified documents before devices are taken abroad by staff. It runs from an administrative workstation over SMB or WinRM, requires no software installation on the target device, and produces a self-contained interactive HTML report with remediation prioritization.

### Key Constraints

- Single target machine per scan (no batch orchestration)
- No dependencies installed on the target endpoint
- No dependencies required on the admin workstation (standalone .exe via PyInstaller)
- Domain-joined Windows environment
- Report output only (no ticketing, SIEM, or notification integrations)
- PII and document classification focus — no secrets/credentials scanning

## 1. Project Structure

```
hawk_scan/
├── pyproject.toml
├── hawk_scan/
│   ├── __init__.py             # __version__ = "0.1.0"
│   ├── cli.py                  # argparse CLI, main() entry point, progress display
│   ├── config.py               # YAML config + fingerprint loading/merging
│   ├── models.py               # Dataclasses: FileMetadata, Finding, SkippedFile, ScanResult, ScanReport
│   ├── remote/
│   │   ├── transport.py        # Transport ABC, Credentials, negotiate_transport()
│   │   ├── winrm_transport.py  # WinRM via pywinrm (PowerShell remoting)
│   │   └── smb_transport.py    # SMB via smbprotocol (admin shares)
│   ├── scanner/
│   │   ├── engine.py           # ScanEngine: regex matching, thresholds, co-occurrence, redaction
│   │   ├── readers.py          # File content extractors by extension
│   │   └── orchestrator.py     # Coordinates enumerate → retrieve → scan → collect
│   └── report/
│       ├── generator.py        # HTML/JSON report generation with directory prioritization
│       └── template.html       # Self-contained Jinja2 template with JS sorting/filtering
├── fingerprints/
│   └── default.yml             # PII patterns + document classification markings
├── config.yml.sample
├── hawk_scan.spec              # PyInstaller build spec
└── tests/                      # 94 tests across 9 test files
```

### Layer Separation

- **remote/** — How to reach files. Transport abstraction means the scanner has no knowledge of WinRM vs SMB.
- **scanner/** — What to do with file content. Pure functions, no network awareness.
- **report/** — What to produce. Takes structured results, generates output.
- **cli.py** — Ties layers together with progress display and credential handling.

## 2. Remote Access Layer

### Transport Interface (transport.py)

Both WinRM and SMB implement the `Transport` ABC:

- `is_available()` — connectivity/auth check
- `enumerate(paths, exclude_patterns, progress_callback)` — yields `FileMetadata` for scannable files
- `retrieve(remote_path, local_dir)` — downloads a file to local temp, returns local path
- `detect_volumes()` — discovers fixed drives on the target

`negotiate_transport()` auto-selects: tries WinRM first, falls back to SMB. `--transport smb|winrm` forces a specific transport.

`Credentials` dataclass supports current-user Kerberos auth or explicit NTLM credentials.

### SMB Transport (smb_transport.py)

- Uses `smbprotocol` / `smbclient` for admin share access (`\\host\C$\...`)
- Custom `_walk_safe()` using `smbclient.scandir()` instead of `smbclient.walk()` to handle Windows symlinks/junctions (e.g., `All Users → C:\ProgramData`) that crash the standard walk
- Filters by `SCANNABLE_EXTENSIONS` during enumeration — only collects files the readers can process
- Uses `ntpath` for UNC path manipulation (cross-platform: works from macOS or Linux)
- Deferred session registration — `register_session()` called on first use, not in constructor
- Progress callback fires on each file found during enumeration

### WinRM Transport (winrm_transport.py)

- Uses `pywinrm` to execute PowerShell on the target
- Enumeration: `Get-ChildItem -Recurse -File` with server-side exclude filtering via `Where-Object`
- Retrieval: `[System.IO.File]::ReadAllBytes()` → base64 decode
- Volume detection: `Get-Volume` for fixed drives
- Auth: Kerberos (current user) or NTLM (explicit credentials)

## 3. Scanning Engine

### ScanEngine (engine.py)

Compiles fingerprint regexes once at init, runs them against text content per file.

**Threshold-based detection (`min_matches`):**
Patterns specify a minimum match count per file. A single SSN in a file is likely a false positive; 3+ SSNs is a list. This dramatically reduces noise:

| Pattern | min_matches | Rationale |
|---------|-------------|-----------|
| SSN | 3 | Bulk exposure, not a stray number |
| Credit Card | 10 | A database extract or list |
| Driver License | 10 | A list, not an isolated match |
| Email | 10 | A contact list, not a signature |
| US Passport | 2 | Multiple passports = a list |
| ITIN | 2 | Multiple ITINs = a list |
| EIN | 3 | Multiple EINs = a list |

**Co-occurrence rules (`require_all`):**
Compound patterns that only fire when ALL sub-patterns match in the same file. Used for bank account detection: a routing number alone isn't actionable, but routing number + account number together in one file is a finding.

**Context keywords:**
Optional per-pattern keyword list that boosts confidence. SSN matches near "social security" or "tax id" get `confidence: high`; bare numeric matches without context get `confidence: low`.

**Redaction:**
When `--redact` is enabled, matched values have their middle portion masked with `*` characters. Sample text is also redacted.

### File Readers (readers.py)

All imports are lazy to avoid dependency conflicts at startup.

| Extension | Reader | Library |
|-----------|--------|---------|
| .txt, .csv | `read_text()` | stdlib (UTF-8 with fallback) |
| .pdf | `read_pdf()` | PyPDF2 |
| .docx | `read_docx()` | python-docx |
| .xlsx | `read_xlsx()` | openpyxl |
| .pptx | `read_pptx()` | python-pptx |
| .png, .jpg, .jpeg, .gif, .bmp | `read_image_ocr()` | pytesseract + Pillow + OpenCV |

Only these extensions are enumerated. Scripts (.ps1, .py, .bat), config files (.json, .xml, .yml), and binaries are excluded at the enumeration level — they never cross the network.

OCR pipeline: grayscale → contrast enhancement → thresholding → OpenCV denoising → Tesseract. Handles palette/transparent images by compositing onto white background.

### Orchestrator (orchestrator.py)

Two-phase execution:

1. **Enumerate** — calls `transport.enumerate()`, returns full file list with progress callback
2. **Scan** — iterates file list: check size limit → retrieve to temp → read content → run engine → collect `Finding`/`SkippedFile` → cleanup temp file in `finally` block

The CLI displays separate progress indicators for each phase.

## 4. Fingerprint Patterns

PII-focused with threshold-based detection. No secrets/credentials scanning.

### PII Patterns

- **SSN** (with and without dashes) — min 3 matches, context keywords
- **Credit Card Number** (Visa, MC, Amex, Discover) — min 10 matches
- **Driver License** — min 10 matches, context keywords
- **Bank Account + Routing Number** — co-occurrence rule (both required in same file)
- **US Passport Number** — min 2 matches, context keywords
- **ITIN** — min 2 matches, context keywords
- **EIN** — min 3 matches, context keywords
- **Email** — min 10 matches (bulk exposure only)

### Document Classification Markings

- **Confidential / Strictly Confidential** — severity high
- **Secret** — severity high, with context keywords to reduce false positives
- **Restricted** — severity medium, with context keywords
- **Internal Use Only** — severity medium

### Custom Patterns

Loaded via `--custom-fingerprints path.yml`. Same YAML format with `pattern`, `severity`, `category`, optional `min_matches`, `context_keywords`, or `require_all`. Merged with defaults; custom patterns override defaults by name.

## 5. CLI Interface

```
hawk_scan <target_hostname> [options]

Required:
  target                    Target hostname or IP address

Common options:
  --transport smb|winrm     Force transport (default: auto-negotiate)
  --username DOMAIN\user    Explicit credentials (prompts for password)
  --paths PATH [PATH ...]   Remote paths to scan (default: C:\Users + detected volumes)
  --exclude PAT [PAT ...]   Additional exclude patterns
  --report-format html|json Report format (default: html)
  --output DIR              Output directory (default: current dir)
  --redact                  Mask matched values in report
  --custom-fingerprints F   Path to custom fingerprints YAML
  --max-file-size MB        Skip files larger than this (default: 50)
  --config FILE             Path to config.yml
  --debug                   Verbose output with UNC paths and error details
```

### Progress Display

1. **Enumeration phase**: spinner with live file counter ("Enumerating... 847 files found")
2. **Scanning phase**: progress bar with file count and truncated filename ("Scanning report.docx ━━━━━━━━ 123/847 files")
3. **Completion summary**: files scanned, skipped, findings, duration, report path

### Default Configuration

- Scan paths: `C:\Users` + auto-detected additional volumes
- Excluded: AppData, node_modules, .git, Windows, Program Files, $Recycle.Bin, ProgramData
- Max file size: 50MB
- Report format: HTML
- All overridable via `config.yml` or CLI flags (CLI takes precedence)

## 6. Report Output

### HTML Report

Self-contained single file with inlined CSS and JavaScript. No external dependencies.

**Interactive features:**
- **Sortable columns** — click any column header to sort ascending/descending
- **Search box** — free-text search across all finding fields
- **Severity filter** — dropdown to show only High/Medium/Low
- **Category filter** — dropdown to filter by PII vs classification
- **Result counter** — shows "Showing X of Y" when filtered

**Priority Directories section:**
Directories ranked by risk score (High finding = 10pts, Medium = 3pts, Low = 1pt). Each directory shows:
- Risk score
- Breakdown of High/Medium/Low findings
- Number of affected files
- Visual severity bar

This tells the admin which directories need remediation before travel.

**Other sections:**
- Scan metadata (target, transport, user, timing)
- Summary cards (total findings, severity breakdown, category breakdown)
- Findings table (severity, file path, pattern, category, match count, sample, owner, modified)
- Skipped files table (path, reason)

### JSON Report

Same data structure as HTML for programmatic consumption.

### File Naming

`hawk_scan_<hostname>_<YYYYMMDD_HHMMSS>.html` (or `.json`)

## 7. Packaging

### PyInstaller Distribution

```
hawk_scan/
├── hawk_scan.exe
├── tesseract/
│   ├── tesseract.exe
│   └── tessdata/eng.traineddata
├── fingerprints/default.yml
└── config.yml.sample
```

Build: `pyinstaller hawk_scan.spec` (must run on Windows for Windows exe).

### Dependencies (bundled)

pywinrm, smbprotocol, pytesseract, Pillow, opencv-python-headless, numpy, PyPDF2, python-docx, openpyxl, python-pptx, pyyaml, rich, jinja2

## 8. Error Handling

- **Connectivity failure**: clear error message, exit 1
- **Transport fallback**: WinRM → SMB logged transparently
- **File errors (non-fatal)**: locked/permission-denied/corrupt files logged to skipped section, scan continues
- **Large files**: skipped with reason in report
- **Windows symlinks/junctions**: detected via `is_symlink()`, skipped during SMB walk to avoid crashes
- **Temp cleanup**: `finally` block ensures cleanup on success, failure, or Ctrl+C
- **Library warnings**: PIL, PyPDF2, openpyxl warnings suppressed
- **OCR import failure**: graceful degradation if numpy/cv2 have version conflicts

## 9. Cross-Platform Notes

Developed and tested on macOS scanning Windows targets over SMB. Key cross-platform considerations:

- `ntpath` used for all UNC/Windows path manipulation (not `os.path`)
- `smbclient.scandir()` used instead of `smbclient.walk()` to handle Windows reparse points
- All heavy library imports are lazy to avoid environment-specific conflicts at startup
- Final packaging targets Windows x64 only (PyInstaller)

## Lineage

Forked from [rohitcoder/hawk-eye](https://github.com/rohitcoder/hawk-eye). Original multi-source scanner code removed. Hawk Scan extracts and improves the scanning core (regex engine, file readers, OCR pipeline) while replacing everything else with purpose-built remote endpoint infrastructure.

## Future Scope

- GUI wrapper for less technical staff
- Batch scanning (list of hostnames)
- .pst / .ost Outlook data file scanning
- Integration with ticketing/SIEM systems
- WinRM enumeration performance (single remote command vs per-directory SMB round-trips)
