# Hawk Scan: Remote Endpoint PII & Secrets Scanner

**Date:** 2026-04-29
**Status:** Approved
**Approach:** New project extracting hawk-eye's scanning core (Approach 2)

## Overview

Hawk Scan is a standalone Windows CLI tool for enterprise administrators to remotely scan domain-joined Windows endpoints for PII, secrets, and classified data before devices are taken abroad by staff. It runs from an administrative workstation, requires no software installation on the target device, and produces a self-contained report.

### Key Constraints

- Single target machine per scan (no batch orchestration)
- No dependencies installed on the target endpoint
- No dependencies required on the admin workstation (standalone .exe)
- Domain-joined Windows environment (Azure/M365/Power Platform/Dynamics stack)
- Report output only (no ticketing, SIEM, or notification integrations)

## 1. Project Structure & Component Architecture

```
hawk_scan/
├── cli.py              # CLI entry point, arg parsing
├── config.py           # YAML config loading (connection + fingerprints)
├── remote/
│   ├── transport.py    # Abstract interface for remote file access
│   ├── winrm.py        # WinRM implementation (primary)
│   └── smb.py          # SMB admin share implementation (fallback)
├── scanner/
│   ├── engine.py       # Regex fingerprint matching (extracted from hawk-eye)
│   ├── readers.py      # File content extraction: PDF, Office, OCR, plain text
│   └── orchestrator.py # Coordinates enumeration -> download -> scan -> results
├── report/
│   └── generator.py    # HTML and JSON report generation
├── fingerprints/
│   └── default.yml     # US PII + Azure/M365/Dynamics secrets
└── config.yml.sample   # Sample config file
```

### Separation of Concerns

- **remote/**: How to reach files on the target. Transport abstraction lets WinRM and SMB be swapped or combined without touching scanning logic.
- **scanner/**: What to do with file content. The regex engine and file readers are pure functions with no knowledge of where files came from.
- **report/**: What to produce. Takes structured results, generates output.
- **cli.py**: Ties it all together.

The transport abstraction is the critical design boundary. `orchestrator.py` asks the transport layer "enumerate files at these paths" and "give me this file's contents" -- it does not care whether that happens via WinRM or SMB.

## 2. Remote Access Layer

### Transport Interface

Both WinRM and SMB implement the same contract:

- `enumerate(target_host, paths, exclude_patterns)` -- yields remote file metadata (path, size, extension)
- `retrieve(target_host, remote_path, local_temp_path)` -- downloads a single file to a local temp directory for scanning
- `is_available(target_host)` -- connectivity/auth check

### WinRM (Primary)

- Uses `pywinrm` library to execute PowerShell commands on the target.
- Enumeration runs `Get-ChildItem -Recurse` remotely, returning file paths and metadata. Only the file listing travels over the network, not file contents.
- Retrieval: small files are read via PowerShell and streamed back as base64. Larger files fall back to SMB to avoid WinRM's message size limits (~150KB).
- Authentication: Kerberos (current user context) or NTLM (explicit credentials).

### SMB (Fallback)

- Uses `smbprotocol` / `smbclient` library to access admin shares (`\\target\C$\...`).
- Enumeration walks the remote share directory tree. Functional but slower than WinRM since every directory listing is a network round-trip.
- Retrieval: copies files directly from the share to local temp.
- Authentication: same credential options as WinRM.

### Auto-Negotiation Flow

1. Try WinRM `is_available()` on the target.
2. If WinRM succeeds: use WinRM for enumeration, WinRM+SMB hybrid for retrieval (small files via WinRM, large files via SMB).
3. If WinRM fails: fall back to pure SMB for both enumeration and retrieval.
4. Report which transport was used in the output.

### Temp File Handling

Files are downloaded to a temp directory on the admin workstation, scanned, then deleted. The temp directory is cleaned up at the end of the scan (or on failure via `finally` block). No target-device files persist on the admin workstation after the scan completes.

## 3. Scanning Engine

Extracted from hawk-eye's `system.py`, cleaned up and focused.

### Regex Matching (engine.py)

- Lifted from hawk-eye's `match_strings()`: loads YAML fingerprint patterns, compiles regexes, runs them against text content.
- Returns structured results: pattern name, matched values, match count, sample text.
- Supports redaction mode (mask middle portion of matched values) controlled by config.
- Patterns are compiled once at startup and reused across all files (hawk-eye recompiles per call).

### File Readers (readers.py)

Each reader is a standalone function: takes a file path, returns extracted text.

- **Plain text**: read as UTF-8 with fallback to latin-1.
- **PDF**: extract text via PyPDF2 page-by-page.
- **Word (.docx)**: extract paragraph text via python-docx.
- **Excel (.xlsx)**: extract cell values via openpyxl.
- **PowerPoint (.pptx)**: extract text from slides via python-pptx (hawk-eye had an unimplemented stub).
- **Images (.png, .jpg, .gif, .bmp)**: OCR via Tesseract/pytesseract with image enhancement (grayscale, contrast, thresholding, denoising).

### File Routing

`scan_file()` dispatches by extension to the appropriate reader, then passes extracted text to the regex engine. No archive or video branches.

### OCR Bundling

Tesseract binaries (~30MB) are included as data files in the PyInstaller spec. The `pytesseract` library is pointed to the bundled binary path at runtime.

### What Is Dropped from Hawk-Eye

- Archive extraction (zip/rar/tar)
- Video frame OCR (cv2 video capture)
- ProcessPoolExecutor / ThreadPoolExecutor for video
- Notification logic (Slack, Jira)
- All non-filesystem command modules (S3, MySQL, PostgreSQL, MongoDB, CouchDB, Redis, Firebase, GCS, Google Drive, Slack, text)

## 4. Fingerprint Patterns

### US PII Patterns (New)

- Social Security Number (XXX-XX-XXXX and variants with/without dashes)
- US Passport Number
- Driver's License (state-format-aware where feasible, generic fallback)
- ITIN (Individual Taxpayer Identification Number)
- EIN (Employer Identification Number)
- US Phone Numbers (domestic formats)
- US Bank Account / Routing Numbers
- Credit/Debit Card Numbers (Visa, Mastercard, Amex, Discover; Luhn-validated in post-processing where possible)
- Date of Birth patterns near PII context keywords
- Email Addresses (kept from hawk-eye)

### Secrets Patterns (Azure/M365/Power Platform/Dynamics)

- Azure AD / Entra ID Client Secrets
- Azure Storage Account Keys
- Azure SAS Tokens (Shared Access Signatures)
- Azure Service Bus / Event Hub connection strings
- Microsoft Graph API tokens
- M365 / SharePoint app credentials
- Azure DevOps Personal Access Tokens
- Azure SQL connection strings with embedded credentials
- Power Platform: Dataverse/CDS connection strings, Power Automate flow connection credentials, environment URL patterns with embedded auth
- Dynamics CRM: Dynamics 365 connection strings with embedded credentials, CRM Organization Service URLs with auth tokens
- Slack tokens (access, user, webhook)
- Generic Basic Auth credentials in URLs
- Private key file markers / PFX certificate references
- Generic password patterns (`password=`, `passwd:`, `connectionstring=` near values)

### Custom Patterns (Org-Specific)

Loaded from a separate `custom_fingerprints.yml` file specified via `--custom-fingerprints` flag. Same YAML format. Merged with defaults at runtime; custom patterns can override defaults by using the same pattern name.

Example:
```yaml
Member ID: "\\bMID-\\d{8}\\b"
Classification - Confidential: "(?i)\\b(CONFIDENTIAL|STRICTLY CONFIDENTIAL)\\b"
Classification - Internal Use: "(?i)\\bINTERNAL USE(\\s+ONLY)?\\b"
Classification - Restricted: "(?i)\\bRESTRICTED\\b"
```

### False Positive Management

Each pattern can optionally specify `context_keywords` -- a list of nearby words that increase confidence. For example, SSN matches near "SSN", "social security", "tax" are flagged at higher confidence, while bare 9-digit sequences in isolation are reported at lower confidence. This is a lightweight second-pass filter per pattern in the YAML, not a full NLP pipeline.

## 5. CLI Interface & Configuration

### CLI Usage

```
hawk_scan.exe <target_hostname> [options]

# Typical usage - scan with defaults (user profiles + common locations)
hawk_scan.exe WORKSTATION-01

# Specify custom paths
hawk_scan.exe WORKSTATION-01 --paths "C:\Users\jsmith" "D:\Projects"

# Use alternate credentials
hawk_scan.exe WORKSTATION-01 --username DOMAIN\admin --password (prompts securely)

# Control output
hawk_scan.exe WORKSTATION-01 --report-format html --output .\reports\
hawk_scan.exe WORKSTATION-01 --report-format json --output .\reports\

# Use custom fingerprints
hawk_scan.exe WORKSTATION-01 --custom-fingerprints .\custom_fingerprints.yml

# Force a specific transport
hawk_scan.exe WORKSTATION-01 --transport smb

# Other flags
hawk_scan.exe WORKSTATION-01 --redact
hawk_scan.exe WORKSTATION-01 --debug
hawk_scan.exe WORKSTATION-01 --exclude "*.log" "AppData" "node_modules"
hawk_scan.exe WORKSTATION-01 --max-file-size 100  # MB
```

Target hostname is the only required argument. Everything else has sensible defaults.

### Default Scan Paths

When `--paths` is not specified:
- `C:\Users` (all user profile directories)
- Root of any additional local volumes detected (D:\, E:\, etc.) -- enumerated via WinRM `Get-Volume` or SMB share probing; only fixed/local drives, not mapped network drives or removable media

### Configuration File (Optional)

For admins who run scans frequently with the same settings. CLI flags override config file values.

```yaml
# config.yml
default_paths:
  - "C:\\Users"
  - "D:\\"
exclude_patterns:
  - "AppData"
  - "node_modules"
  - ".git"
  - "\\Windows"
  - "\\Program Files"
report:
  format: html
  output_dir: ".\\reports"
  redact: true
custom_fingerprints: ".\\custom_fingerprints.yml"
```

### Password Handling

If `--username` is provided without `--password`, the tool prompts securely (masked input). Passwords are never accepted as a bare CLI argument to avoid shell history exposure.

## 6. Report Output

### HTML Report (Default)

A single self-contained `.html` file with all CSS inlined. No external dependencies; can be opened in any browser or emailed as-is.

**Contents:**
- **Header**: scan metadata -- target hostname, scan timestamp, transport method used (WinRM/SMB), admin username, scan duration.
- **Executive summary**: total files scanned, total findings, breakdown by severity (High/Medium/Low), breakdown by category (PII vs. secrets vs. classification markings).
- **Findings table**: one row per finding with columns for file path, pattern name, category, match count, sample matched values (redacted if enabled), file owner, file last-modified date. Sorted by severity then by file path.
- **Skipped files section**: files that could not be scanned (locked, permission denied, corrupt, over size threshold) with the reason.

### Severity Assignment

Built-in mapping per pattern (declared in fingerprint YAML as a `severity` field):

- **High**: SSN, passport numbers, private keys, credentials/connection strings, credit card numbers
- **Medium**: driver's license, bank account numbers, classification markings (Confidential, Restricted)
- **Low**: email addresses, phone numbers, Internal Use markings, generic pattern matches

Custom patterns can declare their own severity level.

### JSON Report

Same data structure as the HTML report but as machine-readable JSON.

### File Naming

`hawk_scan_<hostname>_<YYYYMMDD_HHMMSS>.html` (or `.json`), written to the output directory.

## 7. Packaging & Dependencies

### Distribution Structure

```
hawk_scan/
├── hawk_scan.exe
├── tesseract/
│   ├── tesseract.exe
│   └── tessdata/
│       └── eng.traineddata
├── fingerprints/
│   └── default.yml
└── config.yml.sample
```

This folder can live on a network share, USB drive, or local directory. Admin runs `hawk_scan.exe` from wherever it sits.

### Python Dependencies (Bundled into exe)

- `pywinrm` -- WinRM communication
- `smbprotocol` -- SMB file access
- `pytesseract` + bundled Tesseract binaries -- OCR
- `Pillow`, `opencv-python-headless` -- image enhancement for OCR
- `PyPDF2` -- PDF text extraction
- `python-docx` -- Word document reading
- `openpyxl` -- Excel spreadsheet reading
- `python-pptx` -- PowerPoint reading
- `pyyaml` -- config and fingerprint parsing
- `rich` -- CLI output formatting and progress display
- `jinja2` -- HTML report templating

### Build Process

A PyInstaller `.spec` file defines the build:
```bash
pip install pyinstaller
pyinstaller hawk_scan.spec
```

Produces `dist/hawk_scan/` ready for distribution. Target platform: Windows x64 only. Build must run on Windows.

## 8. Error Handling & Edge Cases

### Connectivity Failures

- If both WinRM and SMB fail: exit immediately with a clear message ("Cannot reach WORKSTATION-01 -- verify the machine is online, network accessible, and you have admin rights").
- If WinRM fails but SMB succeeds: log the fallback and continue.
- Network timeout configurable (default 30 seconds per connection attempt).

### File-Level Errors (Non-Fatal)

- **Locked files**: skip, log in skipped files section of report.
- **Permission denied**: skip, log.
- **Corrupt files** that crash a reader: catch per-file, log, continue scanning.
- The scan never aborts because of a single bad file.

### Large File Handling

- Files over a configurable size threshold (default 50MB) are skipped.
- `--max-file-size` flag overrides the threshold.
- Reported in skipped files section.

### Scan Progress

- `rich` progress bar: files enumerated, files scanned, current file name.
- On completion: summary with total files scanned, files skipped, findings count, elapsed time.

### Temp File Cleanup

- Downloaded files stored in a system temp directory under a unique scan-session folder.
- Cleanup runs in a `finally` block -- temp files removed whether the scan succeeds, fails, or is interrupted with Ctrl+C.
- If cleanup fails (file lock), warn the admin with the temp directory path for manual cleanup.

## Relationship to Hawk-Eye

This project extracts and reuses hawk-eye's proven scanning logic:

| Reused from hawk-eye | Purpose |
|---|---|
| `match_strings()` regex engine | Core fingerprint matching |
| `scan_file()` file-type routing | Dispatch by extension |
| `read_pdf()` | PDF text extraction |
| `read_office_document()` | Word/Excel reading |
| `enhance_and_ocr()` pipeline | Image OCR with enhancement |
| `RedactData()` | Value masking |
| Fingerprint YAML format | Pattern definition structure |

Everything else is purpose-built for the remote endpoint scanning use case.

## Future Scope (Not in Initial Build)

- GUI wrapper for less technical staff
- Batch scanning (list of hostnames)
- Integration with ticketing/SIEM systems
- .pst / .ost Outlook data file scanning
- Archive extraction (zip/rar)
