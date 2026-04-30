# Hawk Scan User Guide

## Overview

Hawk Scan remotely scans Windows endpoints for personally identifiable information (PII) and classified documents over the network. It connects via SMB admin shares or WinRM (PowerShell remoting), downloads and inspects document files, and produces an interactive HTML report identifying what sensitive data exists and where.

**Primary use case:** Verify that a domain-joined workstation or laptop is clean of PII before the device is taken abroad by staff.

## Basic Usage

```
hawk_scan <target_hostname> [options]
```

The only required argument is the target machine's hostname or IP address. Everything else has sensible defaults.

### Minimal Scan

```bash
hawk_scan WORKSTATION-01
```

This will:
1. Try SMB first (only reads files physically on disk), fall back to WinRM if SMB is unavailable
2. Use your current domain credentials (Kerberos)
3. Scan `C:\Users` and any other local drives detected on the target
4. Skip AppData, Windows, Program Files, and other system directories
5. Generate an HTML report in the current directory

### Scan with Explicit Credentials

```bash
hawk_scan WORKSTATION-01 --username 'DOMAIN\adminuser'
```

You will be prompted securely for the password. Passwords are never accepted as command-line arguments to avoid shell history exposure.

### Scan Specific Directories

```bash
hawk_scan WORKSTATION-01 --paths 'C:\Users\jsmith\Documents' 'C:\Users\jsmith\Desktop'
```

Use `--paths` to target specific directories instead of the full user profile. This is much faster for quick checks.

### Force a Transport Method

```bash
hawk_scan WORKSTATION-01 --transport smb
hawk_scan WORKSTATION-01 --transport winrm
```

By default, Hawk Scan tries WinRM first (faster enumeration) and falls back to SMB. Use `--transport` to force one or the other.

## Command Reference

### Target

```
hawk_scan <hostname_or_ip>
```

The machine to scan. Must be network-reachable from the admin workstation. For SMB, the admin share (`C$`) must be accessible. For WinRM, PowerShell remoting must be enabled on the target.

### Authentication

| Flag | Description |
|------|-------------|
| *(none)* | Uses current user's domain credentials via Kerberos/SPNEGO |
| `--username DOMAIN\user` | Authenticate with explicit NTLM credentials. Password is prompted securely. |

The `--password` flag exists but is hidden and discouraged. Use the interactive prompt instead.

### Scan Scope

| Flag | Description | Default |
|------|-------------|---------|
| `--paths PATH [PATH ...]` | Specific remote directories to scan | `C:\Users` + auto-detected volumes |
| `--exclude PAT [PAT ...]` | Patterns to exclude (directory names or `*.ext` globs) | AppData, .git, node_modules, Windows, Program Files, ProgramData, $Recycle.Bin |
| `--max-file-size MB` | Skip files larger than this (in megabytes) | 50 |

#### Path Examples

```bash
# Scan one user's profile
--paths 'C:\Users\jsmith'

# Scan multiple specific directories
--paths 'C:\Users\jsmith\Documents' 'C:\Users\jsmith\Desktop' 'D:\SharedData'

# Scan an entire secondary drive
--paths 'D:\'
```

#### Exclude Examples

```bash
# Skip log files and a specific directory
--exclude '*.log' 'Archives'

# Skip OneDrive cache
--exclude 'OneDriveTemp'
```

Exclude patterns work two ways:
- Patterns starting with `*` are matched against filenames (glob): `*.log` skips all `.log` files
- All other patterns are matched as substrings against the full path: `AppData` skips any path containing "AppData"

### Output

| Flag | Description | Default |
|------|-------------|---------|
| `--report-format html\|json` | Report format | `html` |
| `--output DIR` | Directory to write the report file | Current directory |
| `--redact` | Mask the middle portion of matched values with `***` | Off |

Report files are named `hawk_scan_<hostname>_<YYYYMMDD_HHMMSS>.html` (or `.json`).

#### Redaction

With `--redact` enabled:
- SSN `123-45-6789` becomes `1***-***789`
- Email `user@example.com` becomes `us***ple.com`
- Sample text is also redacted

Use redaction when reports will be shared with staff or management who don't need to see the actual sensitive values.

### Transport

| Flag | Description | Default |
|------|-------------|---------|
| `--transport smb` | Force SMB admin shares | Auto-negotiate |
| `--transport winrm` | Force WinRM (PowerShell remoting) | Auto-negotiate |

**SMB** connects to `\\hostname\C$` using admin share access. Works from any OS (macOS, Linux, Windows). Slower enumeration (each directory is a network round-trip) but universally available if you have admin rights on the target.

**WinRM** executes PowerShell commands on the target machine via PSRP (PowerShell Remoting Protocol). Faster enumeration (runs `Get-ChildItem` remotely) and can read files that are inaccessible via SMB (e.g., OneDrive cloud files). Requires WinRM to be enabled on the target (typically via GPO in domain environments). Files are retrieved via base64 over the WinRM channel. Uses SPNEGO/Negotiate auth (Kerberos) for current-user auth, or NTLM for explicit credentials. Use the target's FQDN (e.g., `WORKSTATION-01.domain.local`) for reliable Kerberos SPN resolution.

**Auto-negotiation** tries WinRM first, falls back to SMB. The transport used is displayed in the CLI output and recorded in the report.

**OneDrive considerations:** Files in OneDrive folders that are marked "always available" but not actually hydrated locally will fail to read via SMB (`STATUS_CLOUD_FILE_NOT_IN_SYNC`). This is reported as "Cloud file not synced" in the skip list. WinRM can read these files because PowerShell commands run through the local file system filter driver. If your environment uses OneDrive folder redirection, prefer WinRM or use `--transport winrm` to ensure full coverage.

### Configuration File

| Flag | Description | Default |
|------|-------------|---------|
| `--config FILE` | Path to a YAML configuration file | None |

A config file lets you set defaults so you don't have to pass the same flags every time. CLI flags always override config file values.

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
  - "\\Program Files (x86)"
  - "$Recycle.Bin"

report:
  format: html
  output_dir: ".\\reports"
  redact: true

max_file_size_mb: 50
timeout_seconds: 30

custom_fingerprints: ".\\custom_fingerprints.yml"
```

### Custom Fingerprints

| Flag | Description | Default |
|------|-------------|---------|
| `--custom-fingerprints FILE` | Path to a custom fingerprint YAML file | None |

Custom fingerprints are merged with the built-in defaults. If a custom pattern has the same name as a default, the custom version overrides it.

See [Custom Scan Profiles](#custom-scan-profiles) below for details.

### Other Flags

| Flag | Description |
|------|-------------|
| `--debug` | Print verbose output: UNC paths, session details, transport errors, WinRM negotiation, cloud file attributes |
| `--version` | Print version and exit |

## What Gets Scanned

### File Types

Only document and image files are scanned. Code, scripts, config files, and binaries are skipped entirely — they never cross the network.

| Extension | Type | Method |
|-----------|------|--------|
| `.txt`, `.csv` | Plain text | UTF-8 decode |
| `.pdf` | PDF documents | PyPDF2 text extraction |
| `.docx` | Word documents | python-docx paragraph extraction |
| `.xlsx` | Excel spreadsheets | openpyxl cell value extraction |
| `.pptx` | PowerPoint presentations | python-pptx text frame extraction |
| `.png`, `.jpg`, `.jpeg`, `.gif`, `.bmp` | Images | OCR via Tesseract with image enhancement |

### Default PII Patterns

| Pattern | Severity | Threshold | Description |
|---------|----------|-----------|-------------|
| SSN | High | 3+ matches | Social Security Numbers (with dashes) |
| SSN No Dashes | High | 3+ matches | SSNs without dashes (requires context keywords) |
| Credit Card Number | High | 10+ matches | Visa, Mastercard, Amex, Discover |
| Driver License | Medium | 10+ matches | State license format (requires context keywords) |
| Bank Account + Routing | High | Co-occurrence | Both must appear in the same file |
| US Passport Number | High | 2+ matches | US passport format |
| ITIN | High | 2+ matches | Individual Taxpayer ID |
| EIN | Medium | 3+ matches | Employer Identification Number |
| Email | Low | 10+ matches | Bulk email exposure only |

### Document Classification Markings

| Pattern | Severity |
|---------|----------|
| Confidential / Strictly Confidential | High |
| Secret | High (with context keywords) |
| Restricted | Medium (with context keywords) |
| Internal Use Only | Medium |

### Threshold-Based Detection

Hawk Scan uses match thresholds to reduce false positives. A single SSN-like number in a file could be a phone extension, a part number, or any other 9-digit sequence. But 3+ SSN patterns in one file is almost certainly a list of actual SSNs.

Thresholds are set per pattern in the fingerprint YAML via the `min_matches` field.

### Co-Occurrence Rules

Some patterns only make sense in combination. A 9-digit number alone could be anything, but a 9-digit routing number appearing in the same file as an 8-17 digit account number is a bank account record.

Co-occurrence rules use `require_all` in the fingerprint YAML — all sub-patterns must match in the same file for the rule to fire.

### Context Keywords

Patterns with `context_keywords` assign confidence levels:
- **High confidence**: the keyword appears near the match (e.g., "SSN" near a 9-digit number)
- **Low confidence**: the pattern matches but no contextual keyword is present

Both are reported, but confidence level helps prioritize remediation.

## Custom Scan Profiles

Create a YAML file to add organization-specific patterns or adjust detection sensitivity.

### Pattern Format

```yaml
Pattern Name:
  pattern: "regex here"
  severity: high|medium|low
  category: pii|classification|custom
  min_matches: 3          # optional, default 1
  context_keywords:        # optional
    - "keyword1"
    - "keyword2"
```

### Co-Occurrence Pattern Format

```yaml
Pattern Name:
  severity: high
  category: pii
  require_all:
    sub_pattern_1: "regex for first component"
    sub_pattern_2: "regex for second component"
```

### Examples

```yaml
# Flag files containing your org's member IDs (3+ in a file)
Member ID:
  pattern: "\\bMID-\\d{8}\\b"
  severity: high
  category: pii
  min_matches: 3

# Flag internal case numbers
Internal Case Number:
  pattern: "\\bCASE-\\d{6}\\b"
  severity: medium
  category: custom

# Flag documents marked with your org's classification scheme
Proprietary:
  pattern: "(?i)\\bPROPRIETARY\\b"
  severity: high
  category: classification

# Override the default SSN threshold (make it more sensitive)
SSN:
  pattern: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
  severity: high
  category: pii
  min_matches: 1
  context_keywords: ["ssn", "social security"]

# Detect when both a name-like pattern and SSN appear in same file
PII Record (Name + SSN):
  severity: high
  category: pii
  require_all:
    name: "\\b[A-Z][a-z]+ [A-Z][a-z]+\\b"
    ssn: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
```

### Using Custom Profiles

```bash
# One-off custom scan
hawk_scan WORKSTATION-01 --custom-fingerprints ./our_patterns.yml

# Set as default in config file
# config.yml:
#   custom_fingerprints: ".\\our_patterns.yml"
hawk_scan WORKSTATION-01 --config config.yml
```

## Reading the Report

### Priority Directories

The report's **Priority Directories for Remediation** section ranks directories by risk score:
- High finding = 10 points
- Medium finding = 3 points
- Low finding = 1 point

Directories with the highest scores should be remediated first. The visual bar shows the severity mix at a glance.

### Navigating Findings

File paths in the findings table are hyperlinked — click the directory portion to open the folder directly in File Explorer via the admin share. This makes it easy to inspect or remediate flagged files without manually navigating to them.

### Filtering and Sorting

The findings table supports:
- **Click column headers** to sort ascending/descending
- **Search box** to filter by any text (file path, pattern name, etc.)
- **Severity dropdown** to show only High, Medium, or Low
- **Category dropdown** to show only PII or Classification findings

### What to Do with Findings

1. **Review Priority Directories** — focus on the highest-scoring directories first
2. **Filter by High severity** — these are the most critical (SSNs, credit cards, bank accounts, classified markings)
3. **Verify findings** — open the flagged files on the target machine to confirm they contain actual PII (not false positives)
4. **Remediate** — move, encrypt, or delete sensitive files before travel
5. **Re-scan** — run Hawk Scan again to verify the endpoint is clean

## Troubleshooting

### "Cannot reach HOSTNAME"

- Verify the machine is powered on and network-accessible
- Verify you have admin rights on the target (`net use \\HOSTNAME\C$` from a Windows admin workstation)
- If using WinRM, verify it's enabled: `Test-WSMan HOSTNAME` from PowerShell
- Try forcing SMB: `--transport smb`

### WinRM auth fails / "credentials rejected"

- Use the target's FQDN for Kerberos: `hawk_scan WORKSTATION-01.domain.local`
- Verify native WinRM works: `Invoke-Command -ComputerName HOSTNAME -ScriptBlock { Write-Output OK }`
- If your environment only allows Kerberos (no NTLM), don't pass `--username` — let the tool use your current domain session
- Check `--debug` output for the specific auth error

### "Cloud file not synced" skips

OneDrive files showing as "always available" in Explorer may not be truly hydrated on disk. The SMB admin share cannot trigger OneDrive hydration. Options:
- Use `--transport winrm` to read files through the local file system filter driver
- Investigate the user's OneDrive sync health — files marked as synced but returning `STATUS_CLOUD_FILE_NOT_IN_SYNC` indicate a broken sync state

### Scan takes a long time

SMB enumeration is slow because each directory listing is a network round-trip. To speed things up:
- Target specific directories with `--paths` instead of scanning entire user profiles
- Add bulky directories to `--exclude` (e.g., large OneDrive caches, code repos)
- Use WinRM if available (`--transport winrm`) — enumeration runs server-side

### 0 files found

- Check `--debug` output to see the UNC path and any errors
- Verify the target path exists and is accessible via the admin share
- Verify credentials are correct (try `--username` with explicit credentials)

### OCR not working

- Tesseract must be installed and on PATH (dev mode) or bundled (exe mode)
- Check with: `tesseract --version`
- If numpy/cv2 have version conflicts, upgrade: `pip install --upgrade numexpr bottleneck`

### Report written to unexpected location

The `--output` flag specifies the directory. Default is the current working directory. Use an absolute path to be explicit:

```bash
hawk_scan WORKSTATION-01 --output /Users/me/reports
```
