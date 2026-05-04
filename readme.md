# Hawk Scan

Remote endpoint PII scanner for Windows domain environments. Scans domain-joined Windows workstations over the network for personally identifiable information and classified documents — no software installed on the target device.

Built for enterprise IT administrators who need to verify endpoints are clean before staff travel internationally.

## What It Does

- Connects to a remote Windows machine via SMB admin shares or WinRM (PowerShell remoting), or scans the local filesystem directly with `--local`
- Enumerates and downloads documents (PDF, Word, Excel, PowerPoint, images, text/CSV)
- Scans file content for PII using threshold-based regex detection:
  - SSNs (flags files with 3+ matches, not one-off numbers)
  - Credit card numbers (10+ matches)
  - Driver license numbers (10+ matches)
  - Bank account + routing number combinations (co-occurrence in same file)
  - US passport numbers, ITINs, EINs, bulk email lists
- Detects document classification markings (Confidential, Secret, Restricted, Internal Use Only)
- Produces an interactive HTML report with sortable/filterable findings and directory-level remediation priorities

## Quick Start

```bash
# Install (dev mode)
cd hawk_scan && pip install -e ".[dev]"

# Scan a remote machine over SMB
hawk_scan WORKSTATION-01 --transport smb --username 'DOMAIN\admin'

# Scan the local machine directly (no network overhead)
hawk_scan --local

# Scan specific directories
hawk_scan WORKSTATION-01 --transport smb --username 'DOMAIN\admin' \
  --paths 'C:\Users\jsmith\Documents' 'C:\Users\jsmith\Desktop'

# Redact matched values in report
hawk_scan WORKSTATION-01 --transport smb --username 'DOMAIN\admin' --redact

# Output JSON instead of HTML
hawk_scan WORKSTATION-01 --transport smb --username 'DOMAIN\admin' --report-format json
```

Password is prompted securely — never passed as a CLI argument.

## Options

| Flag | Description | Default |
|------|-------------|---------|
| `--local` | Scan local filesystem directly | Off |
| `--transport smb\|winrm\|local` | Force transport method | Auto-negotiate |
| `--username DOMAIN\user` | Explicit credentials | Current user (Kerberos) |
| `--paths PATH [...]` | Remote paths to scan | C:\Users + detected volumes |
| `--exclude PAT [...]` | Additional exclude patterns | AppData, .git, etc. |
| `--report-format html\|json` | Report format | html |
| `--output DIR` | Report output directory | Current directory |
| `--redact` | Mask matched values in report | Off |
| `--custom-fingerprints FILE` | Custom pattern YAML | None |
| `--max-file-size MB` | Skip files over this size | 50 |
| `--config FILE` | Config file path | None |
| `--debug` | Verbose output | Off |

## Report

The HTML report is a single self-contained file (no external dependencies) with:

- **Summary cards** — total findings, severity breakdown, category breakdown
- **Priority directories** — ranked by risk score for remediation guidance
- **Findings table** — sortable columns, text search, severity/category filters
- **Skipped files** — locked, permission denied, or oversized files that couldn't be scanned

## Custom Fingerprints

Create a YAML file with custom patterns:

```yaml
Member ID:
  pattern: "\\bMID-\\d{8}\\b"
  severity: high
  category: pii
  min_matches: 3

Internal Case Number:
  pattern: "\\bCASE-\\d{6}\\b"
  severity: medium
  category: custom
```

Load with `--custom-fingerprints custom.yml`. Custom patterns merge with (and can override) defaults.

## Standalone Executable

Hawk Scan can be packaged as a standalone Windows `.exe` via PyInstaller — no Python required on the admin workstation. See [Windows Build Guide](docs/windows-build-guide.md).

## Architecture

Four-layer design:

- **remote/** — Transport abstraction (SMB + WinRM + local), auto-negotiation, credential handling
- **scanner/** — Regex engine with thresholds and co-occurrence rules, file readers (PDF, Office, OCR), orchestrator
- **report/** — HTML/JSON report generation with Jinja2 templates
- **cli.py** — Ties it all together

See the [design spec](docs/superpowers/specs/2026-04-29-hawk-scan-remote-endpoint-scanner-design.md) for full architecture documentation.

## Development

```bash
cd hawk_scan
pip install -e ".[dev]"
pytest tests/ -v          # 94 tests
```

## License

Commons Clause + LGPL 2.1. See [LICENSE](LICENSE).

Originally forked from [rohitcoder/hawk-eye](https://github.com/rohitcoder/hawk-eye). The original multi-source scanner code has been removed and replaced with purpose-built remote endpoint scanning infrastructure.
