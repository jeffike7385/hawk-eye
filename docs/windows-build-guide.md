# Windows Build Guide — Packaging Hawk Scan as a Signed Executable

## Prerequisites

- Windows 10/11 x64 (or Windows Server)
- Python 3.11+ installed (python.org — not the Microsoft Store stub)
- Git
- Windows 10/11 SDK (provides `signtool.exe` for code signing)
- A code-signing certificate in the `CurrentUser\My` certificate store

Tesseract OCR is downloaded and bundled automatically by the build script.

## Quick Build

From the `hawk_scan/` directory:

```powershell
.\build.ps1
```

This single command:

1. Vendors Tesseract OCR into `vendor/tesseract/` (downloads from GitHub on first run, or copies from an existing system install)
2. Installs all Python dependencies via `pip install -e ".[dev]"`
3. Verifies all required imports
4. Builds a single-file `dist\hawk_scan.exe` via PyInstaller
5. Finds your code-signing cert by EKU + expiration date
6. Signs with SHA-256 + RFC 3161 timestamp (DigiCert)
7. Verifies the signature

Output: `dist\hawk_scan.exe` (~140 MB)

## Build Script Options

```powershell
.\build.ps1                              # full build + sign (auto-find cert expiring 2028-04-18)
.\build.ps1 -Thumbprint <SHA1>           # sign with explicit cert thumbprint
.\build.ps1 -CertExpiry "2030-01-15"     # match cert by a different expiration date
.\build.ps1 -SkipSign                    # build only, no signing
.\build.ps1 -SkipTesseractDownload       # skip Tesseract download (use existing vendor/)
.\build.ps1 -TimestampUrl <url>          # override timestamp server
```

## Manual Signing

If you need to sign separately (e.g., after a `-SkipSign` build):

```powershell
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe" sign /sha1 <THUMBPRINT> /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 dist\hawk_scan.exe
```

Verify:

```powershell
& "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe" verify /pa /v dist\hawk_scan.exe
```

## Test the Build

```powershell
.\dist\hawk_scan.exe --version
.\dist\hawk_scan.exe WORKSTATION-01 --transport smb --username "DOMAIN\admin" --paths "C:\Users\targetuser\Documents"
```

## Distribute

Copy `dist\hawk_scan.exe` (single file, no folder) to:
- A network share accessible to admins
- A USB drive
- Or install locally on admin workstations

Admins run `hawk_scan.exe` directly — no Python, no dependencies, no installation required. The signature will validate on any machine that trusts your CA's root certificate (typically all domain-joined machines via GPO).

## How It Works

- **`hawk_scan.spec`** — PyInstaller spec configured for onefile output, bundles Tesseract binaries and tessdata from `vendor/tesseract/`, fingerprint patterns, report template, and sample config
- **`runtime_hook_tesseract.py`** — PyInstaller runtime hook that sets `pytesseract.tesseract_cmd` and `TESSDATA_PREFIX` to point at the bundled Tesseract inside the frozen exe's temp directory
- **`build.ps1`** — Orchestrates the full build + sign pipeline

## Troubleshooting

**"Python 3.11+ not found"**
Install Python from python.org (not the Microsoft Store). The build script searches common install paths and the `py` launcher. After installing, restart PowerShell.

**"tesseract is not installed or not in PATH"**
At runtime, the bundled exe resolves Tesseract automatically via the runtime hook. If you see this error during development (not from the exe), install Tesseract or run `build.ps1` to vendor it.

**Missing DLLs**
Run `python -m PyInstaller --debug all hawk_scan.spec` to identify what's missing and add it to `hiddenimports` or `binaries` in the spec.

**Large exe size (~140 MB)**
Expected — includes OpenCV, NumPy, Tesseract, and all document parsers. UPX is disabled because it conflicts with code signing and triggers AV false positives.

**Antivirus flags**
PyInstaller onefile executables sometimes trigger AV false positives. The code signature should prevent this on machines that trust your CA. If not, whitelist by hash in your endpoint protection.

**Cert not found during signing**
The script searches `CurrentUser\My` for a cert with code-signing EKU matching the expiration date. List your certs with:
```powershell
Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3' } | Format-List Subject,Thumbprint,NotAfter
```
Pass `-Thumbprint <SHA1>` to select a specific cert.
