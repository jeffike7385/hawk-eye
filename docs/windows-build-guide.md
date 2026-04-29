# Windows Build Guide — Packaging Hawk Scan as an Executable

## Prerequisites

- Windows 10/11 x64 machine (or Windows Server)
- Python 3.11+ installed (python.org, not Microsoft Store)
- Tesseract OCR installed (https://github.com/UB-Mannheim/tesseract/wiki)
- Git (to clone the repo)

## Step 1: Clone and Install

```powershell
git clone https://github.com/your-org/hawk-eye.git
cd hawk-eye\hawk_scan
pip install -e ".[dev]"
```

## Step 2: Verify Tests Pass

```powershell
pytest tests\ -v
```

All 94 tests should pass. If OCR tests fail, verify Tesseract is installed and `tesseract` is on your PATH.

## Step 3: Locate Tesseract

Find your Tesseract installation. Typical paths:

```
C:\Program Files\Tesseract-OCR\tesseract.exe
C:\Program Files\Tesseract-OCR\tessdata\eng.traineddata
```

## Step 4: Update the PyInstaller Spec

Edit `hawk_scan.spec` to include Tesseract binaries. Add to the `datas` list:

```python
datas=[
    ('fingerprints/default.yml', 'fingerprints'),
    ('hawk_scan/report/template.html', 'hawk_scan/report'),
    ('config.yml.sample', '.'),
    # Add Tesseract — adjust path if your install location differs
    (r'C:\Program Files\Tesseract-OCR\tesseract.exe', 'tesseract'),
    (r'C:\Program Files\Tesseract-OCR\tessdata\eng.traineddata', 'tesseract/tessdata'),
],
```

## Step 5: Add Tesseract Path Resolution

The bundled exe needs to find Tesseract at runtime. Add this to `hawk_scan/cli.py` in `main()`, before the scan runs:

```python
import pytesseract
import sys

# Point pytesseract at bundled Tesseract when running as frozen exe
if getattr(sys, 'frozen', False):
    tesseract_path = os.path.join(sys._MEIPASS, 'tesseract', 'tesseract.exe')
    if os.path.exists(tesseract_path):
        pytesseract.pytesseract.tesseract_cmd = tesseract_path
```

## Step 6: Build

```powershell
pyinstaller hawk_scan.spec
```

This produces `dist\hawk_scan\` containing:

```
dist\hawk_scan\
├── hawk_scan.exe          # Main executable
├── tesseract\             # Bundled OCR engine
│   ├── tesseract.exe
│   └── tessdata\
│       └── eng.traineddata
├── fingerprints\
│   └── default.yml        # Default PII patterns
├── config.yml.sample      # Reference config
└── [bundled Python + dependencies]
```

## Step 7: Test the Build

```powershell
cd dist\hawk_scan
.\hawk_scan.exe --version
.\hawk_scan.exe WORKSTATION-01 --transport smb --username "DOMAIN\admin" --paths "C:\Users\targetuser\Documents"
```

## Step 8: Distribute

Copy the entire `dist\hawk_scan\` folder to:
- A network share accessible to admins
- A USB drive
- Or install locally on admin workstations

Admins run `hawk_scan.exe` directly — no Python, no dependencies, no installation.

## Troubleshooting

**"tesseract is not installed or not in PATH"**
Verify the Tesseract exe was bundled correctly. Check that the `datas` paths in `hawk_scan.spec` match your Tesseract install location.

**Missing DLLs**
PyInstaller should bundle everything, but if you see missing DLL errors, run `pyinstaller` with `--debug all` to identify what's missing and add it to `hiddenimports` or `binaries` in the spec.

**Large exe size**
The bundled exe will be ~100-150MB due to OpenCV, numpy, and Tesseract. This is expected. Use UPX compression (PyInstaller supports it) to reduce by ~30%.

**Antivirus flags**
PyInstaller executables sometimes trigger AV false positives. Sign the exe with your organization's code signing certificate, or whitelist the hash in your endpoint protection.
