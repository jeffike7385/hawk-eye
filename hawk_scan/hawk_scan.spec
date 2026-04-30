# -*- mode: python ; coding: utf-8 -*-
import os
import re
from pathlib import Path
from PyInstaller.utils.win32.versioninfo import (
    VSVersionInfo, FixedFileInfo, StringFileInfo, StringTable, StringStruct,
    VarFileInfo, VarStruct,
)

block_cipher = None

# Read version from hawk_scan/__init__.py
_init = (Path(os.path.dirname(os.path.abspath(SPEC))) / "hawk_scan" / "__init__.py").read_text()
_ver_str = re.search(r'__version__\s*=\s*["\']([^"\']+)', _init).group(1)
_parts = [int(x) for x in _ver_str.split(".")] + [0] * (4 - len(_ver_str.split(".")))

version_info = VSVersionInfo(
    ffi=FixedFileInfo(
        filevers=tuple(_parts[:4]),
        prodvers=tuple(_parts[:4]),
    ),
    kids=[
        StringFileInfo([StringTable("040904B0", [
            StringStruct("CompanyName", "MSRA"),
            StringStruct("FileDescription", "Hawk Scan — Remote Endpoint PII & Secrets Scanner"),
            StringStruct("FileVersion", _ver_str),
            StringStruct("InternalName", "hawk_scan"),
            StringStruct("OriginalFilename", "hawk_scan.exe"),
            StringStruct("ProductName", "Hawk Scan"),
            StringStruct("ProductVersion", _ver_str),
        ])]),
        VarFileInfo([VarStruct("Translation", [1033, 1200])]),
    ],
)

# Tesseract binaries are expected at vendor/tesseract/ relative to this spec.
# See build.ps1 — it downloads and extracts the UB-Mannheim portable build there.
SPEC_DIR = Path(os.path.dirname(os.path.abspath(SPEC)))
TESSERACT_DIR = SPEC_DIR / "vendor" / "tesseract"

tesseract_binaries = []
tesseract_datas = []
if TESSERACT_DIR.exists():
    for f in TESSERACT_DIR.rglob("*"):
        if not f.is_file():
            continue
        rel_parent = f.parent.relative_to(TESSERACT_DIR)
        dest = str(Path("tesseract") / rel_parent)
        if f.suffix.lower() in (".exe", ".dll"):
            tesseract_binaries.append((str(f), dest))
        else:
            tesseract_datas.append((str(f), dest))

a = Analysis(
    ['hawk_scan/cli.py'],
    pathex=[],
    binaries=tesseract_binaries,
    datas=[
        ('fingerprints/default.yml', 'fingerprints'),
        ('hawk_scan/report/template.html', 'hawk_scan/report'),
        ('config.yml.sample', '.'),
    ] + tesseract_datas,
    hiddenimports=[
        'pypsrp',
        'pypsrp.powershell',
        'pypsrp.wsman',
        'winkerberos',
        'smbprotocol',
        'pytesseract',
        'PIL',
        'cv2',
        'numpy',
        'PyPDF2',
        'docx',
        'openpyxl',
        'pptx',
        'yaml',
        'rich',
        'jinja2',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=['runtime_hook_tesseract.py'],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='hawk_scan',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='hawk_scan.ico',
    version=version_info,
)
