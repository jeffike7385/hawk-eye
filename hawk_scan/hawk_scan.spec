# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path

block_cipher = None

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
        'winrm',
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
    icon=None,
)
