# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['hawk_scan/cli.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('fingerprints/default.yml', 'fingerprints'),
        ('hawk_scan/report/template.html', 'hawk_scan/report'),
        ('config.yml.sample', '.'),
    ],
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
    runtime_hooks=[],
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
    [],
    exclude_binaries=True,
    name='hawk_scan',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='hawk_scan',
)
