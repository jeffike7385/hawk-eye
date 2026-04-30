# Build + sign hawk_scan.exe (onefile, Tesseract bundled).
# Run from the hawk_scan/ directory.
#
# Usage:
#   .\build.ps1                                  # auto-find cert by EKU + expiration 2028-04-18
#   .\build.ps1 -Thumbprint <SHA1>               # explicit cert thumbprint
#   .\build.ps1 -SkipSign                        # build only

[CmdletBinding()]
param(
    [string]$Thumbprint,
    [string]$CertExpiry = "2028-04-18",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [switch]$SkipSign,
    [switch]$SkipTesseractDownload
)

$ErrorActionPreference = "Stop"
$ScriptRoot = $PSScriptRoot

# --- 1. Vendor Tesseract -----------------------------------------------------
$TessDir = Join-Path $ScriptRoot "vendor\tesseract"
if (-not (Test-Path (Join-Path $TessDir "tesseract.exe"))) {
    # Reuse any existing system install — avoids the NSIS uninstall-prompt loop
    # that triggers when the installer detects a prior install.
    $existingTess = @(
        "$env:ProgramFiles\Tesseract-OCR\tesseract.exe",
        "${env:ProgramFiles(x86)}\Tesseract-OCR\tesseract.exe"
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if ($existingTess) {
        $existingDir = Split-Path $existingTess -Parent
        Write-Host "==> Found existing Tesseract at $existingDir — copying to vendor"
        New-Item -ItemType Directory -Force -Path $TessDir | Out-Null
        robocopy $existingDir $TessDir /E /NFL /NDL /NJH /NJS /NP | Out-Null
        if ($LASTEXITCODE -ge 8) { throw "robocopy failed (exit $LASTEXITCODE)" }
        if (-not (Test-Path (Join-Path $TessDir "tesseract.exe"))) {
            throw "tesseract.exe missing after copy from $existingDir"
        }
    } elseif (-not $SkipTesseractDownload) {
    Write-Host "==> Resolving latest Tesseract w64 installer (tesseract-ocr/tesseract)..."
    $apiHeaders = @{ "User-Agent" = "hawk-scan-build" }
    $releases = Invoke-RestMethod -Uri "https://api.github.com/repos/tesseract-ocr/tesseract/releases" -Headers $apiHeaders -UseBasicParsing
    # Releases are returned newest-first. Pick the first one that actually ships a w64 installer
    # (recent releases sometimes publish source-only with no assets).
    $TessUrl = $null
    foreach ($rel in $releases) {
        $asset = $rel.assets | Where-Object { $_.name -like "tesseract-ocr-w64-setup-*.exe" } | Select-Object -First 1
        if ($asset) {
            Write-Host "    Release: $($rel.tag_name)"
            $TessUrl = $asset.browser_download_url
            break
        }
    }
    if (-not $TessUrl) { throw "Could not resolve Tesseract w64 installer URL from GitHub API" }
    Write-Host "    URL: $TessUrl"
    $TessInstaller = Join-Path $env:TEMP "tesseract-installer.exe"
    Invoke-WebRequest -Uri $TessUrl -OutFile $TessInstaller -Headers $apiHeaders -UseBasicParsing
    # NSIS /D= requires an unquoted path with no spaces (and must be the LAST arg).
    # The repo path has a space, so stage into a no-space temp dir then copy over.
    $StageDir = Join-Path $env:TEMP "hawk-scan-tess-stage"
    if (Test-Path $StageDir) { Remove-Item -Recurse -Force $StageDir }
    Write-Host "==> Installing Tesseract to staging: $StageDir"
    # Build a single command line so /D= remains unquoted (NSIS requirement).
    $cmdLine = "`"$TessInstaller`" /S /D=$StageDir"
    $proc = Start-Process -FilePath "cmd.exe" -ArgumentList "/c",$cmdLine -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        Write-Warning "Tesseract installer exit code: $($proc.ExitCode) (continuing — NSIS often returns nonzero)"
    }
    if (-not (Test-Path (Join-Path $StageDir "tesseract.exe"))) {
        throw "Tesseract extraction failed — tesseract.exe not found in $StageDir. Try running PowerShell as Administrator."
    }
    Write-Host "==> Copying staged Tesseract to $TessDir"
    New-Item -ItemType Directory -Force -Path $TessDir | Out-Null
    robocopy $StageDir $TessDir /E /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw "robocopy failed (exit $LASTEXITCODE)" }
    Remove-Item -Recurse -Force $StageDir -ErrorAction SilentlyContinue
    if (-not (Test-Path (Join-Path $TessDir "tesseract.exe"))) {
        throw "tesseract.exe missing after copy to $TessDir"
    }
    } else {
        throw "Tesseract not found and -SkipTesseractDownload set."
    }
}

# --- 2. PyInstaller build ----------------------------------------------------
Write-Host "==> Locating Python..."
function Find-Python {
    # Skip the Microsoft Store stub in WindowsApps. Prefer real installs.
    $candidates = @(
        "$env:LOCALAPPDATA\Programs\Python\Python313\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe",
        "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe",
        "$env:ProgramFiles\Python313\python.exe",
        "$env:ProgramFiles\Python312\python.exe",
        "$env:ProgramFiles\Python311\python.exe",
        "${env:ProgramFiles(x86)}\Python313\python.exe",
        "${env:ProgramFiles(x86)}\Python312\python.exe",
        "${env:ProgramFiles(x86)}\Python311\python.exe"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    # Try py launcher last
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        # Resolve py -3 to its actual python.exe
        $resolved = & py -3 -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $resolved) { return $resolved.Trim() }
    }
    return $null
}

$PyExe = Find-Python
if (-not $PyExe) {
    throw @"
Python 3.11+ not found. Install via:
    winget install Python.Python.3.12 -e --source winget
Then close + reopen PowerShell and re-run this script.
(Note: the 'python'/'python3' on PATH is a Microsoft Store stub, not a usable interpreter.)
"@
}
Write-Host "==> Using Python: $PyExe"

Write-Host "==> Ensuring project + dev deps are installed..."
# Run pip from the script dir (where pyproject.toml lives) so '-e .' resolves correctly.
Push-Location $ScriptRoot
try {
    & $PyExe -m pip install --upgrade pip --quiet
    & $PyExe -m pip install -e ".[dev]"
    if ($LASTEXITCODE -ne 0) { throw "pip install -e .[dev] failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

# Sanity check: make sure all hiddenimports in the spec actually import.
Write-Host "==> Verifying critical imports..."
$importCheck = @"
import sys
mods = ['winrm','smbprotocol','pytesseract','PIL','cv2','numpy','PyPDF2','docx','openpyxl','pptx','yaml','rich','jinja2','PyInstaller']
failed = []
for m in mods:
    try:
        __import__(m)
    except Exception as e:
        failed.append(f'{m}: {e}')
if failed:
    print('MISSING:', '; '.join(failed))
    sys.exit(1)
print('all imports OK')
"@
& $PyExe -c $importCheck
if ($LASTEXITCODE -ne 0) { throw "Required Python modules failed to import. Fix the above errors and rerun." }

Write-Host "==> Running PyInstaller..."
Remove-Item -Recurse -Force (Join-Path $ScriptRoot "build"),(Join-Path $ScriptRoot "dist") -ErrorAction SilentlyContinue
Push-Location $ScriptRoot
try {
    & $PyExe -m PyInstaller --clean --noconfirm "hawk_scan.spec"
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

$ExePath = Join-Path $ScriptRoot "dist\hawk_scan.exe"
if (-not (Test-Path $ExePath)) { throw "Build did not produce $ExePath" }
Write-Host "==> Built: $ExePath ($([math]::Round((Get-Item $ExePath).Length / 1MB, 1)) MB)"

# --- 3. Sign -----------------------------------------------------------------
if ($SkipSign) {
    Write-Host "==> Skipping signing (--SkipSign)"
    return
}

if (-not $Thumbprint) {
    Write-Host "==> Searching CurrentUser\My for code-signing cert expiring $CertExpiry..."
    $expiryDate = [datetime]::Parse($CertExpiry)
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object {
        ($_.EnhancedKeyUsageList.ObjectId -contains '1.3.6.1.5.5.7.3.3') -and
        ($_.NotAfter.Date -eq $expiryDate.Date)
    } | Select-Object -First 1
    if (-not $cert) {
        throw "No code-signing cert found in CurrentUser\My with NotAfter=$CertExpiry. Pass -Thumbprint explicitly."
    }
    $Thumbprint = $cert.Thumbprint
    Write-Host "    Found: $($cert.Subject)"
    Write-Host "    Thumbprint: $Thumbprint"
}

$SignTool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.22621.0\x64\signtool.exe"
if (-not (Test-Path $SignTool)) {
    $SignTool = (Get-ChildItem "C:\Program Files (x86)\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
                 Sort-Object FullName -Descending | Select-Object -First 1).FullName
    if (-not $SignTool) { throw "signtool.exe not found. Install the Windows 10/11 SDK." }
}

Write-Host "==> Signing with $SignTool"
& $SignTool sign /sha1 $Thumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 $ExePath
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed (exit $LASTEXITCODE)" }

Write-Host "==> Verifying signature"
& $SignTool verify /pa /v $ExePath
if ($LASTEXITCODE -ne 0) { throw "signtool verify failed (exit $LASTEXITCODE)" }

Write-Host ""
Write-Host "==> DONE: $ExePath"
