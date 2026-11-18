# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    deploy/setup/setup_sut_windows.ps1 — One-time SUT setup for firmware validation (Windows SUT-only)

.DESCRIPTION
    Windows counterpart to deploy/setup/setup_sut.sh (which is Linux/bash-only and cannot run
    on Windows at all — it relies on apt-get/systemd/lsblk/efibootmgr).

    Unlike the Linux script, this does NOT need to install a background service, configure
    fstab, or set up a UEFI boot entry: each Windows *_sut_wins_func.py test that must
    survive a reboot (dTPM, fTPM/PTT, TME, PAVP) registers/removes its own Windows Task
    Scheduler resume task internally (schtasks /sc ONLOGON) — there is no global resume
    service to pre-install.

    So the ONLY one-time setup needed on Windows is the Python venv, created as a SIBLING
    directory of the repo (matching setup_sut.sh's "../venv" layout on Linux):

      1. Find Python 3.10+ (py launcher or python on PATH); if none, install Python 3.12
         (added to PATH) -- for ALL users when run as Administrator, else for this user only --
         via winget, or -- without winget -- from a python-3*-amd64.exe in Downloads\ or
         downloaded from python.org (signature-checked), then create the venv at ..\venv
         (skipped if it already exists — safe to re-run)
      2. Install requirements.txt into it (includes py7zr, which reads .7z archives)
      3. Stage the external tools from Downloads\ into Tools\ via deploy\tools\deploy_tools.py
         (e.g. SCEWIN_64.exe + amigendrv64.sys from the AMISCE SceWin.7z/.zip package).
         Coreinfo64.exe (AES-NI) is downloaded automatically (Coreinfo.zip from
         Sysinternals); the vendor/NDA packages must be in Downloads\ -- re-run once
         they are there (safe to re-run).
      4. Install OpenSSL for Windows (AES-NI test) and add its bin folder to the system
         PATH. Skipped when openssl is already on PATH. Version, link and SHA-256 are
         pinned in deploy\tools\download_links.xml (component OpenSSL_Windows). Without
         internet access, drop that .msi into Downloads\ first. Needs Administrator;
         without it this step is skipped with a warning.

    NOTE ON PER-TEST EXTRAS (not handled by this script, same as setup_sut.sh does NOT
    bake in test-specific .efi tool copying either — see doc/TEST_GUIDE.md instead):
      - RPMC, CSME UPID          : manually copy Meinfo.exe to the SUT, set win_meinfo_path
      - AES-NI                   : nothing (Coreinfo64.exe: step 3; OpenSSL: step 4)
      - dTPM, fTPM/PTT, TME, PAVP: no extra setup — Task Scheduler resume is automatic

.PARAMETER VenvDir
    Where to create the venv. Default: sibling "..\venv" of this repo (env override:
    SB_VENV_DIR).

.PARAMETER SkipOpenSSL
    Do not install OpenSSL (step 4), e.g. when the AES-NI test is not run on this SUT.

.EXAMPLE
    # Run in PowerShell, ON the Windows SUT, from inside the repo folder:
    .\deploy\setup\setup_sut_windows.ps1

.EXAMPLE
    # Then activate + run a test:
    ..\venv\Scripts\Activate.ps1
    python -m pytest tests\hdcp\test_ec62443_hdcp_sut_wins_func.py -v -s --setup-confirmed --yes

.NOTES
    Run it from an Administrator PowerShell: Python (step 1) is then installed for all users
    so `python` works for every account on the SUT, and step 4 (OpenSSL install + system
    PATH) is included. Without Administrator, Python is installed for the current user only
    and step 4 is skipped. Individual *_sut_wins_func.py tests may still need an elevated
    (Administrator) PowerShell to run (see each test's own docstring).
#>

[CmdletBinding()]
param(
    [string]$VenvDir = $(if ($env:SB_VENV_DIR) { $env:SB_VENV_DIR } else { $null }),
    [switch]$SkipOpenSSL
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# ------------------------------------------------------------------
# Pretty output helpers (matches deploy/secure_boot/enable_secure_boot_windows.ps1 style)
# ------------------------------------------------------------------
function Write-Ok     { param([string]$m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn   { param([string]$m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Fail   { param([string]$m) Write-Host "[FAIL] $m" -ForegroundColor Red; exit 1 }
function Write-Info   { param([string]$m) Write-Host "       $m" }
function Write-Action { param([string]$m) Write-Host "[ACTION] $m" -ForegroundColor Cyan }

# Returns the full path of a Python >= 3.10 interpreter, or $null.
# Probing the version also skips the WindowsApps "python.exe" Store stub.
function Find-SystemPython {
    $probe = 'import sys; sys.version_info >= (3, 10) and print(sys.executable)'
    $launchers = @(
        @{ Cmd = 'py';     Args = @('-3', '-c', $probe) },
        @{ Cmd = 'python'; Args = @('-c', $probe) }
    )
    foreach ($l in $launchers) {
        if (-not (Get-Command $l.Cmd -ErrorAction SilentlyContinue)) { continue }
        try { $exe = & $l.Cmd $l.Args 2>$null } catch { continue }
        if ($LASTEXITCODE -eq 0 -and $exe -and (Test-Path ([string]$exe).Trim())) {
            return ([string]$exe).Trim()
        }
    }
    return $null
}

# ------------------------------------------------------------------
# Derived paths
# ------------------------------------------------------------------
$RepoRoot = (Get-Location).Path
if (-not (Test-Path (Join-Path $RepoRoot 'requirements.txt'))) {
    Write-Fail "requirements.txt not found in $RepoRoot`n       Run this script from the repo root, e.g.:`n         cd edge-platform-security-toolsuite`n         .\deploy\setup\setup_sut_windows.ps1"
}

if (-not $VenvDir) {
    # Sibling directory of the repo -- same "../venv" layout setup_sut.sh uses on Linux.
    $VenvDir = Join-Path (Split-Path $RepoRoot -Parent) 'venv'
}
$Requirements = Join-Path $RepoRoot 'requirements.txt'
$PythonBin    = Join-Path $VenvDir 'Scripts\python.exe'

Write-Host "=============================================="
Write-Host " Firmware Validation -- Windows SUT One-Time Setup"
Write-Host "=============================================="
Write-Host ""

# ------------------------------------------------------------------
# Step 1 -- Create the venv (skip if it already exists, same as setup_sut.sh)
# ------------------------------------------------------------------
Write-Host "[1/4] Setting up Python venv..."

$SysPython = Find-SystemPython
if (-not $SysPython) {
    $PyVersion = '3.12.10'
    $IsAdmin   = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                     [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($IsAdmin) {
        $WingetScope   = 'machine'
        $InstallerArgs = '/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1'
        Write-Warn "Python 3.10+ not found on PATH -- installing it for all users..."
    }
    else {
        $WingetScope   = 'user'
        $InstallerArgs = '/quiet InstallAllUsers=0 PrependPath=1 Include_launcher=1 InstallLauncherAllUsers=0'
        Write-Warn "Python 3.10+ not found on PATH -- installing it for this user only (not Administrator)."
        Write-Info "Other accounts on this SUT will not get 'python'; re-run as Administrator to install for all users."
    }

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        winget install -e --id Python.Python.3.12 --scope $WingetScope --silent `
            --accept-package-agreements --accept-source-agreements --override $InstallerArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "winget exited with code $LASTEXITCODE -- checking whether Python is usable anyway..."
        }
    }
    else {
        # No winget (e.g. Windows Server/LTSC): use an installer from Downloads\ (offline SUT) or python.org
        $installer = Get-ChildItem (Join-Path $RepoRoot 'Downloads') -Filter 'python-3*-amd64.exe' -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending | Select-Object -First 1 -ExpandProperty FullName
        if ($installer) {
            Write-Info "winget not available -- using $installer"
        }
        else {
            $url       = "https://www.python.org/ftp/python/$PyVersion/python-$PyVersion-amd64.exe"
            $installer = Join-Path $env:TEMP "python-$PyVersion-amd64.exe"
            Write-Info "winget not available -- downloading $url"
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $oldProgress = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'   # PS 5.1 progress bar makes downloads very slow
            try {
                Invoke-WebRequest -Uri $url -OutFile $installer -UseBasicParsing
            }
            catch {
                Write-Fail "Download failed: $($_.Exception.Message)`n       Offline SUT? Copy python-$PyVersion-amd64.exe (from python.org) into Downloads\ and re-run."
            }
            finally {
                $ProgressPreference = $oldProgress
            }
        }

        $sig = Get-AuthenticodeSignature -FilePath $installer
        if ($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate -or
            $sig.SignerCertificate.Subject -notmatch 'Python Software Foundation') {
            Write-Fail "$installer is not validly signed by the Python Software Foundation (status: $($sig.Status)) -- refusing to run it."
        }

        Write-Info "Running Python installer silently (this can take a minute)..."
        $proc = Start-Process -FilePath $installer -ArgumentList $InstallerArgs -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            Write-Warn "Python installer exited with code $($proc.ExitCode) -- checking whether Python is usable anyway..."
        }
    }

    # Pick up the PATH entries the installer just added, without needing a new shell
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [Environment]::GetEnvironmentVariable('Path', 'User')
    $SysPython = Find-SystemPython
    if (-not $SysPython) {
        $SysPython = @(
            Get-ChildItem $env:ProgramFiles -Directory -Filter 'Python3*' -ErrorAction SilentlyContinue
            Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Programs\Python') -Directory -Filter 'Python3*' -ErrorAction SilentlyContinue
        ) | ForEach-Object { Join-Path $_.FullName 'python.exe' } | Where-Object { Test-Path $_ } |
            Sort-Object -Descending | Select-Object -First 1
    }
    if (-not $SysPython) {
        Write-Fail "Python install did not produce a usable interpreter. Install Python 3.10+ manually`n       (https://www.python.org/downloads/windows/, tick 'Add python.exe to PATH'), then re-run."
    }
    Write-Ok "Python installed: $SysPython"
    Write-Info "Open a NEW PowerShell window for 'python' to be found there."
}
else {
    Write-Ok "Python found: $SysPython"
}

if (-not (Test-Path $VenvDir)) {
    & $SysPython -m venv $VenvDir
    if (-not (Test-Path $PythonBin)) {
        Write-Fail "venv creation appears to have failed -- $PythonBin not found."
    }
    Write-Ok "venv created: $VenvDir"
}
else {
    Write-Ok "venv already exists: $VenvDir"
    if (-not (Test-Path $PythonBin)) {
        Write-Fail "$VenvDir exists but $PythonBin is missing -- delete $VenvDir and re-run."
    }
}

# ------------------------------------------------------------------
# Step 2 -- Install requirements.txt (via the venv's own python -- no
# activation needed, matches the full-path style used in doc/TEST_GUIDE.md
# and by fw-validation-resume.service on the Linux side)
# ------------------------------------------------------------------
Write-Host "[2/4] Installing requirements..."

# pip ignores the Windows auto-detected (WPAD/PAC) proxy that PowerShell uses, so hand it over explicitly
if (-not $env:HTTPS_PROXY) {
    $sysProxy = [System.Net.WebRequest]::GetSystemWebProxy().GetProxy('https://pypi.org/')
    if ($sysProxy.Authority -ne 'pypi.org') {
        $env:HTTPS_PROXY = $sysProxy.AbsoluteUri
        $env:HTTP_PROXY  = $sysProxy.AbsoluteUri
        Write-Info "Using system proxy for pip: $($sysProxy.AbsoluteUri)"
    }
}

& $PythonBin -m pip install -q -r $Requirements
if ($LASTEXITCODE -ne 0) {
    Write-Fail "pip install failed (exit $LASTEXITCODE) -- see output above."
}
Write-Ok "Requirements installed from $Requirements"

# ------------------------------------------------------------------
# Step 3 -- Stage external tools (Downloads\ -> Tools\) with the venv's python so
# py7zr (installed above) can open the .7z vendor archives such as SceWin.7z.
# ------------------------------------------------------------------
Write-Host "[3/4] Staging external tools (deploy\tools\deploy_tools.py)..."

$DeployToolsPy = Join-Path $RepoRoot 'deploy\tools\deploy_tools.py'
$DownloadsDir  = Join-Path $RepoRoot 'Downloads'
$ToolsStatus   = 'skipped'
$DeployArgs    = @()

if ([Console]::IsInputRedirected) {
    # No one can answer the retry/skip prompts: never hang on them. Still run it with
    # an empty Downloads\, so the auto-download tools (Coreinfo) are fetched and staged.
    $DeployArgs = @('--yes')
}

& $PythonBin $DeployToolsPy @DeployArgs
if ($LASTEXITCODE -eq 0) {
    $ToolsStatus = 'staged'
    Write-Ok "External tools staged into Tools\ (see logs\deploy_tools_*.log for details)"
}
else {
    $ToolsStatus = 'partial'
    Write-Warn "External tools: some were missing/skipped -- see logs\deploy_tools_*.log"
}
if ($ToolsStatus -ne 'staged') {
    Write-Info "Get the missing tools from doc\DEPENDENCIES.md into Downloads\ (for AMISCE on an"
    Write-Info "AMI BIOS: copy the whole SceWin.7z there), then re-run:"
    Write-Info "  $PythonBin deploy\tools\deploy_tools.py"
}

# ------------------------------------------------------------------
# Step 4 -- OpenSSL for Windows (AES-NI test). The pinned MSI wraps the
# Shining Light Inno Setup installer, which installs to its default folder
# (C:\Program Files\OpenSSL-Win64); the folder is read back afterwards.
# ------------------------------------------------------------------
Write-Host "[4/4] OpenSSL for Windows (AES-NI test)..."

$LinksXml      = Join-Path $RepoRoot 'deploy\tools\download_links.xml'
$OpenSslStatus = 'skipped'
$OpenSslInfo   = ''

function Find-OpenSslExe {
    $onPath = Get-Command openssl.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($onPath) { return @{ Exe = $onPath.Source; OnPath = $true } }

    $candidates = @()
    $uninstallKeys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($entry in (Get-ItemProperty $uninstallKeys -ErrorAction SilentlyContinue)) {
        $props = $entry.PSObject.Properties
        if (-not ($props['DisplayName'] -and "$($entry.DisplayName)" -like 'OpenSSL*')) { continue }
        foreach ($name in 'InstallLocation', 'Inno Setup: App Path') {
            if ($props[$name] -and "$($props[$name].Value)") {
                $candidates += Join-Path $props[$name].Value 'bin\openssl.exe'
            }
        }
    }
    $candidates += Join-Path $env:ProgramFiles 'OpenSSL-Win64\bin\openssl.exe'
    $candidates += 'C:\OpenSSL-Win64\bin\openssl.exe'
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return @{ Exe = $c; OnPath = $false } }
    }
    return $null
}

function Add-ToMachinePath {
    param([string]$Dir)
    # Edit the registry value directly (kept as REG_EXPAND_SZ) -- the .NET
    # SetEnvironmentVariable(..., 'Machine') call rewrites it as REG_SZ, which
    # breaks %SystemRoot%-style entries already in the system PATH.
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment', $true)
    try {
        $current = $key.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $parts = @($current -split ';' | Where-Object { $_ })
        if (-not ($parts | Where-Object { $_.TrimEnd('\') -ieq $Dir.TrimEnd('\') })) {
            $key.SetValue('Path', (($parts + $Dir) -join ';'), [Microsoft.Win32.RegistryValueKind]::ExpandString)
        }
    }
    finally {
        $key.Close()
    }
    if (-not (($env:Path -split ';') | Where-Object { $_.TrimEnd('\') -ieq $Dir.TrimEnd('\') })) {
        $env:Path = "$env:Path;$Dir"
    }
    # Tell Explorer the environment changed, so newly opened shells see the new PATH.
    if (-not ('FwValidation.EnvBroadcast' -as [type])) {
        Add-Type -Namespace FwValidation -Name EnvBroadcast -MemberDefinition @'
[DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint Msg, UIntPtr wParam,
    string lParam, uint fuFlags, uint uTimeout, out UIntPtr lpdwResult);
'@
    }
    $result = [UIntPtr]::Zero
    [void][FwValidation.EnvBroadcast]::SendMessageTimeout(
        [IntPtr]0xffff, 0x1A, [UIntPtr]::Zero, 'Environment', 2, 5000, [ref]$result)
}

$found = Find-OpenSslExe
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($SkipOpenSSL) {
    Write-Warn "OpenSSL: skipped (-SkipOpenSSL)."
    $OpenSslStatus = 'skipped_user'
}
elseif ($found -and $found.OnPath) {
    $OpenSslInfo = "$(& $found.Exe version 2>&1) ($($found.Exe))"
    Write-Ok "OpenSSL already on PATH: $OpenSslInfo"
    $OpenSslStatus = 'present'
}
elseif (-not $isAdmin) {
    Write-Warn "OpenSSL: not on PATH, and this PowerShell is not Administrator -- skipped."
    Write-Info "Re-run this script from an Administrator PowerShell to install it."
    $OpenSslStatus = 'skipped_admin'
}
else {
    try {
        if (-not $found) {
            $linkNode = ([xml](Get-Content -LiteralPath $LinksXml -Raw)).SelectSingleNode(
                "/downloads/component[@name='OpenSSL_Windows']/link")
            if (-not $linkNode) { throw "component OpenSSL_Windows not found in $LinksXml" }
            $msiUrl    = $linkNode.InnerText.Trim()
            $msiSha256 = $linkNode.GetAttribute('sha256').Trim()
            $msiName   = Split-Path $msiUrl -Leaf
            $msiPath   = Join-Path $DownloadsDir $msiName

            if (-not (Test-Path -LiteralPath $msiPath)) {
                $localMsi = Get-ChildItem -LiteralPath $DownloadsDir -Filter 'Win64OpenSSL*.msi' -File -ErrorAction SilentlyContinue |
                    Select-Object -First 1
                if ($localMsi) {
                    Write-Warn "Using $($localMsi.Name) from Downloads\ -- not the pinned $msiName, so its SHA-256 is not checked."
                    $msiPath   = $localMsi.FullName
                    $msiSha256 = ''
                }
                else {
                    Write-Info "Downloading $msiUrl ..."
                    New-Item -ItemType Directory -Path $DownloadsDir -Force | Out-Null
                    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
                    $partPath = "$msiPath.part"
                    $ProgressPreference = 'SilentlyContinue'
                    Invoke-WebRequest -Uri $msiUrl -OutFile $partPath -UseBasicParsing -TimeoutSec 300
                    Move-Item -LiteralPath $partPath -Destination $msiPath -Force
                }
            }

            if ($msiSha256) {
                $actual = (Get-FileHash -LiteralPath $msiPath -Algorithm SHA256).Hash
                if ($actual -ne $msiSha256) {
                    Remove-Item -LiteralPath $msiPath -Force
                    throw "SHA-256 mismatch for $msiName (expected $msiSha256, got $actual) -- file deleted"
                }
                Write-Ok "SHA-256 verified: $msiName"
            }

            $LogsDir = Join-Path $RepoRoot 'logs'
            New-Item -ItemType Directory -Path $LogsDir -Force | Out-Null
            $msiLog = Join-Path $LogsDir ("openssl_install_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            Write-Info "Installing $(Split-Path $msiPath -Leaf) (silent; log: $msiLog) ..."
            $proc = Start-Process -FilePath 'msiexec.exe' -Wait -PassThru -ArgumentList @(
                '/i', "`"$msiPath`"", '/qn', '/norestart', '/l*v', "`"$msiLog`"")
            # 3010 = success, reboot required; 1638 = another version is already installed.
            if ($proc.ExitCode -notin 0, 3010, 1638) {
                throw "msiexec exited with $($proc.ExitCode) -- see $msiLog"
            }
            $found = Find-OpenSslExe
            if (-not $found) { throw "installer finished but openssl.exe was not found -- see $msiLog" }
        }

        $binDir = Split-Path $found.Exe -Parent
        Add-ToMachinePath -Dir $binDir
        Write-Ok "Added to system PATH: $binDir"

        $OpenSslInfo = "$(& $found.Exe version 2>&1)"
        if ($LASTEXITCODE -ne 0) { throw "'$($found.Exe) version' failed: $OpenSslInfo" }
        $OpenSslInfo = "$OpenSslInfo ($($found.Exe))"
        Write-Ok "OpenSSL ready: $OpenSslInfo"
        $OpenSslStatus = 'installed'
    }
    catch {
        Write-Warn "OpenSSL install failed: $($_.Exception.Message)"
        Write-Info "Install it by hand from https://slproweb.com/products/Win32OpenSSL.html and add"
        Write-Info "its bin folder to the system PATH, or fix the cause and re-run this script."
        $OpenSslStatus = 'failed'
    }
}

# ------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------
Write-Host ""
Write-Host "=============================================="
Write-Host " Setup Complete"
Write-Host "=============================================="
Write-Host ""
Write-Ok "Python venv : $VenvDir"
switch ($ToolsStatus) {
    'staged'  { Write-Ok   "External tools: staged from Downloads\ into Tools\" }
    default   { Write-Warn "External tools: some missing/skipped -- see logs\deploy_tools_*.log" }
}
switch ($OpenSslStatus) {
    'present'       { Write-Ok   "OpenSSL       : $OpenSslInfo" }
    'installed'     { Write-Ok   "OpenSSL       : installed, $OpenSslInfo (new shells see the PATH change)" }
    'skipped_user'  { Write-Warn "OpenSSL       : skipped (-SkipOpenSSL)" }
    'skipped_admin' { Write-Warn "OpenSSL       : NOT installed -- re-run from an Administrator PowerShell" }
    default         { Write-Warn "OpenSSL       : install FAILED -- see the warning above" }
}
Write-Host ""
Write-Host "Next steps:"
Write-Info "1. Run the tests from this folder (Administrator PowerShell; no venv activation needed):"
Write-Info "     python test_runner.py"
Write-Info "   Pick the tests; the pre-flight then sets the BIOS knobs and Secure Boot they need"
Write-Info "   (AMI BIOS: AMISCE; other BIOS: list + reboot into BIOS Setup) and runs the tests."
Write-Info ""
Write-Info "2. Some tests need extra per-test setup (see doc/TEST_GUIDE.md / each test's"
Write-Info "   own docstring) -- e.g. copying Meinfo.exe (RPMC, CSME UPID). Most tests need"
Write-Info "   none of this."
Write-Info ""
Write-Info "3. Direct pytest instead (no pre-flight; venv activated with $VenvDir\Scripts\Activate.ps1):"
Write-Info "     python -m pytest tests\hdcp\test_ec62443_hdcp_sut_wins_func.py \"
Write-Info "         -v -s --setup-confirmed --yes"
Write-Host ""
