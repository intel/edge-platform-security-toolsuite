# Copyright 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

<#
.SYNOPSIS
    deploy/secure_boot/enable_secure_boot_windows.ps1 — Enable UEFI Secure Boot on a Windows SUT (runbook)

.DESCRIPTION
    PROVISIONING runbook, NOT a test. It CHANGES firmware/key state: it stages
    the test Secure Boot policy on the EFI System Partition and runs the WDK
    'EnableUefiSbTest' tool to enroll PK/KEK/DB/DBx, which turns Secure Boot ON.
    It mirrors the Windows "Enable UEFI Secure Boot" procedure step-by-step.

    Stage-based and re-runnable — run one stage, do the reboot / manual BIOS
    action it prints, then run the next stage. No hidden state file.

      provision   Mount the ESP, copy SecureBootPolicy.p7b to
                  X:\EFI\Microsoft\Boot, dump keys (expected empty), run
                  EnableUefiSbTest to enroll keys, then AUTO-REBOOT.
      verify      Dump keys and run Confirm-SecureBootUEFI (expects True).
      auto        One command for both (test_runner.py pre-flight runs it):
                  picks the next stage and installs a Scheduled Task
                  (SecureBootAutoResume, at boot as SYSTEM -- no sign-in needed) so
                  'verify' runs by itself after the reboot; the task removes itself
                  at the end or on failure.

    PRE-REQUIRED (software):
      * Install the Windows Driver Kit (WDK) — Visual Studio is installed as part
        of the WDK setup. Latest WDK:
        https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk
      * The WDK ships the two files this runbook needs under:
          C:\Program Files (x86)\Windows Kits\10\Tools\amd64\SecureBoot
            \EnableSB\EnableUefiSbTest_amd64.exe
            \Policies\SecureBootPolicyPreproduction.p7b   (copied + renamed to
                                                            SecureBootPolicy.p7b)

    This script auto-discovers those files under the WDK path. If the WDK is not
    installed here, drop the two files into -WorkDir yourself:
        <WorkDir>\EnableUefiSbTest_amd64.exe
        <WorkDir>\SecureBootPolicy.p7b

.PARAMETER Stage
    auto | provision | verify | status | help

.EXAMPLE
    # Run in an ELEVATED (Administrator) PowerShell, ON the SUT:
    .\deploy\secure_boot\enable_secure_boot_windows.ps1 auto
    #   ... AUTO-REBOOT; 'verify' runs by itself at the next boot (no sign-in needed) ...

.EXAMPLE
    # Run in an ELEVATED (Administrator) PowerShell, ON the SUT:
    .\deploy\secure_boot\enable_secure_boot_windows.ps1 provision
    #   ... AUTO-REBOOT; then enter BIOS and confirm Secure Boot = Enabled ...
    .\deploy\secure_boot\enable_secure_boot_windows.ps1 verify

.NOTES
    Auto-reboot: set -NoReboot to skip it; -RebootDelay N sets the countdown.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('provision', 'verify', 'status', 'auto', 'help')]
    [string]$Stage = 'help',

    # Where the WDK SecureBoot tools live (auto-discovered; override if needed).
    [string]$WdkSecureBootDir = $(if ($env:WDK_SECUREBOOT_DIR) { $env:WDK_SECUREBOOT_DIR } else { 'C:\Program Files (x86)\Windows Kits\10\Tools\amd64\SecureBoot' }),

    # Local working dir that holds the staged .exe and .p7b.
    [string]$WorkDir = $(if ($env:SB_WORKDIR) { $env:SB_WORKDIR } else { 'C:\SecureBootTest' }),

    # Drive letter used to mount the EFI System Partition.
    [string]$MountLetter = $(if ($env:SB_MOUNT_LETTER) { $env:SB_MOUNT_LETTER } else { 'X' }),

    # Auto-reboot controls (provision stage only).
    [switch]$NoReboot,
    [int]$RebootDelay = $(if ($env:REBOOT_DELAY) { [int]$env:REBOOT_DELAY } else { 10 })
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Resolve this script's own path (used to install the at-logon reminder task).
$ScriptPath = $PSCommandPath
if (-not $ScriptPath) { $ScriptPath = $MyInvocation.MyCommand.Path }

# ------------------------------------------------------------------
# Derived paths
# ------------------------------------------------------------------
$ToolExeName   = 'EnableUefiSbTest.exe'
$PolicyName    = 'SecureBootPolicy.p7b'                 # target name on the ESP
$WdkPolicySrc  = 'Policies\SecureBootPolicyPreproduction.p7b'
$WdkEnableSrc  = "EnableSB\$ToolExeName"
$WdkDownloadUrl = 'https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk'

$ToolExe       = Join-Path $WorkDir $ToolExeName
$PolicyFile    = Join-Path $WorkDir $PolicyName
$MountRoot     = "$MountLetter`:"
# NOTE: built with string concatenation, not Join-Path -- Join-Path validates
# that the drive exists, but $MountRoot (e.g. "X:") isn't mounted until
# Mount-Esp runs later, which would make this throw "Cannot find drive" here.
$EspBootDir    = "$MountRoot\EFI\Microsoft\Boot"
$EspPolicy     = "$EspBootDir\$PolicyName"
$ProgressFile  = Join-Path $WorkDir '.progress'
$LogonTaskName = 'SecureBootProgressReminder'
# 'auto' stage: task that continues at the next boot (as SYSTEM, no sign-in), removed when done or on failure.
$AutoTaskName  = 'SecureBootAutoResume'
$RepoRoot      = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $ScriptPath))   # deploy\secure_boot\ -> repo
$AutoLog       = Join-Path $RepoRoot 'logs\enable_secure_boot_windows_auto.log'
$BiosKnobState = Join-Path $(if ($env:ProgramData) { $env:ProgramData } else { 'C:\ProgramData' }) 'fw-validation\bios_knob\state.json'
# test_runner.py pre-flight plan; when it exists, 'auto' reports to the chain script.
$PreflightPlan  = Join-Path $RepoRoot 'logs\preflight_plan.json'
$PreflightChain = Join-Path $RepoRoot 'deploy\preflight\preflight_chain.py'
$script:AutoMode = $false

# ------------------------------------------------------------------
# Pretty output helpers
# ------------------------------------------------------------------
function Write-Ok     { param([string]$m) Write-Host "[OK]   $m" -ForegroundColor Green }
function Write-Warn   { param([string]$m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Info   { param([string]$m) Write-Host "       $m" }
function Write-Action { param([string]$m) Write-Host "[ACTION] $m" -ForegroundColor Cyan }
function Fail {
    param([string]$m)
    Write-Host "[FAIL] $m" -ForegroundColor Red
    if ($script:AutoMode) {
        Remove-AutoResumeTask
        Write-Info 'Fix the error above, then run:  .\deploy\secure_boot\enable_secure_boot_windows.ps1 auto'
        Report-Preflight -Result 'fail' -Detail $m
    }
    exit 1
}

function Require-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Fail "Run in an ELEVATED PowerShell (Right-click -> 'Run as administrator')."
    }
    # 'auto' installs its own logon task instead of the status reminder.
    if (-not $script:AutoMode) { Install-LogonReminder }
}

# ------------------------------------------------------------------
# Boot-state / Secure Boot capability helpers
# ------------------------------------------------------------------
function Get-FirmwareType {
    try {
        $info = Get-ComputerInfo -Property BiosFirmwareType -ErrorAction Stop
        return [string]$info.BiosFirmwareType
    }
    catch {
        return 'Unknown'
    }
}

function Get-SecureBootVarState {
    param([string]$Name)
    try {
        $v = Get-SecureBootUEFI -Name $Name -ErrorAction Stop
        if ($v.Bytes.Count -gt 0) { return [int]$v.Bytes[0] }
        return $null
    }
    catch {
        return $null
    }
}

# Print a short summary of the currently running boot configuration so the
# operator always knows what's active before a stage runs (or fails) — mirrors
# describe_boot() in the Linux enable_secure_boot.sh.
function Show-BootState {
    $fw = Get-FirmwareType
    $sbEnabled = $null
    try { $sbEnabled = Confirm-SecureBootUEFI -ErrorAction Stop } catch { $sbEnabled = $null }
    $setupModeVal = Get-SecureBootVarState -Name 'SetupMode'
    $pkExists = $false
    try { Get-SecureBootUEFI -Name 'PK' -ErrorAction Stop | Out-Null; $pkExists = $true } catch { $pkExists = $false }

    Write-Host '--- Current boot state -----------------------------------------------'
    Write-Info ("Firmware mode  : {0}" -f $fw)
    Write-Info ("Secure Boot    : {0}" -f $(if ($null -eq $sbEnabled) { 'unknown/unsupported' } else { $sbEnabled }))
    Write-Info ("Setup Mode     : {0}" -f $(
        if ($null -eq $setupModeVal) { 'unknown' }
        elseif ($setupModeVal -eq 1) { 'yes (no PK enrolled)' }
        else { 'no (PK present)' }
    ))
    Write-Info ("PK enrolled    : {0}" -f $(if ($pkExists) { 'yes' } else { 'no' }))
    Write-Host '------------------------------------------------------------------------'
}

# EnableUefiSbTest / Confirm-SecureBootUEFI need a genuine UEFI boot with
# Secure Boot variables exposed. Fail fast with a clear message instead of a
# confusing cmdlet error deep inside a stage — mirrors require_efivars() in
# the Linux enable_secure_boot.sh.
function Require-SecureBootCapable {
    $fw = Get-FirmwareType
    if ($fw -ne 'Uefi') {
        Fail "Firmware is '$fw', not UEFI. Secure Boot enrollment requires a UEFI boot`n       (not Legacy/CSM/BIOS). Re-install/boot Windows in UEFI mode, then re-run."
    }
    try {
        Confirm-SecureBootUEFI -ErrorAction Stop | Out-Null
    }
    catch {
        Fail "Confirm-SecureBootUEFI failed: $($_.Exception.Message)`n       The firmware does not expose Secure Boot variables to Windows -- check BIOS Secure Boot settings."
    }
}

# ------------------------------------------------------------------
# Progress breadcrumb — mirrors record_progress()/show_progress() in the
# Linux enable_secure_boot.sh so the operator can tell what was already done
# after a reboot. Convenience only: stages remain safe to re-run without it.
# ------------------------------------------------------------------
function Record-Progress {
    param([string]$StageName)
    if (-not (Test-Path $WorkDir)) { New-Item -ItemType Directory -Path $WorkDir | Out-Null }
    "$StageName $(Get-Date -Format o)" | Add-Content -Path $ProgressFile
}

function Show-Progress {
    Write-Host '--- Secure Boot progress ------------------------------------------------'
    if (-not (Test-Path $ProgressFile)) {
        Write-Info "No stage recorded yet on this SUT -- start with:  .\deploy\secure_boot\enable_secure_boot_windows.ps1 provision"
    }
    else {
        $last = Get-Content $ProgressFile -Tail 1
        $parts = $last -split ' ', 2
        $lastStage = $parts[0]
        $lastTime = if ($parts.Count -gt 1) { $parts[1] } else { 'unknown time' }
        Write-Info "Last completed stage : $lastStage  ($lastTime)"
        switch ($lastStage) {
            'provision' { Write-Info 'NEXT: .\deploy\secure_boot\enable_secure_boot_windows.ps1 verify' }
            'verify'    { Write-Info 'All stages recorded complete -- Secure Boot should be enabled.' }
            default     { Write-Info "Unrecognized stage in $ProgressFile -- re-check manually." }
        }
    }
    if (Get-ScheduledTask -TaskName $AutoTaskName -ErrorAction SilentlyContinue) {
        Write-Info "Auto-resume is ON (Scheduled Task '$AutoTaskName'): the next stage runs at the next boot (no sign-in needed)."
        Write-Info "Progress log: $AutoLog"
    }
    else {
        Write-Info 'Or let the script pick the next stage:  .\deploy\secure_boot\enable_secure_boot_windows.ps1 auto'
    }
    Write-Host '------------------------------------------------------------------------'
}

# Install a Scheduled Task that shows the boot-state + progress banner at the
# next logon — the Windows equivalent of the /etc/update-motd.d hook on the
# Linux side, so the operator doesn't have to remember to run 'status' after
# the manual reboot. Idempotent: re-registering replaces the existing task.
# Fires at the logon of ANY local administrator (e.g. Administrator or Local_Admin), not only the
# account that started the run. S-1-5-32-544 = BUILTIN\Administrators on every Windows language.
function New-AdminLogonPrincipal {
    return New-ScheduledTaskPrincipal -GroupId 'S-1-5-32-544' -RunLevel Highest
}

function Install-LogonReminder {
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
            -Argument "-NoExit -NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" status"
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-AdminLogonPrincipal
        Unregister-ScheduledTask -TaskName $LogonTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Register-ScheduledTask -TaskName $LogonTaskName -Action $action -Trigger $trigger -Principal $principal `
            -Description 'Shows Secure Boot provisioning progress at logon (installed by enable_secure_boot_windows.ps1).' `
            -ErrorAction Stop | Out-Null
        Write-Ok "Logon reminder installed (Scheduled Task '$LogonTaskName') -- shows progress at next logon."
    }
    catch {
        Write-Warn "Could not install logon reminder scheduled task: $($_.Exception.Message)"
    }
}

# Reboot with a cancellable countdown (Ctrl+C aborts before it fires).
function Invoke-AutoReboot {
    param([string]$NextCmd)
    if ($NoReboot) {
        Write-Action "-NoReboot set — reboot manually, then run:  .\deploy\secure_boot\enable_secure_boot_windows.ps1 $NextCmd"
        return
    }
    Write-Host ''
    Write-Action "Rebooting in $RebootDelay s to continue (Ctrl+C to cancel)."
    if ($script:AutoMode) {
        Write-Info "After the reboot this continues by itself -- no sign-in needed (Scheduled Task '$AutoTaskName')."
        Write-Info "Progress: $AutoLog (the status window opens when an administrator signs in)."
    }
    else {
        Write-Info   "After reboot, enter BIOS and confirm Secure Boot = Enabled, then run:"
        Write-Info   "  .\deploy\secure_boot\enable_secure_boot_windows.ps1 $NextCmd"
    }
    for ($i = $RebootDelay; $i -gt 0; $i--) {
        Write-Host ("`r       rebooting in {0,2}s... " -f $i) -NoNewline
        Start-Sleep -Seconds 1
    }
    Write-Host ''
    Restart-Computer -Force
}

# ------------------------------------------------------------------
# Stage the two WDK files into WorkDir (idempotent)
# ------------------------------------------------------------------
function Ensure-Files {
    if (-not (Test-Path $WorkDir)) {
        New-Item -ItemType Directory -Path $WorkDir | Out-Null
        Write-Ok "Created working dir: $WorkDir"
    }

    # EnableUefiSbTest_amd64.exe
    if (Test-Path $ToolExe) {
        Write-Ok "Tool present: $ToolExe"
    }
    else {
        $srcExe = Join-Path $WdkSecureBootDir $WdkEnableSrc
        if (Test-Path $srcExe) {
            Copy-Item $srcExe $ToolExe -Force
            Write-Ok "Copied tool from WDK: $srcExe"
        }
        else {
            Write-Warn "Tool not found: $ToolExe"
            Write-Info "WDK source also missing:  $srcExe"
            Write-Info "Install the WDK:  $WdkDownloadUrl"
            Write-Info "...or place the file manually at:  $ToolExe"
            Fail "Missing $ToolExeName — see the instructions above."
        }
    }

    # SecureBootPolicy.p7b (renamed from the preproduction policy)
    if (Test-Path $PolicyFile) {
        Write-Ok "Policy present: $PolicyFile"
    }
    else {
        $srcPolicy = Join-Path $WdkSecureBootDir $WdkPolicySrc
        if (Test-Path $srcPolicy) {
            Copy-Item $srcPolicy $PolicyFile -Force   # copy + rename to SecureBootPolicy.p7b
            Write-Ok "Copied + renamed policy from WDK: $srcPolicy"
        }
        else {
            Write-Warn "Policy not found: $PolicyFile"
            Write-Info "WDK source also missing:  $srcPolicy"
            Write-Info "Install the WDK:  $WdkDownloadUrl"
            Write-Info "...or place the file manually at:  $PolicyFile"
            Fail "Missing $PolicyName — see the instructions above."
        }
    }
}

# ------------------------------------------------------------------
# Mount / dismount the EFI System Partition
# ------------------------------------------------------------------
function Mount-Esp {
    Write-Action "Mounting the EFI System Partition at $MountRoot ..."
    & mountvol $MountRoot /s
    if ($LASTEXITCODE -ne 0) { Fail "mountvol $MountRoot /s failed (exit $LASTEXITCODE)." }
    Write-Ok "ESP mounted at $MountRoot"
}

function Dismount-Esp {
    & mountvol $MountRoot /d 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Ok "ESP dismounted from $MountRoot" }
}

# ------------------------------------------------------------------
# Stage: provision
# ------------------------------------------------------------------
function Stage-Provision {
    Require-Admin
    Require-SecureBootCapable
    Write-Host '=== Stage: provision Secure Boot (enroll test policy) ==============='

    Ensure-Files

    $setupMode = Get-SecureBootVarState -Name 'SetupMode'
    if ($null -ne $setupMode -and $setupMode -ne 1) {
        Write-Warn 'Firmware is NOT in Setup Mode (a PK is already present).'
        Write-Info 'EnableUefiSbTest key enrollment typically requires Setup Mode.'
        Write-Info "Fix: BIOS Secure Boot settings -> 'Reset to Setup Mode' / 'Delete all Secure Boot keys', then re-run."
    }

    Mount-Esp
    try {
        if (-not (Test-Path $EspBootDir)) {
            Fail "ESP boot dir not found: $EspBootDir (is this a UEFI/GPT install?)."
        }
        Copy-Item $PolicyFile $EspPolicy -Force
        Write-Ok "Copied policy to $EspPolicy"
    }
    finally {
        Dismount-Esp
    }

    # Dump current keys — expected to be EMPTY before enrollment, but only if
    # the firmware is in Setup Mode (no PK enrolled yet). Keys being non-empty
    # does NOT mean "Secure Boot is disabled" -- it means a PK is already
    # enrolled (User Mode), which is independent of the Secure Boot on/off
    # toggle and usually means Secure Boot is already enabled and working.
    Write-Action "Dumping current keys (expected EMPTY only if firmware is in Setup Mode)..."
    & $ToolExe /dump
    Write-Info "Review the dump above — PK/KEK/DB/DBx should be empty ONLY if the"
    Write-Info "firmware is in Setup Mode (no PK enrolled yet). If PK/KEK/DB already"
    Write-Info "have values, Secure Boot is likely ALREADY enabled with existing keys --"
    Write-Info "run '.\deploy\secure_boot\enable_secure_boot_windows.ps1 verify' to confirm."

    # Enroll the keys (turns Secure Boot ON at next boot).
    Write-Action "Running EnableUefiSbTest to enroll PK/KEK/DB/DBx ..."
    & $ToolExe
    if ($LASTEXITCODE -ne 0) {
        Write-Warn "$ToolExeName failed (exit $LASTEXITCODE) -- enrollment did NOT happen."
        if ($LASTEXITCODE -eq -805306334) {
            # -805306334 = 0xD0000022 = STATUS_ACCESS_DENIED. This is the expected
            # result when a PK is already enrolled: the firmware is in User Mode,
            # where PK/KEK/DB/DBx can only be updated via an authenticated (signed)
            # transaction -- an unsigned test enrollment is correctly rejected.
            Write-Info "       This does NOT mean Secure Boot is broken -- since keys are"
            Write-Info "       already enrolled, Secure Boot is likely already ENABLED."
            Write-Info "       Run:  .\deploy\secure_boot\enable_secure_boot_windows.ps1 verify"
            Write-Info "       to confirm the current state before deciding whether you"
            Write-Info "       actually need to re-provision with the WDK test policy."
        }
        Write-Warn "Stopping here -- no reboot, no progress recorded (enrollment did not complete)."
        return
    }
    Write-Ok "Enrollment command completed"

    Write-Host ''
    Write-Action "After reboot, enter BIOS: 'Secure Boot' should show ENABLED."
    Record-Progress -StageName 'provision'
    Invoke-AutoReboot -NextCmd 'verify'
}

# ------------------------------------------------------------------
# Stage: verify
# ------------------------------------------------------------------
function Stage-Verify {
    Require-Admin
    Require-SecureBootCapable
    Write-Host '=== Stage: verify Secure Boot state ================================='

    if (Test-Path $ToolExe) {
        Write-Action "Dumping keys — PK/KEK/DB/DBx should now be populated..."
        & $ToolExe /dump
    }
    else {
        Write-Warn "Tool not found ($ToolExe) — skipping key dump."
    }

    Write-Action "Running Confirm-SecureBootUEFI ..."
    $state = $null
    try { $state = Confirm-SecureBootUEFI } catch { Fail "Confirm-SecureBootUEFI failed: $($_.Exception.Message)" }
    Write-Host "Confirm-SecureBootUEFI: $state"
    if ($state -ne $true) { Fail "Secure Boot is NOT enabled (Confirm-SecureBootUEFI returned '$state')." }
    Write-Ok "UEFI Secure Boot is ENABLED"
    Record-Progress -StageName 'verify'
}

# ------------------------------------------------------------------
# Stage: status (read-only summary of boot state + provisioning progress)
# ------------------------------------------------------------------
function Stage-Status {
    Write-Host '=== Secure Boot status ================================================'
    Write-Info ("Work dir         : {0}" -f $WorkDir)
    Write-Info ("Tool staged      : {0}" -f $(if (Test-Path $ToolExe) { $ToolExe } else { 'not staged yet' }))
    Write-Info ("Policy staged    : {0}" -f $(if (Test-Path $PolicyFile) { $PolicyFile } else { 'not staged yet' }))
}

# ------------------------------------------------------------------
# Stage: auto (next stage by itself; continues at the next boot)
# ------------------------------------------------------------------
function Install-AutoResumeTask {
    # At boot as SYSTEM, like the fTPM/dTPM reboots: runs whether or not anyone signs in (no -NoExit:
    # nobody can close a window in the boot session). The 30 s delay lets the TPM/WMI services come up.
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" auto " +
               "-WorkDir `"$WorkDir`" -WdkSecureBootDir `"$WdkSecureBootDir`" -MountLetter $MountLetter"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argList
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $trigger.Delay = 'PT30S'
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Unregister-ScheduledTask -TaskName $LogonTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $AutoTaskName -Confirm:$false -ErrorAction SilentlyContinue
    Register-ScheduledTask -TaskName $AutoTaskName -Action $action -Trigger $trigger -Principal $principal `
        -Description 'Continues Secure Boot enablement after reboot (enable_secure_boot_windows.ps1 auto).' `
        -ErrorAction Stop | Out-Null
    Write-Ok "Auto-resume installed (Scheduled Task '$AutoTaskName')."
}

function Remove-AutoResumeTask {
    if (Get-ScheduledTask -TaskName $AutoTaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $AutoTaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Ok "Auto-resume removed (Scheduled Task '$AutoTaskName')."
    }
}

function Get-LastStage {
    if (-not (Test-Path $ProgressFile)) { return '' }
    return ((Get-Content $ProgressFile -Tail 1) -split ' ', 2)[0]
}

# Tell deploy\preflight\preflight_chain.py how this step ended, when a test_runner.py
# pre-flight started it. On 'pass' the chain starts the next step or runs the tests
# in this (elevated) window. Does nothing for a run started by hand.
function Report-Preflight {
    param([string]$Result, [string]$Detail)
    if (-not (Test-Path $PreflightPlan) -or -not (Test-Path $PreflightChain)) { return }
    $python = 'python'
    try {
        $plan = Get-Content $PreflightPlan -Raw | ConvertFrom-Json
        if ($plan.python -and (Test-Path $plan.python)) { $python = $plan.python }
    }
    catch { }
    & $python $PreflightChain next --from secure_boot --result $Result --detail $Detail
}

function Stage-Auto {
    $script:AutoMode = $true
    $script:TranscriptStopped = $false
    $logDir = Split-Path -Parent $AutoLog
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
    Start-Transcript -Path $AutoLog -Append | Out-Null
    try {
        Require-Admin
        Require-SecureBootCapable
        Write-Host '=== Secure Boot: auto ==============================================='

        if (Test-Path $BiosKnobState) {
            Fail "A BIOS knob configuration run is in progress ($BiosKnobState).`n       Let it finish (it resumes after the reboot by itself), then run:  .\deploy\secure_boot\enable_secure_boot_windows.ps1 auto"
        }

        if ((Confirm-SecureBootUEFI) -eq $true) {
            Stage-Verify
            # Removed only after verify: until then FW_Preflight_Resume (same boot) must see this step as busy
            Remove-AutoResumeTask
            Write-Host ''
            Write-Ok 'Secure Boot is ENABLED.'
            if (Test-Path $PreflightPlan) {
                # Close the transcript first: the chain may run pytest in this window, and its
                # output would otherwise make the transcript very large.
                Stop-Transcript | Out-Null
                $script:TranscriptStopped = $true
                Report-Preflight -Result 'pass' -Detail 'Secure Boot enabled'
            }
            else {
                Write-Info 'Run the tests:  python test_runner.py'
            }
            return
        }

        $last = Get-LastStage
        Write-Info ("Secure Boot is DISABLED; last completed stage: {0}" -f $(if ($last) { $last } else { 'none' }))
        if ($last -eq 'provision') {
            Remove-AutoResumeTask
            Write-Action 'The keys are enrolled but Secure Boot is still DISABLED.'
            Write-Info   'Enter BIOS Setup -> Security -> Secure Boot -> set it to Enabled, save and reboot.'
            Write-Info   'Then run:  .\deploy\secure_boot\enable_secure_boot_windows.ps1 auto   (or pick the tests again in python test_runner.py)'
            Report-Preflight -Result 'fail' -Detail 'the keys are enrolled but Secure Boot is still off: enable it in BIOS Setup (Security -> Secure Boot), then pick the tests again.'
            return
        }
        if ($last -eq 'verify') {
            Write-Warn 'Secure Boot was set up before but is DISABLED now (IFWI reflash or BIOS change).'
            $archive = "$ProgressFile.$(Get-Date -Format yyyyMMdd_HHmmss)"
            Move-Item $ProgressFile $archive
            Write-Info "Starting again from 'provision'; old progress kept in $archive"
        }

        Install-AutoResumeTask
        Stage-Provision
        # Stage-Provision returns without a reboot when the enrollment did not happen.
        if ((Get-LastStage) -ne 'provision') {
            Remove-AutoResumeTask
            Report-Preflight -Result 'fail' -Detail 'EnableUefiSbTest did not enroll the keys -- see the window / logs\enable_secure_boot_windows_auto.log'
        }
    }
    finally {
        if (-not $script:TranscriptStopped) { Stop-Transcript | Out-Null }
    }
}

# ------------------------------------------------------------------
# Usage
# ------------------------------------------------------------------
function Show-Usage {
    @"
Enable UEFI Secure Boot on Windows — provisioning runbook.

Usage (ELEVATED PowerShell, run ON the SUT):
  .\deploy\secure_boot\enable_secure_boot_windows.ps1 <stage>

Recommended (one command; test_runner.py pre-flight runs it for you):
  auto        Run whichever stage comes next. Before the provision reboot it
              installs the Scheduled Task '$AutoTaskName', which runs
              'auto' again at the next boot (verify, no sign-in needed) and then removes itself.
              Started by test_runner.py's pre-flight, it then hands over to
              deploy\preflight\preflight_chain.py (next step, then the tests).
              Progress log: $AutoLog

Stages (run in order):
  provision   Stage SecureBootPolicy.p7b on the ESP, run EnableUefiSbTest to
              enroll PK/KEK/DB/DBx, then AUTO-REBOOT.
              (After reboot, confirm Secure Boot = Enabled in BIOS — manual.)
  verify      Dump keys and run Confirm-SecureBootUEFI (expects True).
  status      Show current boot state + which stage was last completed and
              what to run next (read-only; also shown automatically at the
              next logon via an installed Scheduled Task reminder).

Pre-required:
  Install the WDK; this script auto-finds the two files it needs under:
    $WdkSecureBootDir
  WDK download:
    $WdkDownloadUrl
  Or drop them into -WorkDir yourself:
    <WorkDir>\$ToolExeName
    <WorkDir>\$PolicyName

Options / overrides:
  -WorkDir <path>          Staging dir for the exe + p7b (default: $WorkDir)
  -WdkSecureBootDir <path> WDK SecureBoot tools dir
  -MountLetter <X>         Drive letter for the ESP mount (default: $MountLetter)
  -NoReboot                Skip auto-reboot; print a manual reminder instead.
  -RebootDelay <N>         Countdown seconds before rebooting (default: $RebootDelay)

Env overrides: WDK_SECUREBOOT_DIR, SB_WORKDIR, SB_MOUNT_LETTER, REBOOT_DELAY
"@ | Write-Host
}

# ------------------------------------------------------------------
# Dispatch
# ------------------------------------------------------------------
switch ($Stage) {
    'auto'      { Show-BootState; Show-Progress; Stage-Auto }
    'provision' { Show-BootState; Show-Progress; Stage-Provision }
    'verify'    { Show-BootState; Show-Progress; Stage-Verify }
    'status'    { Show-BootState; Show-Progress; Stage-Status }
    default     { Show-Usage }
}
