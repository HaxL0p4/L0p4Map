#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$PythonExe,
    [string]$VenvPath,
    [switch]$CheckOnly,
    [switch]$Launch
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0
if (-not $VenvPath) { $VenvPath = Join-Path $PSScriptRoot '.venv' }

function Find-Python {
    if ($PythonExe) {
        $candidates = @($PythonExe)
    } else {
        $candidates = @()
        $command = Get-Command python.exe -ErrorAction SilentlyContinue
        if ($command -and $command.Source -notlike '*\WindowsApps\*') {
            $candidates += $command.Source
        }
        $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($launcher) {
            $resolved = & $launcher.Source -3 -c 'import sys; print(sys.executable)' 2>$null
            if ($LASTEXITCODE -eq 0) { $candidates += $resolved }
        }
        foreach ($base in @($env:LOCALAPPDATA, $env:ProgramFiles)) {
            if (-not $base) { continue }
            foreach ($relative in @('Programs\Python', '')) {
                $directory = if ($relative) { Join-Path $base $relative } else { $base }
                if (Test-Path $directory) {
                    $candidates += @(Get-ChildItem $directory -Directory -Filter 'Python*' |
                        Sort-Object Name -Descending | ForEach-Object { Join-Path $_.FullName 'python.exe' })
                }
            }
        }
    }
    foreach ($candidate in $candidates) {
        if (-not (Test-Path $candidate -PathType Leaf)) { continue }
        & $candidate -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'
        if ($LASTEXITCODE -eq 0) { return $candidate }
    }
    return $null
}

function Invoke-Python {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Python command failed (exit $LASTEXITCODE)." }
}

function Get-Requirements {
    param([string]$Executable)
    $output = & $Executable -m core.windows_requirements --json
    if ($LASTEXITCODE -notin @(0, 1)) { throw 'Prerequisite diagnostic failed.' }
    return (($output -join "`n") | ConvertFrom-Json)
}

function Show-Requirements {
    param($Report)
    foreach ($check in $Report.checks) {
        $label = if ($check.ok) { 'OK' } else { 'MISSING' }
        Write-Host "[$label] $($check.name): $($check.detail)"
    }
}

function Install-OfficialPackage {
    param([string]$Url, [string[]]$InstallerArguments)
    $directory = Join-Path ([IO.Path]::GetTempPath()) ('l0p4map-' + [guid]::NewGuid().ToString())
    New-Item $directory -ItemType Directory | Out-Null
    try {
        $file = Join-Path $directory ([IO.Path]::GetFileName(([uri]$Url).AbsolutePath))
        Write-Host "Downloading $Url"
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Url -OutFile $file -UseBasicParsing
        $signature = Get-AuthenticodeSignature -FilePath $file
        if ($signature.Status -ne 'Valid') { throw "Invalid installer signature: $($signature.Status)." }
        Write-Host 'Complete the official installer window; this script will wait.'
        $process = Start-Process -FilePath $file -ArgumentList $InstallerArguments -Wait -PassThru
        if ($process.ExitCode -eq 3010) { throw 'Installation requires a Windows restart. Restart and rerun this script.' }
        if ($process.ExitCode -ne 0) { throw "Installer failed or was cancelled (exit $($process.ExitCode))." }
    } finally {
        Remove-Item $directory -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Push-Location $PSScriptRoot
try {
    if ($env:OS -ne 'Windows_NT') { throw 'This script is for Windows.' }
    if ($CheckOnly -and $Launch) { throw 'Use -CheckOnly or -Launch, not both.' }
    if (-not $CheckOnly) {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw 'Open PowerShell as Administrator and rerun .\setup-windows.ps1.'
        }
    }

    $venvPython = Join-Path $VenvPath 'Scripts\python.exe'
    if ($CheckOnly) {
        $python = if (Test-Path $venvPython) { $venvPython } else { Find-Python }
        if (-not $python) { throw 'Python 3.11+ is missing. Run this script without -CheckOnly to install prerequisites.' }
        $report = Get-Requirements $python
        Show-Requirements $report
        if (-not $report.ready) { exit 1 }
        exit 0
    }

    $python = Find-Python
    if (-not $python) {
        if ($PythonExe) { throw 'The selected Python is missing or older than 3.11.' }
        $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
        if (-not $winget) { throw 'Install Python 3.11+ from https://www.python.org/downloads/windows/ and rerun. WinGet is unavailable.' }
        & $winget.Source install --id Python.Python.3.12 --exact --source winget
        if ($LASTEXITCODE -ne 0) { throw "Python installation failed (exit $LASTEXITCODE)." }
        $python = Find-Python
        if (-not $python) { throw 'Python installation finished but Python 3.11+ was not found. Reopen PowerShell and rerun.' }
    }
    if (-not (Test-Path $venvPython)) {
        Invoke-Python -Executable $python -Arguments @('-m', 'venv', $VenvPath)
    }
    Invoke-Python -Executable $venvPython -Arguments @('-m', 'pip', 'install', '-r', (Join-Path $PSScriptRoot 'requirements.txt'))

    $report = Get-Requirements $venvPython
    Show-Requirements $report
    $npcap = @($report.checks | Where-Object { $_.name -eq 'Npcap' })[0]
    if (-not $npcap.ok) {
        Install-OfficialPackage -Url 'https://npcap.com/dist/npcap-1.89.exe' -InstallerArguments @('/winpcap_mode=yes', '/no_kill=yes')
        $report = Get-Requirements $venvPython
        if (-not @($report.checks | Where-Object { $_.name -eq 'Npcap' })[0].ok) {
            throw 'Npcap could not be loaded. Restart Windows and rerun the setup.'
        }
    }
    $nmap = @($report.checks | Where-Object { $_.name -eq 'Nmap' })[0]
    if (-not $nmap.ok) {
        Install-OfficialPackage -Url 'https://nmap.org/dist/nmap-7.991-setup.exe' -InstallerArguments @('/NPCAP=NO', '/REGISTRYMODS=NO')
    }
    # Refresh the process PATH after installation; never replace the persistent PATH.
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $env:Path = "$machinePath;$userPath;$env:Path"
    $report = Get-Requirements $venvPython
    Show-Requirements $report
    if (-not $report.ready) { throw 'Prerequisites are incomplete. Fix the MISSING items and rerun.' }
    $nmap = @($report.checks | Where-Object { $_.name -eq 'Nmap' })[0]
    $env:Path = (Split-Path $nmap.path -Parent) + ';' + $env:Path
    Write-Host 'L0p4Map prerequisites are ready. No network scan has been performed.'
    Write-Host "To launch: & '$venvPython' .\__main__.py"
    if ($Launch) { Invoke-Python -Executable $venvPython -Arguments @((Join-Path $PSScriptRoot '__main__.py')) }
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
} finally {
    Pop-Location
}
