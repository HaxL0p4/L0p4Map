#Requires -Version 5.1
# Native PowerShell tests. All downloads and installer launches are simulated.
param([string]$PythonExe)
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'setup-windows.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$functions = $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
foreach ($definition in $functions) { . ([scriptblock]::Create($definition.Extent.Text)) }

$script:signatureStatus = 'Valid'
$script:installerExit = 0
$script:launchCount = 0
$script:lastArguments = @()
function Invoke-WebRequest { param($Uri, $OutFile, [switch]$UseBasicParsing); Set-Content $OutFile 'fake installer' }
function Get-AuthenticodeSignature { param($FilePath); return [pscustomobject]@{ Status = $script:signatureStatus } }
function Start-Process {
    param($FilePath, $ArgumentList, [switch]$Wait, [switch]$PassThru)
    $script:launchCount++
    $script:lastArguments = $ArgumentList
    if (-not $Wait) { throw 'Installer was not awaited.' }
    return [pscustomobject]@{ ExitCode = $script:installerExit }
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Expected)
    $caught = $null
    try { & $Action } catch { $caught = $_.Exception.Message }
    if (-not $caught -or $caught -notlike "*$Expected*") { throw "Expected '$Expected', got '$caught'." }
}

$script:signatureStatus = 'NotSigned'
Assert-Throws { Install-OfficialPackage 'https://nmap.org/dist/test.exe' @('/NPCAP=NO') } 'Invalid installer signature'
if ($script:launchCount -ne 0) { throw 'Unsigned installer was launched.' }
Write-Host 'PASS: unsigned installer rejected before execution'

$script:signatureStatus = 'Valid'
$script:installerExit = 1
Assert-Throws { Install-OfficialPackage 'https://nmap.org/dist/test.exe' @('/NPCAP=NO') } 'cancelled'
Write-Host 'PASS: cancelled installer stops setup'

$script:installerExit = 3010
Assert-Throws { Install-OfficialPackage 'https://npcap.com/dist/test.exe' @('/no_kill=yes') } 'restart'
Write-Host 'PASS: restart requirement stops setup'

$script:installerExit = 0
Install-OfficialPackage -Url 'https://nmap.org/dist/test.exe' -InstallerArguments @('/NPCAP=NO', '/REGISTRYMODS=NO')
if (($script:lastArguments -join ',') -ne '/NPCAP=NO,/REGISTRYMODS=NO') { throw 'Installer arguments were lost.' }
Write-Host 'PASS: signed installer is awaited and success is accepted'

$testPython = Find-Python
if (-not $testPython) { throw 'These tests require Python 3.11+; supply -PythonExe if needed.' }
Invoke-Python -Executable $testPython -Arguments @('-c', "import sys; assert sys.argv[1:] == ['one', 'two']", 'one', 'two')
Write-Host 'PASS: Python receives the complete argument list'
Assert-Throws { Invoke-Python -Executable $testPython -Arguments @('-c', 'import sys; sys.exit(5)') } 'exit 5'
Write-Host 'PASS: Python failures stop setup'
Write-Host '6 PowerShell tests passed; no installer or download was executed.'
