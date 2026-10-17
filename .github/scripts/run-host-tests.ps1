# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][string]$ReportDirectory,
    [Parameter(Mandatory = $true)][string]$WdkPackageDirectory,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$sourceRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$packageRoot = [IO.Path]::GetFullPath($WdkPackageDirectory)
[xml]$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'test-packages.config') -Raw
$content = @{}
foreach ($package in $manifest.packages.package) {
    $path = Join-Path $packageRoot ($package.id + '.' + $package.version + '/c')
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "Missing kit content: $path" }
    $content[$package.id] = [IO.Path]::GetFullPath($path)
}
if (-not $env:VCToolsInstallDir) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    $vsPath = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $vsPath) { throw 'Visual Studio x64 C++ tools are required.' }
    Import-Module (Join-Path $vsPath 'Common7/Tools/Microsoft.VisualStudio.DevShell.dll')
    Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments '-arch=amd64 -host_arch=amd64'
}
$sdk = $content['Microsoft.Windows.SDK.CPP']
$sdkX64 = $content['Microsoft.Windows.SDK.CPP.x64']
$wdk = $content['Microsoft.Windows.WDK.x64']
$version = '10.0.26100.0'
$env:AP6256_TEST_SDK = $sdk
$env:AP6256_TEST_SDK_VERSION = $version
$env:AP6256_TEST_EXTRA_KIT = "$wdk;$sdkX64"
$env:AP6256_TEST_EXTRA_INCLUDE = Join-Path $wdk "Include/$version"
$env:AP6256_TEST_EXTRA_LIB = $sdkX64 + ';' + (Join-Path $wdk "Lib/$version")
& $Python -B (Join-Path $sourceRoot 'tests/audit.py')
if ($LASTEXITCODE -ne 0) { throw 'Public test source audit failed.' }
& $Python -B (Join-Path $sourceRoot 'tests/run.py') --output $OutputDirectory
$testExit = $LASTEXITCODE
if (Test-Path -LiteralPath (Join-Path $OutputDirectory 'results.json')) {
    & $Python -B (Join-Path $sourceRoot 'tests/export_reports.py') --input $OutputDirectory --output $ReportDirectory
    if ($LASTEXITCODE -ne 0) { throw 'Test report export failed.' }
}
if ($testExit -ne 0) { throw "Host test suite failed with exit code $testExit." }
