# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$VersionCacheDirectory)

$ErrorActionPreference = 'Stop'
$statePath = Join-Path $VersionCacheDirectory 'source-versions.json'
if (-not [string]::IsNullOrWhiteSpace($env:RECOVERED_VERSION_STATE)) {
    $recoveredState = $env:RECOVERED_VERSION_STATE | ConvertFrom-Json
    if ($recoveredState.schema -ne 1 -or $null -eq $recoveredState.versions) { throw 'Invalid recovered version state.' }
    New-Item -ItemType Directory -Path $VersionCacheDirectory -Force | Out-Null
    [IO.File]::WriteAllText($statePath, $env:RECOVERED_VERSION_STATE, (New-Object Text.UTF8Encoding($false)))
    return
}
if (Test-Path -LiteralPath $statePath -PathType Leaf) { return }
$headers = @{
    Accept = 'application/vnd.github+json'
    Authorization = 'Bearer ' + $env:GH_TOKEN
    'X-GitHub-Api-Version' = '2022-11-28'
}
$repositoryApi = $env:GITHUB_API_URL + '/repos/' + $env:GITHUB_REPOSITORY
$branch = [Uri]::EscapeDataString($env:DEFAULT_BRANCH)
$publishedRuns = @()
foreach ($eventName in @('push', 'workflow_dispatch')) {
    $runs = Invoke-RestMethod -Uri ($repositoryApi + '/actions/workflows/build-drivers.yml/runs?branch=' + $branch + '&event=' + $eventName + '&status=success&per_page=1') -Headers $headers
    $publishedRuns += @($runs.workflow_runs)
}
$previousRun = $publishedRuns | Where-Object { $_.head_repository.full_name -eq $env:GITHUB_REPOSITORY } | Sort-Object id -Descending | Select-Object -First 1
if ($null -eq $previousRun) { return }
$artifacts = Invoke-RestMethod -Uri ($repositoryApi + '/actions/runs/' + $previousRun.id + '/artifacts?per_page=100') -Headers $headers
$backup = $artifacts.artifacts | Where-Object { $_.name -eq 'source-versions' -and -not $_.expired } | Sort-Object id -Descending | Select-Object -First 1
if ($null -eq $backup) {
    throw 'Previous builds exist but version state is unavailable. Restore source-versions.json from your saved backup before assigning new versions.'
}
New-Item -ItemType Directory -Path $VersionCacheDirectory -Force | Out-Null
$backupZip = Join-Path $env:RUNNER_TEMP 'ap6256-version-backup.zip'
& gh api ('repos/' + $env:GITHUB_REPOSITORY + '/actions/artifacts/' + $backup.id + '/zip') --method GET > $backupZip
if ($LASTEXITCODE -ne 0) { throw 'Version-state download failed.' }
$archive = [IO.Compression.ZipFile]::OpenRead($backupZip)
try {
    $entry = $archive.GetEntry('source-versions.json')
    if ($null -eq $entry -or $entry.Length -gt 10MB) { throw 'Invalid version-state backup.' }
    $reader = New-Object IO.StreamReader($entry.Open())
    try { $stateText = $reader.ReadToEnd() } finally { $reader.Dispose() }
    $state = $stateText | ConvertFrom-Json
    if ($state.schema -ne 1 -or $null -eq $state.versions) { throw 'Invalid version-state backup.' }
    [IO.File]::WriteAllText($statePath, $stateText, (New-Object Text.UTF8Encoding($false)))
} finally {
    $archive.Dispose()
}

