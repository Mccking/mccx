# One command to stay current with upstream: sync the constants, then rebuild the APK.
#
#   pwsh tools/release.ps1              # sync + build
#   pwsh tools/release.ps1 -SkipSync    # build only
#
# Sync failures stop the build on purpose: shipping an APK whose constants were
# silently not refreshed is worse than not shipping one.
param(
    [switch]$SkipSync
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

if (-not $SkipSync) {
    Write-Host '== sync upstream =='
    & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'sync_upstream.ps1')
    if ($LASTEXITCODE -ne 0) {
        throw "上游同步失败（exit $LASTEXITCODE）"
    }
}

Write-Host '== build apk =='
& pwsh -NoProfile -File (Join-Path $root 'build.ps1')
if ($LASTEXITCODE -ne 0) {
    throw "构建失败（exit $LASTEXITCODE）"
}

$apk = Get-ChildItem (Join-Path $root 'dist') -Filter '*.apk' |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
$hash = (Get-FileHash $apk.FullName -Algorithm SHA256).Hash
Write-Host ''
Write-Host ("产物 {0}  {1:N0} 字节" -f $apk.FullName, $apk.Length)
Write-Host ("sha256 {0}" -f $hash)
