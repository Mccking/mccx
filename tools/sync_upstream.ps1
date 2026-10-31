# Syncs the WARP constants the Android port depends on from github.com/hezhanleiok/xehn.
#
#   pwsh tools/sync_upstream.ps1              # regenerate src/com/xehn/warp/UpstreamDefaults.java
#   pwsh tools/sync_upstream.ps1 -Check       # report drift only, exit 1 when upstream moved
#   pwsh tools/sync_upstream.ps1 -LocalPath E:\deepseek\xehn
#
# Only data is synced: API base/version/UA, MTU, keepalive, AmneziaWG junk
# parameters, and the WARP endpoint pools the scanner probes. The Go code itself
# (connect pipeline, mihomo rendering, GUI) has no Android counterpart and is
# ported by hand when it changes.
param(
    [string]$Owner = 'hezhanleiok',
    [string]$Repo = 'xehn',
    [string]$Ref = 'main',
    [string]$LocalPath = '',
    [switch]$Check
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$target = Join-Path $root 'src\com\xehn\warp\UpstreamDefaults.java'
$work = Join-Path $root 'build\upstream'

function Get-UpstreamTree {
    if ($LocalPath) {
        if (-not (Test-Path $LocalPath)) { throw "本地路径不存在: $LocalPath" }
        Write-Host "source: $LocalPath"
        return (Get-Item $LocalPath).FullName
    }
    Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $work | Out-Null
    $zip = Join-Path $work 'src.zip'
    $url = "https://codeload.github.com/$Owner/$Repo/zip/refs/heads/$Ref"
    Write-Host "source: $url"
    Invoke-WebRequest -Uri $url -OutFile $zip -TimeoutSec 300
    Expand-Archive $zip -DestinationPath $work -Force
    return (Get-ChildItem $work -Directory | Where-Object { $_.Name -like "$Repo-*" } | Select-Object -First 1).FullName
}

function Get-UpstreamCommit {
    if ($LocalPath) { return @{ sha = 'local'; date = (Get-Date).ToString('yyyy-MM-dd') } }
    try {
        $r = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/commits?per_page=1" `
            -Headers @{ 'User-Agent' = 'mccx-sync' } -TimeoutSec 60
        return @{ sha = $r[0].sha; date = $r[0].commit.committer.date }
    } catch {
        return @{ sha = 'unknown'; date = 'unknown' }
    }
}

function Read-Go($path) {
    if (-not (Test-Path $path)) { throw "缺少源文件: $path" }
    return Get-Content $path -Raw
}

function Match-Const($text, $pattern, $what) {
    $m = [regex]::Match($text, $pattern, 'Multiline')
    if (-not $m.Success) { throw "上游里找不到 $what（正则: $pattern）—— 结构变了，需要人工看" }
    return $m.Groups[1].Value
}

$src = Get-UpstreamTree
$commit = Get-UpstreamCommit

$warpGo = Read-Go (Join-Path $src 'warp.go')
$registerGo = Read-Go (Join-Path $src 'register.go')
$poolsGo = Read-Go (Join-Path $src 'pools.go')

$regUrl = Match-Const $registerGo 'regBaseURL\s*=\s*"([^"]+)"' 'regBaseURL'
$clientVersion = Match-Const $registerGo 'cfClientVersion\s*=\s*"([^"]+)"' 'cfClientVersion'
$userAgent = Match-Const $registerGo 'cfUserAgent\s*=\s*"([^"]+)"' 'cfUserAgent'
$mtu = Match-Const $warpGo '(?m)^\s*tunnelMTU\s*=\s*(\d+)\s*$' 'tunnelMTU'
$keepalive = Match-Const $warpGo '(?m)^\s*keepalive\s*=\s*(\d+)\s*$' 'keepalive'
$awgJc = Match-Const $warpGo '(?m)^\s*awgJc\s*=\s*(\d+)\s*$' 'awgJc'
$awgJmin = Match-Const $warpGo '(?m)^\s*awgJmin\s*=\s*(\d+)\s*$' 'awgJmin'
$awgJmax = Match-Const $warpGo '(?m)^\s*awgJmax\s*=\s*(\d+)\s*$' 'awgJmax'

$poolBlock = [regex]::Match($poolsGo, 'var poolsV4 = \[\]netip\.Prefix\{(?<body>[\s\S]*?)\n\}', 'Multiline')
if (-not $poolBlock.Success) { throw '上游 pools.go 结构变了：找不到 poolsV4' }
$prefixes = [regex]::Matches($poolBlock.Groups['body'].Value, '"([0-9.]+/\d+)"') |
    ForEach-Object { $_.Groups[1].Value }

# Four hosts per /24 keeps the probe count bounded (14 prefixes -> 56 probes).
$perPrefix = 4
$scanIps = New-Object System.Collections.Generic.List[string]
foreach ($cidr in $prefixes) {
    $parts = $cidr.Split('/')
    $base = [System.Net.IPAddress]::Parse($parts[0])
    $bytes = $base.GetAddressBytes()
    for ($i = 1; $i -le $perPrefix; $i++) {
        $b = [byte[]]$bytes.Clone()
        $b3 = [int]$b[3] + $i
        if ($b3 -gt 255) { $b3 = $b3 % 256 }
        $b[3] = [byte]$b3
        $scanIps.Add((New-Object System.Net.IPAddress(,$b)).ToString())
    }
}

$sha7 = if ($commit.sha.Length -ge 7) { $commit.sha.Substring(0, 7) } else { $commit.sha }

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('package com.xehn.warp;')
$lines.Add('')
$lines.Add('// GENERATED FILE - do not edit by hand.')
$lines.Add('// Source: github.com/' + $Owner + '/' + $Repo + ' @ ' + $commit.sha)
$lines.Add('// Commit date: ' + $commit.date)
$lines.Add('// Regenerate: pwsh tools/sync_upstream.ps1')
$lines.Add('//')
$lines.Add('// Only the data the Android port consumes is copied here. The Go code itself')
$lines.Add('// (connect pipeline, mihomo rendering, Windows GUI) has no Android counterpart.')
$lines.Add('public final class UpstreamDefaults {')
$lines.Add('')
$lines.Add('    private UpstreamDefaults() {')
$lines.Add('    }')
$lines.Add('')
$lines.Add('    public static final String UPSTREAM_COMMIT = "' + $commit.sha + '";')
$lines.Add('    public static final String UPSTREAM_DATE = "' + $commit.date + '";')
$lines.Add('')
$lines.Add('    public static final String REG_URL = "' + $regUrl + '";')
$lines.Add('    public static final String CF_CLIENT_VERSION = "' + $clientVersion + '";')
$lines.Add('    public static final String USER_AGENT = "' + $userAgent + '";')
$lines.Add('')
$lines.Add('    public static final int TUNNEL_MTU = ' + $mtu + ';')
$lines.Add('    public static final int KEEPALIVE = ' + $keepalive + ';')
$lines.Add('    public static final int AWG_JC = ' + $awgJc + ';')
$lines.Add('    public static final int AWG_JMIN = ' + $awgJmin + ';')
$lines.Add('    public static final int AWG_JMAX = ' + $awgJmax + ';')
$lines.Add('')
$lines.Add('    /** WARP edge pools from the upstream scanner, four hosts per prefix. */')
$lines.Add('    public static final String[] SCAN_IPS = {')
for ($i = 0; $i -lt $scanIps.Count; $i += 4) {
    $chunk = $scanIps[$i..([Math]::Min($i + 3, $scanIps.Count - 1))] | ForEach-Object { '"' + $_ + '"' }
    $lines.Add('            ' + ($chunk -join ', ') + ',')
}
$lines.Add('    };')
$lines.Add('}')

$content = ($lines -join [Environment]::NewLine) + [Environment]::NewLine

if ($Check) {
    if (-not (Test-Path $target)) {
        Write-Host 'UpstreamDefaults.java 不存在，需要先同步'
        exit 1
    }
    $current = Get-Content $target -Raw
    if ($current -eq $content) {
        Write-Host "已同步：$Owner/$Repo@$sha7（$($commit.date)）"
        exit 0
    }
    Write-Host "上游有变化：$Owner/$Repo@$sha7（$($commit.date)）"
    Write-Host '运行 pwsh tools/sync_upstream.ps1 重新生成'
    exit 1
}

New-Item -ItemType Directory -Force (Split-Path -Parent $target) | Out-Null
Set-Content -Path $target -Value $content -Encoding UTF8 -NoNewline

Write-Host ''
Write-Host "上游: $Owner/$Repo@$sha7  ($($commit.date))"
Write-Host ("  reg_url        {0}" -f $regUrl)
Write-Host ("  client_version {0}" -f $clientVersion)
Write-Host ("  user_agent     {0}" -f $userAgent)
Write-Host ("  mtu/keepalive  {0} / {1}" -f $mtu, $keepalive)
Write-Host ("  awg            Jc={0} Jmin={1} Jmax={2}" -f $awgJc, $awgJmin, $awgJmax)
Write-Host ("  pools          {0} 个网段 -> {1} 个扫描候选" -f $prefixes.Count, $scanIps.Count)
Write-Host "已写入 $target"
