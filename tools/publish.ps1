# Publishes this repo to GitHub: authenticate (Git Credential Manager), create the
# repository if needed, push, and try to store the two signing secrets.
#
#   pwsh tools/publish.ps1                 # repo Mccking/mccx (public, needed by the updater)
#   pwsh tools/publish.ps1 -Repo mccx2 -Private
#
# A GitHub login window opens on first run; approve it once and the rest is automatic.
param(
    [string]$Owner = 'Mccking',
    [string]$Repo = 'mccx',
    [switch]$Private,
    [string]$KeystorePass = 'xehn-apk'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

function Get-GitHubToken {
    $gcm = 'C:\Program Files\Git\mingw64\bin\git-credential-manager.exe'
    $accounts = ''
    if (Test-Path $gcm) {
        $accounts = (& $gcm github list 2>$null | Out-String).Trim()
    }
    if (-not $accounts) {
        Write-Host '未发现已登录的 GitHub 账号，开始授权…'
        if (Test-Path $gcm) {
            & $gcm github login --browser
            if ($LASTEXITCODE -ne 0) {
                Write-Host '浏览器流程未完成，改用设备码（会给出一个 8 位码，在 github.com/login/device 输入）…'
                & $gcm github login --device
            }
        } else {
            Write-Host '没有找到 GCM，请先执行一次 git push 完成登录'
        }
    }

    # Only now is non-interactive safe: the credential should already be stored.
    $env:GIT_TERMINAL_PROMPT = '0'
    $cred = "protocol=https`nhost=github.com`n`n" | & git credential fill 2>$null
    $line = $cred | Select-String '^password=' | Select-Object -First 1
    if (-not $line) {
        Write-Host ''
        Write-Host '仍然没有拿到凭据。两种办法任选其一：'
        Write-Host "  1) 直接跑一次 git push，浏览器里登录后凭据会被记住，再回来执行本脚本"
        Write-Host "  2) 用 PAT 登录：& '$gcm' github login --pat ghp_你的token（scope 勾 repo + workflow）"
        throw '没有拿到 GitHub 凭据'
    }
    return ($line.Line -replace '^password=', '')
}

Write-Host "== GitHub 认证 =="
Write-Host '如果弹出登录窗口，请在浏览器里完成授权…'
$token = Get-GitHubToken
$headers = @{
    Authorization          = "token $token"
    'User-Agent'           = 'mccx-publish'
    Accept                 = 'application/vnd.github+json'
}
Write-Host '已获得凭据'

Write-Host "== 仓库 $Owner/$Repo =="
$repoUrl = "https://api.github.com/repos/$Owner/$Repo"
$exists = $true
try {
    $null = Invoke-RestMethod -Uri $repoUrl -Headers $headers -TimeoutSec 30
} catch {
    if ($_.Exception.Response.StatusCode.value__ -eq 404) { $exists = $false }
    else { throw }
}

if (-not $exists) {
    $body = @{ name = $Repo; private = [bool]$Private; has_issues = $true; has_wiki = $false } | ConvertTo-Json
    $null = Invoke-RestMethod -Method Post -Uri 'https://api.github.com/user/repos' -Headers $headers -Body $body -ContentType 'application/json' -TimeoutSec 60
    Write-Host "已创建 $Owner/$Repo"
} else {
    Write-Host "仓库已存在"
}

Write-Host '== 推送 =='
Push-Location $root
try {
    $current = (git rev-parse --abbrev-ref HEAD).Trim()
    if ($current -ne 'main') {
        git branch -M main
    }
    $remotes = git remote
    if ($remotes -contains 'origin') {
        git remote set-url origin "https://github.com/$Owner/$Repo.git"
    } else {
        git remote add origin "https://github.com/$Owner/$Repo.git"
    }
    git push -u origin main
    if ($LASTEXITCODE -ne 0) { throw "git push 失败（exit $LASTEXITCODE）" }
} finally {
    Pop-Location
}

Write-Host '== 签名密钥 secrets =='
$pynacl = $false
try {
    python -c "import nacl" 2>$null
    $pynacl = ($LASTEXITCODE -eq 0)
} catch {
    $pynacl = $false
}

if ($pynacl) {
    $keyInfo = Invoke-RestMethod -Uri "https://api.github.com/repos/$Owner/$Repo/actions/secrets/public-key" -Headers $headers
    $keystore = Join-Path $root 'keystore.jks'
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($keystore))

    $env:MCCX_PUBKEY = $keyInfo.key
    $env:MCCX_B64 = $b64
    $env:MCCX_SECRET_PASS = $KeystorePass
    $sealed = python -c @'
import base64, os
from nacl import encoding, public
pk = public.PublicKey(os.environ["MCCX_PUBKEY"].encode(), encoding.Base64Encoder())
box = public.SealedBox(pk)
print(base64.b64encode(box.encrypt(os.environ["MCCX_B64"].encode())).decode())
'@
    $sealedPass = python -c @'
import base64, os
from nacl import encoding, public
pk = public.PublicKey(os.environ["MCCX_PUBKEY"].encode(), encoding.Base64Encoder())
box = public.SealedBox(pk)
print(base64.b64encode(box.encrypt(os.environ["MCCX_SECRET_PASS"].encode())).decode())
'@
    $sealed = ($sealed | Select-Object -Last 1).Trim()
    $sealedPass = ($sealedPass | Select-Object -Last 1).Trim()

    $h = @{
        name          = 'MCCX_KEYSTORE_BASE64'
        encrypted_value = $sealed
        key_id        = $keyInfo.key_id
    } | ConvertTo-Json
    Invoke-RestMethod -Method Put -Uri "https://api.github.com/repos/$Owner/$Repo/actions/secrets/MCCX_KEYSTORE_BASE64" -Headers $headers -Body $h -ContentType 'application/json' | Out-Null

    $h2 = @{
        name          = 'MCCX_KEYSTORE_PASS'
        encrypted_value = $sealedPass
        key_id        = $keyInfo.key_id
    } | ConvertTo-Json
    Invoke-RestMethod -Method Put -Uri "https://api.github.com/repos/$Owner/$Repo/actions/secrets/MCCX_KEYSTORE_PASS" -Headers $headers -Body $h2 -ContentType 'application/json' | Out-Null
    Write-Host '两个 secret 已写入'
} else {
    Write-Host '未检测到 PyNaCl，secrets 需要手动添加：'
    Write-Host "  MCCX_KEYSTORE_BASE64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes('keystore.jks'))"
    Write-Host "  MCCX_KEYSTORE_PASS   = $KeystorePass"
}

Write-Host ''
Write-Host "仓库地址   https://github.com/$Owner/$Repo"
Write-Host "更新地址   https://github.com/$Owner/$Repo/releases/latest/download/update.json"
Write-Host ''
Write-Host '最后一步：把 src/com/xehn/warp/Updater.java 的 MANIFEST_URL 改成上面的更新地址，重打一次包并安装。'

