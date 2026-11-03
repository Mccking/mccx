# Builds xehn-warp-vpn.apk: aapt2 -> javac -> d8 -> zip (+ native wg-go) -> zipalign -> apksigner.
$ErrorActionPreference = 'Stop'

$root   = 'E:\deepseek\xehn-vpn'
$sdk    = 'E:\deepseek\tools\android-sdk'
$bt     = "$sdk\build-tools\35.0.0"
$androidJar = "$sdk\platforms\android-34\android.jar"
$jdk    = 'E:\deepseek\tools\jdk\jdk-17.0.20.1+1'
$env:JAVA_HOME = $jdk

$lib    = "$root\lib"
$build  = "$root\build"
$dist   = "$root\dist"
$jni    = "$build\aar\jni"
# A fresh clone has no extracted AAR: the WireGuard native libs live inside it.
if (-not (Test-Path "$jni\arm64-v8a")) {
    Write-Host '== extract tunnel.aar =='
    Expand-Archive "$lib\tunnel.aar" -DestinationPath "$build\aar" -Force
}
Remove-Item $build\gen, $build\classes, $build\dex -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $build, $dist, "$build\gen", "$build\classes", "$build\dex" | Out-Null

$deps = @(
    "$lib\tunnel.jar",
    "$lib\collection.jar",
    "$lib\annotation.jar",
    "$lib\okhttp.jar",
    "$lib\okio.jar"
)
$depPath = ($deps -join ';')

Write-Host '== aapt2 compile =='
& "$bt\aapt2.exe" compile --dir "$root\res" -o "$build\res.zip"
if ($LASTEXITCODE -ne 0) { throw 'aapt2 compile failed' }

Write-Host '== aapt2 link =='
& "$bt\aapt2.exe" link -o "$build\base.apk" -I $androidJar `
    --manifest "$root\AndroidManifest.xml" `
    --java "$build\gen" `
    --min-sdk-version 24 --target-sdk-version 33 `
    --version-code 1015 --version-name 3.8 `
    "$build\res.zip"
if ($LASTEXITCODE -ne 0) { throw 'aapt2 link failed' }

Write-Host '== javac =='
$sources = @()
$sources += (Get-ChildItem "$build\gen" -Recurse -Filter *.java | ForEach-Object { $_.FullName })
$sources += (Get-ChildItem "$root\src" -Recurse -Filter *.java | ForEach-Object { $_.FullName })
& "$jdk\bin\javac.exe" '-J-Duser.language=en' -encoding UTF-8 -source 8 -target 8 `
    -bootclasspath $androidJar -classpath "$androidJar;$depPath" `
    -d "$build\classes" $sources
if ($LASTEXITCODE -ne 0) { throw 'javac failed' }

Write-Host '== d8 =='
& "$jdk\bin\jar.exe" cf "$build\classes.jar" -C "$build\classes" .
if ($LASTEXITCODE -ne 0) { throw 'jar failed' }
Remove-Item "$build\dex\classes.dex" -Force -ErrorAction SilentlyContinue
$d8Args = @('--release', '--min-api', '24', '--lib', $androidJar, '--output', "$build\dex", "$build\classes.jar") + $deps
& "$bt\d8.bat" $d8Args
if ($LASTEXITCODE -ne 0 -or -not (Test-Path "$build\dex\classes.dex")) { throw 'd8 failed' }

Write-Host '== package apk =='
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open("$build\base.apk", 'Update')
try {
    $dex = [System.IO.File]::ReadAllBytes("$build\dex\classes.dex")
    $entry = $zip.CreateEntry('classes.dex', [System.IO.Compression.CompressionLevel]::Optimal)
    $s = $entry.Open()
    try { $s.Write($dex, 0, $dex.Length) } finally { $s.Dispose() }

    foreach ($abi in @('arm64-v8a', 'armeabi-v7a')) {
        foreach ($so in (Get-ChildItem "$jni\$abi" -Filter *.so)) {
            $name = "lib/$abi/$($so.Name)"
            $e = $zip.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
            $out = $e.Open()
            try {
                $bytes = [System.IO.File]::ReadAllBytes($so.FullName)
                $out.Write($bytes, 0, $bytes.Length)
            } finally { $out.Dispose() }
        }
        # Locally built engine binaries (mihomo, launcher) live outside the AAR.
        $extra = "$root\libs\$abi"
        if (Test-Path $extra) {
            foreach ($so in (Get-ChildItem $extra -Filter *.so)) {
                $name = "lib/$abi/$($so.Name)"
                $e = $zip.CreateEntry($name, [System.IO.Compression.CompressionLevel]::Optimal)
                $out = $e.Open()
                try {
                    $bytes = [System.IO.File]::ReadAllBytes($so.FullName)
                    $out.Write($bytes, 0, $bytes.Length)
                } finally { $out.Dispose() }
            }
        }
    }
} finally {
    $zip.Dispose()
}

Write-Host '== zipalign =='
& "$bt\zipalign.exe" -f -p 4 "$build\base.apk" "$build\aligned.apk"
if ($LASTEXITCODE -ne 0) { throw 'zipalign failed' }

Write-Host '== sign =='
$ks = "$root\keystore.jks"
if (-not (Test-Path $ks)) {
    & "$jdk\bin\keytool.exe" -genkeypair -keystore $ks -alias xehn -keyalg RSA -keysize 2048 `
        -validity 10000 -storepass xehn-apk -keypass xehn-apk `
        -dname "CN=XEHN WARP VPN, O=XEHN, C=CN"
    if ($LASTEXITCODE -ne 0) { throw 'keytool failed' }
}
$out = "$dist\mccx-3.8.apk"
& "$bt\apksigner.bat" sign --ks $ks --ks-pass pass:xehn-apk --key-pass pass:xehn-apk `
    --ks-key-alias xehn --v1-signing-enabled true --v2-signing-enabled true `
    --out $out "$build\aligned.apk"
if ($LASTEXITCODE -ne 0) { throw 'apksigner failed' }

Write-Host '== verify =='
& "$bt\apksigner.bat" verify -v $out | Select-Object -First 4
& "$bt\aapt2.exe" dump badging $out | Select-String 'package:|sdkVersion|targetSdkVersion|native-code|launchable-activity' | ForEach-Object { $_.Line }
Get-Item $out | Select-Object FullName, @{n='MB'; e={ [math]::Round($_.Length / 1MB, 2) }}















