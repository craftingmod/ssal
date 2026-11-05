$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "$env:LOCALAPPDATA/Android/Sdk" }
$tools = Get-ChildItem "$sdk/build-tools" -Directory | Where-Object { Test-Path "$($_.FullName)/lib/d8.jar" } | Sort-Object Name -Descending | Select-Object -First 1
if (!$tools) { throw 'Android SDK build-tools/d8.jar missing' }
$classes = "$repo/out/phase7fc/classes"
New-Item -ItemType Directory -Force $classes, "$repo/out/bin" | Out-Null
& javac --release 8 -d $classes "$repo/native/fork-probe/dev/ssal/probe/ForkProbe.java"
if ($LASTEXITCODE) { throw 'javac failed' }
& java -cp "$($tools.FullName)/lib/d8.jar" com.android.tools.r8.D8 --min-api 30 --output "$repo/out/bin/fork-probe.jar" "$classes/dev/ssal/probe/ForkProbe.class"
if ($LASTEXITCODE) { throw 'D8 failed' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$jar = [IO.Compression.ZipFile]::OpenRead("$repo/out/bin/fork-probe.jar")
try { if (!$jar.GetEntry('classes.dex')) { throw 'classes.dex missing' } } finally { $jar.Dispose() }
Get-FileHash "$repo/out/bin/fork-probe.jar" -Algorithm SHA256
