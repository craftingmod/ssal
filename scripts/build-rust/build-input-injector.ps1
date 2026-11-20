$ErrorActionPreference = 'Stop'
$repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "$env:LOCALAPPDATA/Android/Sdk" }
$tools = Get-ChildItem "$sdk/build-tools" -Directory | Where-Object { Test-Path "$($_.FullName)/lib/d8.jar" } | Sort-Object Name -Descending | Select-Object -First 1
if (!$tools) { throw 'Android SDK build-tools/d8.jar missing' }
$platform = Get-ChildItem "$sdk/platforms" -Directory | Where-Object { Test-Path "$($_.FullName)/android.jar" } | Sort-Object Name -Descending | Select-Object -First 1
if (!$platform) { throw 'Android SDK platforms/android.jar missing' }
$classes = "$repo/out/input-injector/classes"
New-Item -ItemType Directory -Force $classes, "$repo/out/bin" | Out-Null
& javac --release 8 -classpath "$($platform.FullName)/android.jar" -d $classes "$repo/native/input-injector/dev/ssal/input/InputInjector.java"
if ($LASTEXITCODE) { throw 'javac failed' }
& java -cp "$($tools.FullName)/lib/d8.jar" com.android.tools.r8.D8 --min-api 30 --output "$repo/out/bin/input-injector.jar" "$classes/dev/ssal/input/InputInjector.class"
if ($LASTEXITCODE) { throw 'D8 failed' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$jar = [IO.Compression.ZipFile]::OpenRead("$repo/out/bin/input-injector.jar")
try { if (!$jar.GetEntry('classes.dex')) { throw 'classes.dex missing' } } finally { $jar.Dispose() }
Get-FileHash "$repo/out/bin/input-injector.jar" -Algorithm SHA256
