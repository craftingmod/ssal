$ErrorActionPreference = 'Stop'
bun scripts/property-aosp/fetch.js
if ($LASTEXITCODE -ne 0) { throw 'AOSP source fetch failed' }
New-Item -ItemType Directory -Force out/guest-property-validation-v2/shim/android-base | Out-Null
Copy-Item scripts/property-aosp/strings.h out/guest-property-validation-v2/shim/android-base/strings.h
$path='out/guest-property-validation-v2/aosp/property_service/libpropertyinfoparser/property_info_parser.cpp'
$source=Get-Content -Raw $path
$at=$source.IndexOf('bool PropertyInfoAreaFile::LoadDefaultPath()')
if ($at -lt 0) { throw 'AOSP parser source layout changed' }
$source=$source.Substring(0,$at).Replace('#include <sys/mman.h>','').Replace('#include <unistd.h>','')
$source+="`n} // namespace properties`n} // namespace android`n"
[System.IO.File]::WriteAllText((Join-Path (Get-Location) 'out/guest-property-validation-v2/parser-port.cpp'),$source)
$vcvars='C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
if (!(Test-Path $vcvars)) { throw 'Visual Studio Community vcvars64.bat not found; adjust build script for this machine' }
$command='"' + $vcvars + '" >nul && clang-cl /nologo /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS /FIcstring /Iout\guest-property-validation-v2\shim /Iout\guest-property-validation-v2\aosp\property_service\libpropertyinfoserializer\include /Iout\guest-property-validation-v2\aosp\property_service\libpropertyinfoparser\include /Foout\guest-property-validation-v2\ /Feout\guest-property-validation-v2\aosp-harness.exe scripts\property-aosp\harness.cpp out\guest-property-validation-v2\aosp\property_service\libpropertyinfoserializer\property_info_file.cpp out\guest-property-validation-v2\aosp\property_service\libpropertyinfoserializer\property_info_serializer.cpp out\guest-property-validation-v2\aosp\property_service\libpropertyinfoserializer\trie_builder.cpp out\guest-property-validation-v2\aosp\property_service\libpropertyinfoserializer\trie_serializer.cpp out\guest-property-validation-v2\parser-port.cpp'
cmd /c $command
if ($LASTEXITCODE -ne 0) { throw 'AOSP harness build failed' }
bun scripts/compare-guest-property-aosp.js
if ($LASTEXITCODE -ne 0) { throw 'Comparison failed' }
