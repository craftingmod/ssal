$ErrorActionPreference='Stop'
bun scripts/property-area-prototype/fetch.js
if ($LASTEXITCODE -ne 0) { throw 'source fetch failed' }
$root='out/property-area-prototype'
New-Item -ItemType Directory -Force "$root/include/system_properties", "$root/include/platform/bionic", "$root/include/sys" | Out-Null
@'
#pragma once
#include <atomic>
using std::atomic_uint_least32_t;
using std::memory_order;
using std::memory_order_relaxed;
using std::memory_order_consume;
using std::memory_order_release;
using std::atomic_load_explicit;
using std::atomic_store_explicit;
'@ | Set-Content "$root/include/stdatomic.h"
Copy-Item "$root/source/prop_info.h" "$root/include/system_properties/prop_info.h"
$h=Get-Content -Raw "$root/source/prop_area.h"
$h=$h.Replace('#include <sys/mman.h>', '#include <windows.h>' + "`n" + '#define munmap(p,n) UnmapViewOfFile(p)')
[IO.File]::WriteAllText("$PWD/$root/include/system_properties/prop_area.h",$h)
@'
#pragma once
#define BIONIC_DISALLOW_COPY_AND_ASSIGN(T) T(const T&)=delete; T& operator=(const T&)=delete
#define BIONIC_DISALLOW_IMPLICIT_CONSTRUCTORS(T) T()=delete; BIONIC_DISALLOW_COPY_AND_ASSIGN(T)
#define __BIONIC_ALIGN(value, alignment) (((value) + (alignment) - 1) & ~((alignment) - 1))
'@ | Set-Content "$root/include/platform/bionic/macros.h"
'#define PROP_VALUE_MAX 92' | Set-Content "$root/include/sys/system_properties.h"
$source=Get-Content -Raw "$root/source/prop_area.cpp"
$at=$source.IndexOf('void* prop_area::allocate_obj(')
if($at -lt 0) { throw 'Unexpected upstream source' }
$source='#include <new>' + "`n" + '#include "system_properties/prop_area.h"' + "`n" + $source.Substring($at)
[IO.File]::WriteAllText("$PWD/$root/area-port.cpp",$source)
$vc='C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
if (!(Test-Path $vc)) { throw 'Visual Studio C++ tools required; update vcvars path' }
bun scripts/property-aosp/fetch.js
if($LASTEXITCODE -ne 0) { throw 'serializer sources unavailable' }
$core='out/guest-property-validation-v2/aosp/property_service'
New-Item -ItemType Directory -Force "$root/include/android-base" | Out-Null
Copy-Item scripts/property-aosp/strings.h "$root/include/android-base/strings.h"
$parser=Get-Content -Raw "$core/libpropertyinfoparser/property_info_parser.cpp"
$offset=$parser.IndexOf('bool PropertyInfoAreaFile::LoadDefaultPath()')
if($offset -lt 0) { throw 'Unexpected serializer parser source' }
$parser=$parser.Substring(0,$offset).Replace('#include <sys/mman.h>','').Replace('#include <unistd.h>','') + "`n} // namespace properties`n} // namespace android`n"
[IO.File]::WriteAllText("$PWD/$root/parser-port.cpp",$parser)
$serializer='"'+$vc+'" >nul && clang-cl /nologo /EHsc /std:c++17 /D_CRT_SECURE_NO_WARNINGS /FIcstring /I'+$root+'\include /I'+$core+'\libpropertyinfoserializer\include /I'+$core+'\libpropertyinfoparser\include /Fo'+$root+'\ /Fe'+$root+'\serializer.exe scripts\property-aosp\harness.cpp '+$core+'\libpropertyinfoserializer\property_info_file.cpp '+$core+'\libpropertyinfoserializer\property_info_serializer.cpp '+$core+'\libpropertyinfoserializer\trie_builder.cpp '+$core+'\libpropertyinfoserializer\trie_serializer.cpp '+$root+'\parser-port.cpp'
cmd /c $serializer
if($LASTEXITCODE -ne 0) { throw 'serializer build failed' }
$lines=& "$root/serializer.exe" scripts/property-area-prototype/queries.txt scripts/property-area-prototype/contexts.txt
if($LASTEXITCODE -ne 0 -or ($lines -join "`n") -notmatch 'BUILD_OK' -or ($lines -join "`n") -notmatch "LOOKUP`tdemo.only`tu:object_r:ssal_private_prop:s0`tstring" -or ($lines -join "`n") -notmatch "LOOKUP`tdemo.name`tu:object_r:ssal_demo_prop:s0`tstring") { throw 'synthetic serializer test failed' }
Write-Host 'PASS: synthetic context serializer and exact/prefix lookup'
$cmd='"'+$vc+'" >nul && clang-cl /nologo /EHsc /std:c++17 /I'+$root+'\include /Fo'+$root+'\ /Fe'+$root+'\prototype.exe scripts\property-area-prototype\harness.cpp scripts\property-area-prototype\adapter.cpp '+$root+'\area-port.cpp '+$root+'\source\prop_info.cpp'
cmd /c $cmd
if($LASTEXITCODE -ne 0) { throw 'build failed' }
$test=Join-Path $PWD "$root/test-$([guid]::NewGuid())"
New-Item -ItemType Directory $test | Out-Null
try { & "$root/prototype.exe" $test; if($LASTEXITCODE -ne 0) { throw 'test failed' } }
finally { Remove-Item -LiteralPath $test -Recurse -Force }
