# SSAL SurfaceFlinger — Astra 사전 조사

- 조사일: 2026-11-19
- 목적: Android 16 LineageOS 23.2 GSI의 DisplayManager 시작 대기와 Headless SystemReady 선행 조건을 근거와 함께 정리한다.
- 범위: 기존 로그, 이미지, SSAL 소스, Android 16/LineageOS 소스를 읽기만 했다. 소스·이미지·정책·Host 상태를 수정하지 않았고, 실기기 부팅·SurfaceFlinger/HAL 실행·mount/Binder 등록 실험은 하지 않았다.

## 1. Executive Summary

현재 확인된 최초 차단은 SurfaceFlinger의 응답 지연이 아니라 Guest ServiceManager에서 SurfaceFlingerAIDL Binder 객체를 얻기 전의 waitForService() 대기다.

- 사용 이미지 out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img는 2,733,260,800 bytes, SHA-256 7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff다. fingerprint는 google/lineage_arm64_bvN4/generic_arm64:16/BP4A.251205.006/eng.andrew:userdebug/release-keys, SDK 36 / 36.1, 보안 패치 2026-05-01이다. 공식 AOSP build-number 표의 BP4A.251205.006 대응 태그는 android-16.0.0_r4지만, 정확한 GSI manifest와 LineageOS source commit은 현재 자료에 없다. lineage-23.2 브랜치와 AOSP android16-qpr2-release는 비교 기준이며 바이너리와 같은 commit이라고 확정하지 않는다.
- 실행 기록에서 Guest system_server PID 27208은 2026-11-18 17:58:33.719에 StartDisplayManager에 진입했다. 1.006초 뒤부터 18:01:32.996까지 매초 Waited one second for SurfaceFlingerAIDL 경고가 기록됐다. 같은 PID의 stack은 DisplayManagerService 생성자 → SurfaceControl.getCompositionColorSpaces → nativeGetCompositionDataspaces 안에서 멈춰 있다. 이 시점은 생성자 실행 중으로 onStart()와 기본 display adapter 등록까지 도달하지 않았다.
- waitForService()가 반환한 IBinder가 없으므로 관측된 실행에서 ISurfaceComposer 원격 메서드는 호출되지 않았다. Binder 서비스 등록/획득 대기와 이미 획득한 서비스의 RPC 응답 대기는 다르다. 이번 로그는 전자다. Guest ServiceManager가 관측 시점에 해당 이름의 Binder를 제공하지 않은 것은 확인되지만, SF 프로세스 부재, init 시작 실패, SF 초기화 중 등록 전 정지 중 어느 것이 원인인지는 이 로그만으로 판별할 수 없다.
- Binder를 획득한 뒤 이 코드 경로의 첫 android.gui.ISurfaceComposer 원격 호출은 getCompositionPreference()다. 반환 AIDL parcelable은 기본 dataspace/pixel format과 wide-gamut dataspace/pixel format의 4개 int다. JNI는 기본 및 wide-gamut dataspace 두 값을 Java 배열로 돌려준다. 성공 시 생성자 다음 호출은 getOverlaySupport()이고 반환 타입은 OverlayProperties다. 둘 다 현재 실행에서 도달하지 못했다.
- SSAL 실행에서 Guest ServiceManager와 private /dev/binder는 확인됐고 Host와 분리된 Binder device identity 및 HOST_SNAPSHOT=UNCHANGED도 기록됐다. 반면 Guest ctl.interface_start=aidl/SurfaceFlingerAIDL 시도는 property control 처리 오류를 냈고 Guest VINTF 조회는 /vendor/etc/vintf/manifest.xml을 Permission denied로 읽지 못했다. Host SurfaceFlinger/HWC가 Guest에 제공된다고 볼 수 없다.
- GSI에는 /system/bin/surfaceflinger와 플랫폼 EGL/GLES/Vulkan 및 graphics Binder/HIDL 라이브러리가 있다. 이는 실행 파일과 client library 존재를 확인할 뿐, Galaxy Host의 composer/HWC·mapper·allocator 서비스, GPU 장치 접근, 또는 Guest SurfaceFlinger의 정상 초기화를 입증하지 않는다.

## 2. Call Graph

### 실제 실행에서 관측된 경로

1. SystemServer.startBootstrapServices()
2. SystemServiceManager.startService(DisplayManagerService.class)
3. DisplayManagerService 생성자
4. SurfaceControl.getCompositionColorSpaces()
5. SurfaceControl.nativeGetCompositionDataspaces()
6. JNI android_view_SurfaceControl.cpp
7. SurfaceComposerClient::getCompositionPreference()
8. ComposerServiceAIDL::getComposerService()
9. ComposerServiceAIDL::connectLocked()
10. waitForService<android.gui.ISurfaceComposer>("SurfaceFlingerAIDL")
11. 관측 지점: Binder 객체 미수신으로 계속 대기

근거:

1. LineageOS 23.2의 SystemServer.startBootstrapServices()에서 StartDisplayManager trace 다음에 startService(DisplayManagerService.class)가 실행된다. 실제 Java stack의 SystemServer.java:1343은 이 브랜치의 해당 호출 행과 일치한다. AOSP android16-qpr2-release 소스는 이 지점이 몇 행 앞에 있어 비교 자료이지 동일 commit 증거가 아니다.
2. SystemServiceManager.startService()는 서비스를 생성하며, 실행 stack이 DisplayManagerService.java:708의 생성자 호출에 들어간다. 해당 생성자는 708행에서 SurfaceControl.getCompositionColorSpaces()를, 다음 710행에서 SurfaceControl.getOverlaySupport()를 호출한다.
3. SurfaceControl.getCompositionColorSpaces()는 nativeGetCompositionDataspaces()를 호출한다. JNI 함수는 SurfaceComposerClient::getCompositionPreference()를 호출하고, 성공하면 기본/wide-gamut dataspace를 Java int 배열에 담는다.
4. SurfaceComposerClient::getCompositionPreference()는 ComposerServiceAIDL::getComposerService()를 통해 gui::ISurfaceComposer proxy를 얻은 뒤 getCompositionPreference(&pref)를 호출한다. proxy 연결 함수는 서비스명 SurfaceFlingerAIDL에 대해 waitForService<gui::ISurfaceComposer>()를 호출한다.
5. SSAL 로그의 반복 경고는 libbinder.ServiceManagerCppClient: Waited one second for SurfaceFlingerAIDL이다. 별도로 boot.log:480–490에는 ctl.interface_start=aidl/SurfaceFlingerAIDL 설정 실패가 있다. 이 기록과 stack 위치는 Binder 서비스 획득 전 대기 판별을 뒷받침한다. 서비스 획득 뒤 getCompositionPreference() RPC 응답 대기로 해석할 근거는 없다.

### 소스에서 이어지지만 이번 실행에서 관측하지 않은 경로

waitForService 성공
→ ISurfaceComposer.getCompositionPreference() 동기 AIDL transaction
→ JNI int[2] 반환
→ DisplayManagerService.getOverlaySupport() 동기 AIDL transaction
→ DisplayManagerService.onStart()
→ 기본 display adapter 등록
→ LocalDisplayAdapter 이벤트 연결 및 물리 display ID/token/정보 질의
→ SystemServer PHASE_WAIT_FOR_DEFAULT_DISPLAY
→ 이후 startOtherServices()/systemReady() 경로

이어지는 순서는 소스에서 확인한 것이다.

- DisplayManagerService.onStart()는 persistent display data를 준비하고 MSG_REGISTER_DEFAULT_DISPLAY_ADAPTERS를 예약한 다음 DisplayManager binder service를 publish한다.
- registerDefaultDisplayAdapters()는 LocalDisplayAdapter와 VirtualDisplayAdapter를 등록한다. LocalDisplayAdapter.registerLocked()는 display event listener를 만들고 getPhysicalDisplayIds() 결과를 순회한다. 각 ID에 대해 Binder display token, static display info, dynamic display info를 조회한다.
- SystemServer는 DMS 시작 직후 PHASE_WAIT_FOR_DEFAULT_DISPLAY를 전달한다. DMS는 기본 논리 display가 생기고 virtual adapter가 준비될 때까지 기다리며, 기한까지 기본 display가 없으면 예외를 던진다.
- 이후 startOtherServices()의 LineageOS 23.2 경로에는 wm.systemReady(), mDisplayManagerService.systemReady(safeMode), mActivityManagerService.systemReady(...) 호출이 있다. 이들은 이번 로그에서 실행 확인된 결과가 아니라 소스 순서다.

### 이름과 transaction 경계

main_surfaceflinger.cpp는 하나의 SF 프로세스에서 서로 다른 두 Binder 서비스를 등록한다.

- legacy C++ ISurfaceComposer는 서비스명 SurfaceFlinger로 등록된다.
- 새로운 AIDL android.gui.ISurfaceComposer는 서비스명 SurfaceFlingerAIDL로 등록된다. 초기 composition preference 경로는 두 번째 이름을 사용한다.
- SurfaceFlinger main은 flinger->init()을 마친 뒤 두 서비스를 등록하고, 등록 뒤 display service와 main loop로 진행한다. 프로세스가 보이는 것만으로 SurfaceFlingerAIDL 등록 완료를 단정할 수 없다.
- 이후 SurfaceControl.Transaction.apply()의 layer transaction은 별도 legacy C++ 경로의 SurfaceComposerClient::Transaction::apply() → ISurfaceComposer::setTransactionState()를 사용한다. 이를 첫 getCompositionPreference() AIDL 호출과 혼동하면 안 된다.

## 3. AIDL Contract Matrix

| 인터페이스 / 메서드 | 호출 시점 및 caller | 반환 / Binder 객체 / FD | 안정성 및 SSAL 의미 |
|---|---|---|---|
| android.gui.ISurfaceComposer.getCompositionPreference() | DMS 생성자 → SurfaceControl JNI → SurfaceComposerClient::getCompositionPreference(); 첫 SF AIDL transaction | CompositionPreference: 기본 dataspace/pixel format, wide-gamut dataspace/pixel format의 4개 int. 이 호출 자체는 callback/FD를 반환하지 않는다. JNI는 dataspace 2개를 Java에 보낸다. | framework private AIDL (@hide, @VintfStability 없음). SurfaceFlingerAIDL은 일반 ServiceManager 이름이지 VINTF HAL instance가 아니다. 관측 실행은 이 메서드 전에서 정지했다. |
| android.gui.ISurfaceComposer.getOverlaySupport() | DMS 생성자의 다음 SurfaceControl 호출 | OverlayProperties parcelable. callback/FD 없음. | 위와 같은 framework AIDL. 소스에서 확정된 다음 호출이며 실행 확인은 아니다. |
| getPhysicalDisplayIds(), getPhysicalDisplayToken(id), getStaticDisplayInfo(id), getDynamicDisplayInfoFromId(id) | LocalDisplayAdapter.registerLocked()가 display를 열거할 때 | ID는 long[]; token은 nullable IBinder; static/dynamic display-info parcelable | 서비스 조회 뒤의 source-derived 호출. 토큰은 display 식별용 Binder 객체다. 실제 Galaxy 패널/ID/정보는 이 실행에서 조회하지 않았다. |
| createVirtualDisplay(...) / destroyVirtualDisplay(token) | 등록된 VirtualDisplayAdapter가 virtual display를 요청할 때; 초기 DMS 생성자 호출은 아님 | createVirtualDisplay()는 nullable IBinder display token을 반환하고 destroyVirtualDisplay()는 void다. 이 두 method signature에는 FD/callback이 없다. | framework private AIDL. adapter 등록 자체는 DMS startup에서 source-derived로 확인되지만, virtual display 생성은 일반적으로 별도 요청 시 경로다. 이 token만으로 기본 display를 대체할 수 있는지는 확인되지 않았다. |
| createDisplayEventConnection(...) / android.gui.IDisplayEventConnection | Local display event listener의 vsync/event 경로 | Composer가 IDisplayEventConnection Binder 객체를 반환한다. 이후 stealReceiveChannel(out BitTube)는 이벤트 수신용 BitTube를 전달한다. BitTube는 C++ private header 기반 custom parcelable이며 native channel FD 전달을 포함한다. requestNextVsync()는 oneway 성격이다. | 일반 framework AIDL object/callback 전달보다 복잡하다. FD가 포함된 BitTube의 정확한 Parcel/native-handle 처리는 별도 검증되지 않았다. |
| android.gui.ISurfaceComposer.createConnection() 및 android.gui.ISurfaceComposerClient.createSurface(...) | SurfaceControl client/layer 생성 경로 | ISurfaceComposerClient Binder 객체; createSurface()는 CreateSurfaceResult 반환(IBinder layer handle, layer ID/name, transform hint) | Android GUI framework private AIDL. Binder object 전달은 가능성이 있으나 이 exact interface는 SSAL에서 구현/시험하지 않았다. |
| legacy C++ android::ISurfaceComposer.setTransactionState() | SurfaceControl.Transaction.apply()의 후속 layer transaction | C++ TransactionState와 Parcel 기반. Surface/layer state를 전송한다. Native buffer/fence 경로에서 GraphicBuffer, native handle, fence FD가 추가로 얽힌다. | AIDL과 다른 native Binder interface 및 transaction marshalling이다. ISurfaceComposer.cpp에서 C++ onTransact와 TransactionState 처리. |
| android::IGraphicBufferProducer / BufferQueue | surface에 실제 buffer를 dequeue/queue할 때 | GraphicBuffer metadata/native handle, buffer slot, acquire/release fence 등의 native Parcel/FD payload; BufferQueue Binder endpoint | DMS의 초기 composition preference 질의에는 필요하지 않다. 실제 frame/surface 경로의 후속 의존성이며 RSBinder 구현 호환성은 미검증. |
| android.hardware.graphics.composer3.IComposer (AIDL HAL) 및 Composer HIDL 2.1–2.4 | SurfaceFlinger의 composer/HWC 연결 및 display 초기화 | composer3 createClient()는 IComposerClient Binder를 반환하고 registerCallback(IComposerCallback)는 callback Binder를 연결한다. hotplug/vsync/refresh callback이 있으며 buffer/fence 사용 method에는 ParcelFileDescriptor가 포함될 수 있다. | composer3는 @VintfStability vendor HAL 계열이다. GSI client wrapper/NDK 라이브러리가 있는 것과 실제 Host service/manifest instance는 별개다. 현재 Guest는 device VINTF를 읽지 못했다. |

ISurfaceComposer.aidl과 ISurfaceComposerClient.aidl은 @hide framework 인터페이스이며 VINTF 안정성 선언이 없다. 안정 VINTF AIDL에는 AIDL 파일의 @VintfStability 및 빌드의 stability: "vintf" 같은 조건이 필요하다. GUI interface의 수치 transaction code는 이 보고서에서 생성하지 않았다. AIDL 생성 코드가 method transaction을 정하며 숫자 자체를 안정 계약으로 사용하지 않는다.

### RSBinder 적용 경계

- SSAL의 tools/rsbinder/Cargo.toml은 현재 rsbinder/rsbinder-aidl 0.13.0과 android_16_plus feature를 선언한다.
- 기존 PoC는 scalar/string AIDL, 서비스 조회/등록, Binder callback/object 전달과 재연결을 확인했다. Phase 3 callback 실행 기록은 0.12.0을 사용한 시험이다. 현재 SSAL에는 apex/suspend 계열 Rust AIDL 서비스 등록 경로도 있다.
- CompositionPreference 같은 primitive 필드 parcelable, 배열, 표준 Binder interface skeleton은 같은 interface descriptor/Parcel 계약을 정확히 구현한다면 일반 AIDL 쪽에 속한다. 다만 android.gui exact service descriptor와 Android 16 generated interface는 별도 구현/시험되지 않았다.
- BitTube의 FD/channel custom parcelable, legacy C++ Parcel transaction, GraphicBuffer/AHardwareBuffer/native_handle 및 fence FD, BufferQueue semantics는 현재 PoC 결과로 보장되지 않는다. 이 구간은 native Binder/Parcel 구현 또는 검증된 맞춤 marshalling 경계가 필요하다. 불가능하다는 판정이 아니라 현재 SSAL에서 증거가 없다는 구분이다.

## 4. GSI Dependency Inventory

### 확인한 이미지 파일

| 항목 | 확인 내용 |
|---|---|
| 이미지 | out/LineageOS-23.2-20260524-VANILLA-EXT4-GSI.img, 2,733,260,800 bytes, SHA-256 7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff |
| 빌드 identity | fingerprint google/lineage_arm64_bvN4/generic_arm64:16/BP4A.251205.006/eng.andrew:userdebug/release-keys; Android 16, SDK 36 / 36.1; security patch 2026-05-01; incremental 1779626072 |
| SF ELF | /system/bin/surfaceflinger, AArch64 ET_DYN, 크기 9,676,784 bytes, 추출 ELF SHA-256 7a9999ea2f13e569c386a72fbb08400723e56365bc57d489829020a0be3bffe4 |
| libgui ELF | /system/lib64/libgui.so, 추출 ELF SHA-256 8a1bedd9336ed10f8927cc4fa7c1fd0a7c7c6b82b0e401952b6f337a7a3a2264 |
| init rc | /system/etc/init/surfaceflinger.rc는 /system/bin/surfaceflinger를 class core animation, user system, groups graphics drmrpc readproc, SYS_NICE로 설정한다. interface aidl SurfaceFlingerAIDL 선언은 없다. onrestart는 조건부 zygote 재시작을 요청한다. |
| VINTF | 이미지의 /system/etc/vintf/manifest.xml은 framework manifest이며 framework displayservice 및 scheduler HIDL 1.0 등 framework entries를 포함한다. SurfaceFlingerAIDL은 이 파일의 HAL declaration으로 등록되는 것이 아니라 SF process가 ServiceManager에 등록한다. 실제 device-side /vendor/etc/vintf/manifest.xml은 Host vendor 영역이며 이번 Guest에서는 읽기 거부가 관측됐다. |
| APEX | 이미지에서 com.android.runtime.apex, com.android.art.capex, com.android.i18n.apex, com.android.tzdata.apex, com.android.os.statsd.apex 등을 확인했다. SurfaceFlinger는 /system/bin과 플랫폼 /system/lib64에 있으며 전용 graphics APEX는 목록에서 확인되지 않았다. APEX 파일 존재는 해당 실행에서 mount/활성화됐다는 뜻이 아니다. |

ELF 의존성은 추출된 SF ELF에 llvm-readobj로 동적 dependency와 undefined symbol을 읽어 확인했다. 아래 48개는 DT_NEEDED이며 실행 가능성, 로딩 성공, vendor HAL 동작을 보장하지 않는다. RPATH/RUNPATH는 없었다.

| 계열 | 직접 DT_NEEDED |
|---|---|
| Service/framework/runtime | libpowermanager.so, android.adpf.sessionmanager_aidl-ndk.so, libtimestats_atoms_proto.so, libtracing_perfetto.so, server_configurable_flags.so, libpng.so, libz.so, libcrypto.so, android.os.flags-aconfig-cc-host.so, libaconfig_storage_read_api_cc.so, libbase.so, libbinder.so, libbinder_ndk.so, libfmq.so, libgui.so, libprotobuf-cpp-lite.so, libstatslog_surfaceflinger_bootstrap.so, libui.so, libcutils.so, libhidlbase.so, liblog.so, libprocessgroup.so, libsync.so, libutils.so, libSurfaceFlingerProp.so, libnativewindow.so, libc++.so, libc.so, libm.so, libdl.so |
| Graphics/HAL | android.hardware.common-V2-ndk.so, android.hardware.common.fmq-V1-ndk.so, android.hardware.configstore@1.0.so, android.hardware.configstore@1.1.so, android.hardware.configstore-utils.so, android.hardware.graphics.common@1.2.so, android.hardware.graphics.composer@2.1.so, android.hardware.graphics.composer@2.2.so, android.hardware.graphics.composer@2.3.so, android.hardware.graphics.composer@2.4.so, android.hardware.graphics.allocator@2.0.so, android.hardware.graphics.allocator@3.0.so, android.hardware.drm.common-V1-ndk.so, android.hardware.graphics.composer3-V4-ndk.so, libEGL.so, libGLESv1_CM.so, libGLESv2.so, libvulkan.so |

표의 합계는 48개다. 이미지에는 위 직접 의존성 외에도 graphics allocator/mapper AIDL 및 HIDL wrapper, graphics common, libgralloctypes, libgraphicsenv, GLES v3와 ANGLE 계열 라이브러리가 있다. 공유 라이브러리 존재만으로 GPU driver, mapper HAL 구현, gralloc allocator service, HWC instance가 이미지 안에 있거나 활성이라는 뜻은 아니다.

### 실제 ELF가 보여주는 하드웨어 경계

- surfaceflinger의 undefined symbols에는 AServiceManager_isDeclared, AServiceManager_waitForService, HIDL composer IComposer::getService(), eglGetDisplay/eglInitialize, vkGetInstanceProcAddr, GraphicBuffer/GraphicBufferMapper/GraphicBufferAllocator, IGraphicBufferProducer의 requestBuffers/queueBuffers/dequeueBuffers/exportToParcel, SurfaceComposerClient::Transaction의 apply/setBuffer가 있다.
- EGL/GLES/Vulkan 호출과 composer3/HIDL composer 의존성은 바이너리에서 확인됐다. 실제 RenderEngine backend, GPU driver, HWC service가 이 기기에서 선택·로딩되는지는 확인되지 않았다.
- libdrm.so 또는 별도 RenderEngine DSO는 SF의 직접 DT_NEEDED 목록에 없다. DRM/KMS 사용이 없다는 뜻은 아니다. 경로가 HWC/커널 driver 또는 다른 라이브러리 내부로 갈 수 있다.
- HWC/composer, allocator, mapper는 실제 사용 시 별도 HAL Binder endpoint와 callback/버퍼 계약에 의존할 수 있다. 정확한 active instance/version은 /vendor/etc/vintf/manifest.xml을 읽지 못해 미확인이다.
- /dev/dri, /dev/graphics, /dev/kgsl 같은 GPU/DRM device를 SF에 제공하는 구성은 이번 GSI/Guest namespace에서 확인되지 않았다. Guest /dev 생성 코드와 run log는 /dev/binder 외에 null/zero/random/urandom만 허용하고 Host Binder/property/HAL node가 없다고 기록한다. /sys는 새로운 read-only sysfs mount여서 GPU sysfs가 보이거나 읽히는지는 별도 확인되지 않았다.
- GSI 추출은 읽기 전용 7z 파일 조회로 했다. 도구가 이미지 말미의 43,212,800 bytes를 archive 뒤 데이터로 경고했지만 필요한 system 파일은 추출/해시 확인됐다. 이미지는 수정하거나 mount하지 않았다.

## 5. SSAL Capability Matrix

| 영역 | 현재 확인된 기능 | SurfaceFlinger 관점의 경계 |
|---|---|---|
| Guest Binder/ServiceManager | private BinderFS와 Guest /dev/binder, Guest ServiceManager reachability, custom AIDL 서비스 조회/등록 및 callback 전달 기록이 있다. 2026-11-19 run의 Host snapshot은 unchanged다. | framework가 SurfaceFlingerAIDL로 접근할 수 있는 것은 아니다. 현재 실행에는 해당 service Binder 객체가 반환되지 않았다. |
| AIDL/RSBinder | scalar/string/custom parcelable, Binder object와 callback, 등록/조회가 검증된 범위다. current dependency는 rsbinder 0.13.0이며 Guest 서비스 코드에는 apex/suspend 관련 AIDL 경로가 있다. | android.gui SurfaceFlinger contract, BitTube FD, GraphicBuffer/native Parcel 및 graphics HAL은 구현/검증되지 않았다. |
| Service supervisor / init control | BootService 목록은 servicemanager, apexd, zygote다. 별도 ctl registry는 명시 등록된 서비스만 ctl.interface_start/stop/restart로 연결하고 기본 설정은 서비스 정의가 비어 있다. | SF를 자동 시작하거나 GSI init rc 전체를 실행하지 않는다. SF 또는 aidl/SurfaceFlingerAIDL에 대한 Guest registry 등록 근거가 없다. surfaceflinger.rc에도 AIDL interface alias가 없다. |
| HAL broker | SSAL 소스에서 composer/graphics HIDL 또는 AIDL HAL용 generic broker 구현은 확인되지 않았다. | Host hwservicemanager/HIDL, composer3, mapper/allocator에 대한 Guest proxy나 안전한 접근 경로는 확인되지 않았다. |
| mount namespace | profile은 새 Guest /dev, 새 read-only /sys, read-only Host /vendor, /odm, /vendor_dlkm, private Binder를 사용한다. 실행 기록에서 Guest Binder device는 234:5, Host는 234:1이다. | GPU/HWC device nodes를 Guest /dev에 bind/create하는 graphics 경로는 없다. /vendor는 읽기 전용 bind지만 Guest VINTF manifest read는 -13 Permission denied였다. /sys의 장치별 가시성/권한은 불명이다. |
| SELinux | Guest session-specific type/label 경로와 private Binder label이 사용된다. 로그에는 ssal_p0001_surfaceflinger_display_prop property label이 보인다. | property label은 SF process domain 또는 GPU/HWC permission 증거가 아니다. Guest SurfaceFlinger process transition, HWC/graphics access, 실제 AVC 결과는 측정하지 않았다. Host policy는 읽기 전용으로 유지했다. |
| SurfaceFlinger 실행 | GSI binary와 rc가 있고 Host SurfaceFlinger는 별도 Host process로 기존 기기 audit에 기록돼 있다. | 이번 실행에서 Guest SurfaceFlinger를 시작하지 않았다. Guest SF 실행, HWC 연결, display 초기화, frame/transaction 처리는 전부 미검증이다. |
| Guest/Host 분리 | 같은 run에서 private Binder identity, Guest context manager, HOST_SNAPSHOT=UNCHANGED가 기록됐다. 이전 device audit에는 Host SurfaceFlinger PID 1537이 기록돼 있다. | private Binder와 mount namespace는 Binder/device name을 나누지만 물리 GPU/HWC/kernel state를 복제하지 않는다. 실제 SF가 Host panel이나 power/display 상태를 바꾸지 않는다는 증거는 없다. |

## 6. Headless Boot Dependency Map

분류:

- **Confirmed:** 현재 이미지·로그·SSAL 소스에서 직접 확인.
- **Source-derived:** Android 16/LineageOS 23.2 브랜치 소스에 있으나 이 Guest 실행에서는 도달/검증하지 않음.
- **Hypothesis:** 다른 관측과 맞는 가능성이나 현재 자료로 확인하지 못함.
- **Unknown:** 현재 자료에서 결론을 낼 수 없음.

| 분류 | 단계 / caller | 대상 및 필요한 계약 | SSAL 지원 | 증거 |
|---|---|---|---|---|
| Confirmed | system_server → Guest ServiceManager | SurfaceFlingerAIDL 이름으로 IBinder 획득; 아직 method RPC 전 | Guest private Binder/ServiceManager는 있음. SurfaceFlingerAIDL Binder는 관측되지 않았고 wait가 계속됨. | stderr.log:1295,2641–10006; sample-00.main-stack.txt:55–64; boot.log:197,225,480–490 |
| Confirmed | ServiceManager lazy-start 요청 | ctl.interface_start=aidl/SurfaceFlingerAIDL control dispatch | Guest ctl registry는 explicit mapping만 다룬다. SF mapping 근거 없음. 실제 run에서 control property 처리 실패. 오류 원인(등록 부재/권한/다른 init 연결)은 이 로그만으로 특정 불가. | boot.log:480–490; src/guest/properties/services.rs:18–73; docs/guest-ctl-experimental-20261118.md:47–69; GSI surfaceflinger.rc:1–7 |
| Source-derived | DisplayManagerService constructor | getCompositionPreference() → CompositionPreference; 다음 getOverlaySupport() → OverlayProperties | Guest SurfaceComposer service/proxy 미구현. 원격 호출 전 대기 상태만 확인됨. | LOS DisplayManagerService.java:708–710; SurfaceComposerClient.cpp:154–160,2989–3001; JNI android_view_SurfaceControl.cpp:1850–1873 |
| Source-derived | DisplayManagerService.onStart() → LocalDisplayAdapter | display event connection Binder; BitTube event channel/FD; long[] physical IDs; nullable display-token Binder; static/dynamic info | 물리 display/HWC provider와 BitTube FD marshalling 미제공·미검증. | LOS DisplayManagerService.java:735–753,2363–2380; LocalDisplayAdapter.java:124–151; DisplayControl JNI:160–195; AIDL links below |
| Source-derived | SystemServer.PHASE_WAIT_FOR_DEFAULT_DISPLAY → DMS | Display.DEFAULT_DISPLAY 논리 display와 VirtualDisplayAdapter 준비. 시간 초과면 RuntimeException. | 현재 Guest 실행은 생성자에서 막혀 이 phase에 도달하지 않았다. default display provider/record가 없다. | LOS SystemServer.java:1346–1349; DisplayManagerService.java:756–779 |
| Source-derived | SurfaceFlinger 초기화 → HWC/composer | composer AIDL/HIDL client, callback/display enumeration, 실제 display 구성; EGL/GLES/Vulkan 및 allocator/mapper 경로 | GSI에는 client libraries가 있다. Guest VINTF read, HWC service, GPU node, mapper/allocator endpoint는 검증되지 않았다. | GSI ELF dependency/symbol inventory; main_surfaceflinger.cpp:142–158; Guest VINTF error boot.log:398–405,473–479 |
| Source-derived | WindowManager/SurfaceControl layer 생성 | ISurfaceComposerClient Binder와 CreateSurfaceResult; 후속 legacy setTransactionState, BufferQueue producer, GraphicBuffer/native handle/fence FD | RSBinder generic callback 시험은 있으나 GUI custom/native payload 구현은 없다. | AIDL ISurfaceComposerClient.aidl:25–63, CreateSurfaceResult.aidl:19–25; legacy ISurfaceComposer.cpp; SF ELF symbols |
| Source-derived | startOtherServices()/framework readiness | 소스상 WMS systemReady(), DMS systemReady(), AMS systemReady() 순서; display service와 default display가 선행 조건 | 이번 system_server는 DMS 생성자에서 멈춰 이들 호출을 실행하지 않았다. | LOS SystemServer.java:3182,3246,3360; runtime stack |
| Hypothesis | Guest SurfaceFlinger가 현재 Host vendor/HWC 자원을 직접 사용할 수 있는지 | RO /vendor 파일만으로 충분하지 않고 Guest에서 올바른 composer service namespace, device nodes, linker namespace, SELinux 권한이 모두 맞아야 한다는 가능성 | 실제 SF process/HAL/device 접근을 실행하지 않아 판단 불가. | mount profile, Guest /dev allowlist, boot.log:19,398–405 |
| Unknown | 대체 logical/virtual display가 기본 display 요건을 만족하는지 | DMS는 default logical display와 virtual adapter를 기다린다. SF 없는 stub이 어떤 token/display info/event를 제공해야 하는지는 runtime 미확인. | 지원 여부를 입증하는 SSAL 코드/로그 없음. | LOS DMS:758–779; 실행은 더 앞에서 중단 |
| Unknown | Galaxy에서 실제 사용할 HAL version/service instance/device node | composer3 AIDL, composer HIDL 2.x, mapper/allocator 세대, DRM/KMS/GPU 장치 선택 | Guest device manifest는 접근 거부; Host vendor tree/HAL을 열거하지 않음. | boot.log:398–405,473–479; GSI ELF는 client support만 확인 |

표의 future 단계는 정적 호출 관계다. onStart, display enumeration, 기본 display wait, WindowManager나 framework systemReady()가 현재 실행에서 성공했다고 나타내지 않는다. result.txt의 worker_exit=0 또한 Android SystemReady 완료 의미가 아니다.

## 7. Unresolved Questions

1. 제공 GSI를 만든 정확한 LineageOS manifest revision은 무엇인가? fingerprint/build number만으로 Android build tag는 좁힐 수 있어도 Lineage/vendor manifest commit은 확정되지 않았다.
2. SurfaceFlingerAIDL Binder가 Guest ServiceManager에 없는 직접 원인은 무엇인가? SF가 실행되지 않았는지, init/lazy-start mapping이 없는지, SF의 init()이 등록 전에 막혔는지 현재 로그는 분리하지 못한다.
3. 실제 Host Galaxy가 제공하는 composer/HWC, allocator, mapper service의 interface/version/instance와 사용할 device node는 무엇인가? 이번 Guest에서 Host vendor VINTF 읽기는 실패했다.
4. 현재 private /dev·Guest SELinux 경계에서 SurfaceFlinger가 실제 HWC/GPU 경로를 초기화할 때 필요한 장치 및 공유 커널 자원은 무엇인가? ELF와 mount 코드만으로 open/permission/driver 동작을 확정할 수 없다.
5. SF 없이 또는 software/virtual display backend로 DMS의 기본 논리 display와 boot phase 조건을 만족해 SystemReady까지 갈 수 있는가? 현재 실행과 소스만으로 필요한 최소 Binder object/event/display metadata의 실제 집합을 확정하지 못했다.

## 8. Evidence Index

### 이미지와 실행 로그

| 자료 | 검증 지점 |
|---|---|
| docs/system-server-phase8a-results.md:21 | 사용 GSI 경로, 크기, 이미지 SHA-256, fingerprint/build identity. 이전 문서의 system_server 미실행 상태는 2026-11-19 실행 전의 역사적 기록이다. |
| out/init-preflight-extract/system/build.prop:15–42 | fingerprint, BP4A build ID, incremental, SDK 36/36.1, Android 16. |
| out/init-preflight-extract/system/etc/init/surfaceflinger.rc:1–7 | 실제 GSI SF 실행파일과 class/user/group/capability/restart 설정; AIDL interface alias 없음. |
| out/system-suspend-default-20261119/time.txt:1–2, result.txt:1–5 | 분석한 SSAL run 시간, Guest system_server PID 27208, worker/observer exit 및 HOST_SNAPSHOT=UNCHANGED. |
| out/system-suspend-default-20261119/boot/phase7b/stderr.log:1295,2641–10006 | StartDisplayManager 및 반복 1초 SurfaceFlingerAIDL wait 경고. 주요 표본은 2641–2652, 마지막은 10006. 로그 시간은 해당 파일 표기 기준 2026-11-18 17:58:33–18:01:32. |
| out/system-suspend-default-20261119/samples/sample-00.main-stack.txt:55–64 | 실제 blocked Java stack: nativeGetCompositionDataspaces → getCompositionColorSpaces → DMS constructor → SystemServiceManager → SystemServer. |
| out/system-suspend-default-20261119/boot.log:19,196–198,225,398–405,473–490 | Guest /dev allowlist, private Binder device 234:5와 Host 234:1, Guest context manager, Guest VINTF permission error, ctl.interface_start 오류. |
| docs/guest-ctl-audit-device-20261118.md:96 | 별도 이전 device audit에서 관찰한 Host SurfaceFlinger PID 1537 및 Host service PIDs. 11-19 run과 같은 시점의 PID 주장으로 쓰지 않는다. |

### SSAL 코드 및 기존 시험 기록

| 경로 | 확인 지점 |
|---|---|
| src/guest/initrc.rs:87–107 | SSAL BootService allowlist는 servicemanager/apexd/zygote이며 surfaceflinger는 없다. |
| src/guest/properties/services.rs:18–73 | ctl interface는 명시된 ServiceDefinition mapping을 사용한다. 기본 config에 SF mapping이 있다는 근거는 없다. |
| docs/guest-ctl-experimental-20261118.md:47–69 | services/interfaces 기본값과 ctl registry exact matching; interface mapping이 실제 Binder 등록을 대체하지 않는다는 계약. |
| module/profiles/mounts/initial.json:1–22; src/guest/mount/profile.rs:84–87; src/guest/mount/mod.rs:251–299; src/guest/mount/devices.rs:8–16 | Guest /dev, fresh RO /sys, read-only vendor/odm/vendor_dlkm 및 Host runtime bind 범위. |
| src/guest/binder.rs:56–178 | private BinderFS 생성, /dev/binder bind, Host device와 분리 검증. |
| tools/rsbinder/Cargo.toml:1–19; docs/rsbinder-phase3-results.md:106–110; docs/rsbinder-phase5a-results.md:14,62 | 현재 rsbinder 0.13 dependency와 기존 custom AIDL/callback 시험 범위. GUI/FD/native graphics contract 시험은 아니다. |
| docs/system-server-static-analysis.md:134–144 | 2026-11-04 정적 분석도 default display와 headless/virtual-display 경계를 미확인으로 남겼다. 그 문서의 실행 상태는 이번 run 이전의 기록이다. |

### 대응 소스와 버전 한계

실제 이미지의 정확한 manifest commit은 미확인이다. 아래 source line은 2026-11 시점 비교를 위해 사용했다. LineageOS 23.2 branch에서 SystemServer의 startService가 1343행이며 실행 Java stack도 1343행을 가리킨다. 이는 source shape 정합성이지 binary-to-source commit 증명이 아니다.

| 소스 | 주요 함수/행 | URL |
|---|---|---|
| LineageOS frameworks/base lineage-23.2 | SystemServer.startBootstrapServices: 1342–1349; later wm.systemReady: 3182, DMS: 3246, AMS: 3360 | [SystemServer.java](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/services/java/com/android/server/SystemServer.java#L1342) |
| LineageOS frameworks/base lineage-23.2 | DMS constructor 708–710; onStart 735–753; onBootPhase 756–779; adapter registration 2363–2380 | [DisplayManagerService.java](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/services/core/java/com/android/server/display/DisplayManagerService.java#L708) |
| LineageOS frameworks/base lineage-23.2 | local adapter event listener, physical display IDs/token/info: 124–151 | [LocalDisplayAdapter.java](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/services/core/java/com/android/server/display/LocalDisplayAdapter.java#L124) |
| LineageOS frameworks/base lineage-23.2 | Java native declaration 233–234; Java color-space mapping 2661–2681 | [SurfaceControl.java](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/core/java/android/view/SurfaceControl.java#L2661) |
| LineageOS frameworks/base lineage-23.2 | JNI nativeGetCompositionDataspaces 1850–1859; nativeGetOverlaySupport 1871–1873 | [android_view_SurfaceControl.cpp](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/core/jni/android_view_SurfaceControl.cpp#L1850) |
| LineageOS frameworks/base lineage-23.2 | display ID/token JNI 160–195 | [com_android_server_display_DisplayControl.cpp](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/services/core/jni/com_android_server_display_DisplayControl.cpp#L160) |
| LineageOS frameworks/native lineage-23.2 | AIDL ServiceManager wait 154–160; getCompositionPreference 2989–3001; physical display calls 1277–1294 | [SurfaceComposerClient.cpp](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/gui/SurfaceComposerClient.cpp#L154) |
| LineageOS frameworks/native lineage-23.2 | private ISurfaceComposer methods incl. virtual/physical display IDs/token, preference, overlay support | [ISurfaceComposer.aidl](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/gui/aidl/android/gui/ISurfaceComposer.aidl#L92), [ISurfaceComposerClient.aidl](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/gui/aidl/android/gui/ISurfaceComposerClient.aidl#L25), [CompositionPreference.aidl](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/gui/aidl/android/gui/CompositionPreference.aidl#L19) |
| LineageOS hardware/interfaces lineage-23.2 | composer3 VINTF AIDL: createClient, registerCallback, hotplug/vsync and fence-FD-bearing client methods | [IComposer.aidl](https://github.com/LineageOS/android_hardware_interfaces/blob/lineage-23.2/graphics/composer/aidl/android/hardware/graphics/composer3/IComposer.aidl#L22), [IComposerClient.aidl](https://github.com/LineageOS/android_hardware_interfaces/blob/lineage-23.2/graphics/composer/aidl/android/hardware/graphics/composer3/IComposerClient.aidl#L52), [IComposerCallback.aidl](https://github.com/LineageOS/android_hardware_interfaces/blob/lineage-23.2/graphics/composer/aidl/android/hardware/graphics/composer3/IComposerCallback.aidl#L24) |
| LineageOS frameworks/native lineage-23.2 | IDisplayEventConnection.stealReceiveChannel(BitTube) and custom FD type | [IDisplayEventConnection.aidl](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/gui/aidl/android/gui/IDisplayEventConnection.aidl#L26), [BitTube.aidl](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/gui/aidl/android/gui/BitTube.aidl#L19) |
| LineageOS frameworks/native lineage-23.2 | legacy C++ and AIDL registration names, after flinger->init() | [main_surfaceflinger.cpp](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/services/surfaceflinger/main_surfaceflinger.cpp#L142), [legacy ISurfaceComposer.cpp](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/gui/ISurfaceComposer.cpp#L60) |
| LineageOS frameworks/native lineage-23.2 | ServiceManager wait loop and lazy-start request for aidl/<name> | [IServiceManager.cpp](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/binder/IServiceManager.cpp#L660), [ServiceManager.cpp](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/cmds/servicemanager/ServiceManager.cpp#L881) |
| LineageOS frameworks/native lineage-23.2 | ISurfaceComposerClient.createSurface result fields | [CreateSurfaceResult.aidl](https://github.com/LineageOS/android_frameworks_native/blob/lineage-23.2/libs/gui/aidl/android/gui/CreateSurfaceResult.aidl#L19) |
| AOSP android16-qpr2-release | comparison baseline for SystemServer/framework/native behavior; branch differs by several SystemServer line offsets from LOS branch | [AOSP SystemServer.java](https://android.googlesource.com/platform/frameworks/base/+/android16-qpr2-release/services/java/com/android/server/SystemServer.java), [AOSP SurfaceComposerClient.cpp](https://android.googlesource.com/platform/frameworks/native/+/android16-qpr2-release/libs/gui/SurfaceComposerClient.cpp) |
| Android AIDL stability documentation | VINTF-stable AIDL requirements | [AIDL annotations](https://source.android.com/docs/core/architecture/aidl/aidl-annotations) |
| Android build-number mapping | BP4A.251205.006 → android-16.0.0_r4; this does not identify the LineageOS source manifest | [Build numbers and source tags](https://source.android.com/docs/setup/about/build-numbers#source-code-tags-and-builds) |
| GSI release lineage | LineageOS 23.2 2026-05-24 release family identified by local GSI.md; exact build manifest revision remains unknown | [release listing](https://github.com/MisterZtr/LineageOS_gsi/releases#release-v2026.05.24-lineage23.2) |
