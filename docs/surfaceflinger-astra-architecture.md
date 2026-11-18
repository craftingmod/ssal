# SSAL SurfaceFlinger 아키텍처 판정

2026-11-19 · Android 16 / LineageOS 23.2 arm64 GSI · 설계 결정, 실기기 검증 전

**주 설계는 Virtual Graphics Backend다.** GSI 원본 SurfaceFlinger(SF)와 DisplayManagerService(DMS)를 실행하고, Guest 전용 composer3 HAL이 **연결된 primary display 하나**를 제공한다. SF는 이를 물리 디스플레이로 열거하고, HAL은 Galaxy 패널 대신 Guest 메모리에 프레임을 표시한다. 앱, WindowManager(WM), SF가 쓰는 두 Binder 인터페이스와 BufferQueue는 GSI 구현을 그대로 사용한다. 첫 목표는 Guest의 일반 앱 하나가 display 0에 그린 화면을 외부 뷰어에서 보고 Guest 입력에 따라 바뀌는 것까지다.

**이 선택을 좌우하는 첫 실험은 composer 기동이 아니다.** 같은 Guest allocator/mapper로 만든 Android 그래픽 버퍼를 소프트웨어 EGL/GLES 렌더러가 읽고 쓴 뒤, 별도 프로세스가 그리기 완료 시점과 픽셀을 확인할 수 있어야 한다. 이를 통과하면 합성기 작업에 들어갈 근거가 생긴다. 실패하면 실패한 자원만 중개하는 Host Graphics Broker를 차선으로 검토한다. 세 후보 모두 원본 SF를 쓰므로 RenderEngine 자체를 초기화할 수 없는 경우에는 출력만 전달하는 broker로 복구할 수 없다.

[사전 조사서](surfaceflinger-astra-preflight.md)의 관측점은 Guest PID 27208이 DMS 생성자에서 `SurfaceFlingerAIDL` 객체를 기다린 시점이다. 아래 초기화와 display 0 경로는 소스 판독 결과다. 비교판은 fingerprint의 build ID에 대응하는 AOSP `android-16.0.0_r4`, LineageOS native `26f530ca`, base `1ef04f03`이다. GSI 제작 manifest가 없어 두 커밋을 실물 바이너리의 정확한 리비전으로 간주할 수 없다. [AOSP SF][a-sf] · [AOSP DMS][a-dms] · [관측 기록과 이미지 식별](surfaceflinger-astra-preflight.md#8-evidence-index)

## 1. SF가 서비스 이름을 게시하기까지

| 순서 | 원본 소스의 경로 | 등록에 대한 판정 |
|---|---|---|
| 1. 프로세스와 allocator 시작 옵션 | `main()`이 HIDL RPC pool을 설정하고 `startGraphicsAllocatorService()`를 호출한다. 속성이 켜진 경우 HIDL allocator 3.0, 이어서 2.0 passthrough 등록을 시도한다. 이후 private Binder pool과 SF 객체를 만든다. | main이 이 도우미의 반환값을 검사하지 않는다. 이 옵션 자체는 필수가 아니며 현대 AIDL allocator/mapper를 마련해 주지도 않는다. Guest 프로세스의 로더·Binder·필수 시스템 파일은 실제로 동작해야 한다. [main][main] |
| 2. RenderEngine | `chooseRenderEngineType → RenderEngine::create`가 threaded Skia 구현을 만들고 SF가 최대 texture/viewport 크기를 조회한다. GL은 Ganesh, Vulkan은 선택 조건에 따라 Ganesh 또는 Graphite다. GL은 EGL 초기화, 일반 context, surfaceless 또는 pbuffer, `eglMakeCurrent`가 필요하다. | **작동하는 백엔드 하나는 필수.** 일반 메모리에 그리는 Skia raster를 선택하는 분기는 없다. CPU 합성안을 쓰려면 CPU에서 EGL/GLES 또는 Vulkan 계약을 구현하는 드라이버가 필요하다. `EGL_DEFAULT_DISPLAY` 성공은 패널 점유를 뜻하지 않는다. [SF 선택·생성][sf-re] · [RenderEngine][re] · [GL][gl] |
| 3. Composer 획득과 callback | SF의 서비스명 기본값은 `default`다. 통상 짧은 이름은 `isDeclared`로 composer3 AIDL 여부를 결정한다. AIDL이면 private ServiceManager에서 기다려 `createClient`와 `registerCallback`을 호출한다. AIDL 선택이 안 되면 HIDL 2.1을 조회하고 지원 세대에 맞게 client를 만든다. | **실제 client와 초기 CONNECTED 통지 필수.** AIDL 서비스·client 획득 실패는 fatal이다. callback 등록 오류는 로그만 남길 수 있지만 초기 hotplug가 없으면 다음 관문에서 종료된다. 선언됐는데 서비스가 없는 경우 대기할 수 있다. HIDL fallback에는 별도의 Guest HIDL transport와 manager가 필요해 주 설계는 AIDL을 택한다. [선택][ch] · [AIDL][ac] · [HIDL][hc] |
| 4. Primary 구성 | callback이 pending event를 채운다. `configureLocked`가 이를 소비하고 HWC ID를 SF의 `PhysicalDisplayId`로 대응시킨다. `processHotplugConnect`는 mode 목록과 유효한 active config를 읽고 새 연결에 `BBinder` token을 만든다. primary를 commit해 `DisplayDevice`를 얻고 연결을 확인한 뒤 active mode의 주기로 Scheduler/EventThread를 초기화한다. | **대기 중인 hotplug, 구성 가능한 primary, 연결 상태가 필수.** `configureLocked` 반환값 자체는 event 유무만 본다. 뒤의 primary·연결 검사까지 지나야 한다. callback 등록에 응답하기 전에 초기 hotplug를 전달하는 방식으로 경쟁을 피한다. 단일 고정 모드, 안정적인 포트/ID, 일치하는 active config면 출발할 수 있다. EDID가 없는 legacy port ID 경로도 있다. [init 검사][sf-init] · [hotplug·token][sf-hot] · [ID 생성][hw-id] · [Scheduler][sched] |
| 5. Primary 버퍼와 gralloc | 위 primary commit **안에서** `processDisplayAdded → FramebufferSurface → setupNewDisplayDeviceInternal → Surface::allocateBuffers → BufferQueueProducer::allocateBuffers → GraphicBuffer`가 이어진다. 소비자 usage에는 `HW_FB / HW_RENDER / HW_COMPOSER`가 포함된다. GraphicBuffer는 mapper를 사용하고 allocator는 선택된 mapper 세대와 짝을 맞춘다. | **등록 전 할당 경로에 진입한다.** mapper 탐색은 5→4→3→2, 전부 없으면 fatal이다. 선택된 allocator 로드 실패도 fatal이다. 반면 개별 버퍼의 `initCheck` 실패는 사전 할당 루프가 기록하고 `void` 반환할 수 있다. 서비스 두 개가 보여도 usable framebuffer 확보 여부는 별도 확인해야 한다. [물리 surface][sf-fb] · [사전 할당 호출][sf-alloc] · [usage][fb] · [Surface][surf] · [BQ 오류][bqp] · [mapper][gm] · [allocator][ga] |
| 6. 게시와 첫 프레임 | primary 이후 나머지 display 변경, 예약된 `initializeDisplays`, power advisor 초기화, 조건부 shader cache 준비를 거쳐 `init()`가 반환한다. main이 `SurfaceFlinger`와 `SurfaceFlingerAIDL`을 순서대로 게시한 뒤 legacy display service와 SF loop로 진행한다. | **두 이름의 실제 조회와 호출로 게시를 확인한다.** shader 예열 완료, 앱의 첫 dequeue, vsync에 맞춘 present, 사용자에게 보이는 픽셀은 두 이름을 게시하는 조건이 아니다. [init 후반][sf-end] · [게시 순서][publish] |

Gralloc5에서 `libui`는 `android.hardware.graphics.allocator.IAllocator/default` 선언과 interface version ≥ 2를 확인한다. allocator가 반환한 suffix로 Android 16에서 `AServiceManager_openDeclaredPassthroughHal("mapper", suffix, …)`를 호출해 `AIMapper_loadIMapper`를 로드한다. **allocator는 Binder 서비스이고 mapper는 각 소비 프로세스에 로드되는 라이브러리다.** SF만 아니라 앱/HWUI와 출력 소비자의 linker namespace, ABI, metadata/import/free가 맞아야 한다. 초기 할당 시점도 분기에 따라 앞당겨진다. 예를 들어 AIDL composer client 버전 ≤ 1이며 clear-slot 옵션이 켜지면 client 생성 직후 1×1 버퍼 할당 실패가 fatal이다. [Gralloc5][gr5] · [구버전 AIDL 분기][ac-clear]

**소프트웨어 렌더러의 첫 후보는 SkiaGL + ANGLE + Android용 SwiftShader다.** AOSP Cuttlefish에도 ANGLE/`pastel` 조합이 있으나 gralloc에 minigbm, display 발견에 DRM을 쓰는 VM 설정이다. r4 SF의 직접 Vulkan 경로는 `SYNC_FD` semaphore의 import·export와 재수출 가능성을 검사한다. 같은 태그의 SwiftShader는 Linux FD로 `OPAQUE_FD`를 광고하며 이 조회에서 `SYNC_FD` 지원값을 주지 않는다. 이 두 소스를 그대로 조합한 직접 Vulkan 경로는 제외한다. SkiaGL은 GPU fence 대기가 안 되면 `sync_wait`, draw fence가 없으면 동기 submit 경로가 있다. 이것만으로 ANGLE의 Android native-buffer import나 앱 HWUI가 검증되지는 않는다. [Cuttlefish 설정][cf-vm] · [SF Vulkan 검사][vk-sync] · [SwiftShader semaphore][ss-sem] · [SkiaGL 동기화][gl-sync]

## 2. 물리 패널 없이 display 0이 생기는 조건

1. **DMS 생성과 게시.** 생성자가 SF AIDL에서 composition preference와 overlay 정보를 받아 진행한다. `onStart`는 기본 adapter 등록을 handler에 예약하고 Guest Binder에 `display`를 게시한다. 비동기 등록이므로 서비스 이름이 먼저 관측될 수 있다. [DMS 생성·시작][dms-start]
2. **LocalDisplayAdapter.** 이벤트 수신기를 설치하고 SF의 physical ID 목록을 순회한다. 각 ID에 살아 있는 token, static/dynamic info, mode 목록, 음수가 아닌 active mode ID, non-null desired mode specs가 필요하다. 실제 device 구성에는 목록과 일치하는 active mode가 필요하다. active color mode 오류에는 별도 복구 처리가 있다. 새 device는 ADDED 이벤트를 보내고 물리 주소와 `FLAG_ALLOWED_TO_BE_DEFAULT_DISPLAY`를 제공한다. 이 플래그는 이 리비전에서 첫 display에만 붙는 것이 아니다. [연결 검사][lda] · [주소와 플래그][lda-flag]
3. **LogicalDisplayMapper.** ADDED 처리에서 자격 있는 device가 오면 fallback layout에 default가 비어 있을 때 그 주소를 등록한다. 먼저 일반 logical ID로 device를 생성한 뒤 현재 layout을 적용한다. 주소가 repository의 실제 device에 대응하면 layout의 logical ID를 확보하고 underlying device를 배치·교환한다. default ID는 0이다. 정적 layout에 다른 주소가 지정돼 있으면 단순히 첫 device가 이를 덮어쓰지 않는다. 주소만 있는 XML로 장치를 생성할 수도 없다. [ADDED][ldm-add] · [fallback][ldm-fallback] · [layout 적용][ldm-layout] · [ID 배정][layout]
4. **기동 대기 해제.** DMS의 default 추가 처리가 대기자를 깨운다. `PHASE_WAIT_FOR_DEFAULT_DISPLAY`는 **logical display 0이 존재하고 VirtualDisplayAdapter 객체도 존재할 때** 해제된다. `getDisplayLocked(0)`는 disabled도 포함하므로, phase 통과와 실제 켜진 UI는 측정값이 다르다. [대기식][dms-wait] · [통지][dms-notify] · [조회 범위][ldm-get]

**AOSP에 있는 무패널 부팅 방식은 HAL이 연결된 대체 primary를 제공하는 것이다.** Android의 hotplug 지침에도 부팅 시 패널이 없으면 HAL이 CONNECTED와 placeholder mode를 보고하는 시나리오가 명시돼 있다. 이 HAL은 Guest 안에서 소프트웨어로 구현할 수 있다. 반대로 조사한 r4/23.2의 기본 adapter 등록 경로에는 HWC도 없이 display 0을 만드는 headless adapter가 없다. 일반 `createVirtualDisplay`는 별도의 생성 요청·token을 받아 `TYPE_VIRTUAL` device를 만들고 위 default 자격을 부여하지 않는다. VR용 adapter 조기 등록, 추가 overlay display, 기본 display **그룹** 소속만으로 SF의 primary 검사나 DMS의 ID 0 조건을 충족할 수 없다. placeholder가 부팅 조건을 만족해도 픽셀을 버리는 구현으로는 Guest UI를 완성할 수 없다. [AOSP 무패널 hotplug 규약][a-hot] · [기본·추가 adapter][dms-ad] · [virtual device 생성][vda] · [virtual flags][vda-flags] · [AOSP mapper][a-ldm]

## 3. 세 설계의 경계와 비용

| 후보 | 구현 범위와 외부 바이너리 | SSAL·SELinux 변경 | 유지비, 주된 실패 조건 |
|---|---|---|---|
| **Guest Native SF** | GSI SF + Guest가 독점할 수 있는 기존 composer와 그에 맞는 vendor allocator/mapper, EGL/Vulkan 드라이버. 독립 display endpoint가 이미 있다면 가장 적게 이식한다. Galaxy 내장 패널과 One UI의 composer client는 대상에서 제외한다. | Guest 기동 순서, 해당 ABI/VINTF/linker와 HAL domain, 검증된 독립 장치만 필요하다. HIDL 제품이면 Guest hwbinder/hwservicemanager도 추가된다. | 기종·OTA 결합이 가장 크다. 독점 가능한 출력·HAL instance의 증거가 없다. render-only GPU 접근이 가능해도 primary는 생기지 않는다. 참조 Goldfish조차 기존 composer client가 살아 있으면 새 client 생성을 거절한다. [참조 구현][gold-comp] |
| **Virtual Graphics Backend** **(주 설계)** | GSI SF/DMS/libgui + Guest composer3, Android arm64 allocator/mapper 한 쌍, 소프트웨어 EGL/GLES 드라이버, Guest 메모리 출력. 참조 HAL의 display/client/vsync 코드를 이식하고 DRM present를 교체한다. | 변경 중~대. Guest 전용 device VINTF와 mapper 선언, 읽기 전용 라이브러리 배치, linker namespace, supervisor 순서, Guest 서비스 라벨과 FD 권한을 추가한다. Host graphics HAL·장치 권한을 전제로 하지 않는다. | 구현 부담이 버퍼 상호운용과 fence에 집중되지만 삼성 display HAL·OTA와 분리된다. native buffer import, 앱 HWUI 연동, 느린 CPU 합성과 메모리 사용량이 실패 지점이다. 주 설계 선정은 **격리 조건에서의 상대적 구현 가능성**에 대한 판단이다. |
| **Host Graphics Broker** **(차선)** | Guest의 원본 SF와 대체 primary는 유지한다. Host의 제한된 offscreen 자원만 세션별 broker가 소유한다. 출력 전달만 필요하면 비보호 프레임 복사, allocator만 막히면 호환 mapper를 전제로 버퍼 공급, 렌더러가 막히면 Guest EGL/Vulkan frontend와 대응하는 Host offscreen backend까지 필요하다. | 변경 대~최대. Guest HAL 외에 양쪽 endpoint, peer 인증, 버퍼·동기화 프로토콜, disconnect/재시작 정리가 추가된다. Guest socket으로 요청하고 Host helper가 자체 그래픽 context를 소유한다. | 양쪽 ABI·driver·수명과 장애를 함께 관리한다. SSAL의 SystemSuspend 중개는 연결 구조의 선례다. graphics handle·fence·GPU 명령 호환의 증거는 아니다. 자원 한 종류의 중개로 결함을 해소할 수 있을 때만 채택한다. [SSAL 중개 기록](guest-vintf-system-suspend-20261119.md) |

**GPU 렌더링과 화면 제어는 각각 다른 권한이다.** 기본 구성은 Galaxy GPU도 쓰지 않는다. 향후 가속 후보는 KMS/scanout을 제어할 수 없는 독립 render endpoint 또는 broker 소유 offscreen context로 한정한다. GPU 노드명만으로 권한 분리를 단정하지 않는다. Host SF/HWC client 생성, Host display/layer token 전달, panel power/mode/brightness, DRM master·atomic modeset, framebuffer·backlight 직접 접근은 세 설계의 허용 경로에서 제외한다. Guest의 mode·전원은 Guest HAL 상태로 끝나야 한다. 특히 첫 local display의 brightness 미지원 시 LDA가 LightsManager로 우회하므로 lights/backlight도 Guest 경계에서 종결해야 한다. 첫 뷰어는 별도 컴퓨터에서 세션 출력을 표시한다. [LDA backlight 경로][lda-light]

## 4. UI를 끝까지 연결하는 계약

| 계약 | Guest Native SF | Virtual Graphics Backend | Host Graphics Broker |
|---|---|---|---|
| Framework Binder, 객체 수명 | 원본 SF가 private Binder에 legacy `SurfaceFlinger`와 `SurfaceFlingerAIDL`을 게시한다. AIDL은 preference, display 조회, client/layer 생성 등을 처리하고 legacy C++는 `setTransactionState`와 native Parcel을 처리한다. | 같은 GSI 구현을 사용한다. HAL의 stable composer3 AIDL은 framework의 private `android.gui` AIDL과 별개다. composer3 client·callback도 Guest 객체다. | 앞의 두 서비스와 모든 client, layer, display token을 Guest에 둔다. Host에는 요청별 자원 ID만 보낸다. Binder handle 번호는 다른 Binder context에서 재사용할 수 없다. [AIDL/legacy 근거](surfaceflinger-astra-preflight.md#3-aidl-contract-matrix) · [transaction 적용][sc-tx] |
| BufferQueue와 layer | 앱의 Surface/BLASTBufferQueue가 슬롯을 dequeue/queue하고 SF가 layer transaction으로 buffer를 받아 latch한다. vendor 경로는 자체 gralloc/HWC가 처리한다. | 같은 앱 경로에서 SF RenderEngine이 CLIENT layer를 합성한다. primary의 FramebufferSurface가 client target을 HWC에 건넨다. HAL은 validate/타입 변경/accept, `setClientTarget`, present 결과와 slot cache를 일관되게 처리한다. | 앱의 BufferQueue, 슬롯 번호, callback은 Guest 안에 둔다. 경계에는 완성 프레임 또는 별도 협상한 offscreen 자원만 넘긴다. Host가 느리거나 사라져도 보유 가능한 버퍼 수를 제한하고 Guest 슬롯을 반환한다. [BufferQueue][a-bq] · [composer 명령][hal-client] |
| GraphicBuffer, native_handle | 같은 vendor ABI의 allocator/mapper와 드라이버가 format, usage, stride, plane/offset, metadata와 handle의 FD+정수를 해석한다. | 기본은 SDR RGBA8888 한 모드. allocator가 내준 공유 backing을 mapper가 프로세스별로 import/free하고 GLES와 소비자가 같은 레이아웃으로 읽는다. 출력 복사에는 실제 mapper가 허용한 CPU usage/stride를 적용한다. `HW_FB` 사용만으로 CPU 읽기가 허용되지는 않는다. | 첫 경계는 Guest에서 복사한 비보호 픽셀과 검증된 크기·stride다. zero-copy는 양쪽 import ABI, layout/modifier, usage, FD 개수와 소유권이 왕복 검증된 경우만 사용한다. Unix FD 전달은 `SCM_RIGHTS`로 수신자 FD를 생성한다. 구조체 포인터나 FD 숫자를 보내는 방식은 성립하지 않는다. [GraphicBuffer flatten/import][grbuf] |
| Fence와 vsync | vendor가 제공하는 acquire/release/present fence와 해당 **독립 display**의 타이밍을 사용한다. | producer의 acquire fence가 완료된 뒤 읽고, 마지막 소비가 끝나야 release, 표시할 프레임을 latch한 시점에 맞춰 present 완료를 보고한다. HAL은 `setVsyncEnabled`에 따라 단조시계 기준 활성 mode 주기로 callback한다. SF Scheduler/EventThread가 앱의 `IDisplayEventConnection`과 BitTube FD를 제공한다. | Guest의 frame clock과 display token은 유지한다. 비동기 교차 소비에는 import 가능한 실제 sync_file과 명시적 FD 소유권이 필요하다. 동기 복사는 마지막 read/copy 완료 뒤에만 완료를 통지한다. socket ACK를 Android fence FD로 취급할 수 없다. [Android fence 의미][a-sync] · [AOSP timer 구현][gold-vsync] |
| Display 식별·출력 | HAL의 독립 출력 ID → Guest SF physical ID/token → DMS logical 0 → 독립 출력으로 이어진다. | Guest composer가 합성 primary를 CONNECTED로 유지하고 SF가 token을 발급한다. HAL ID, 64비트 SF physical ID, Java logical ID 0은 서로 다른 식별자다. 첫 hotplug·모드 질의·전원·present가 같은 display를 가리켜야 한다. | Host 출력 자원의 종료는 Guest primary의 unplug가 아니다. Host panel/token/vsync에 연결하지 않고 consumer를 재연결한다. 세 후보 모두 Guest SF 재시작 후 이전 Binder token을 폐기하고 재조회한다. [SF token 생성][sf-hot] · [default layout][ldm-layout] |

**출력 경로.** 첫 primary는 CLIENT 합성 결과를 Guest 소유 메모리에서 실제로 latch하고 이전 버퍼를 반환하는 offscreen display다. 초기 실험은 비보호 테스트 패턴만 사용한다. 사용자용 출력은 default 성립 후 Guest의 비보안 미러 display에 별도 consumer Surface를 붙이고, 읽을 수 있는 버퍼로 복사해 세션 뷰어에 전달한다. 미러 생성은 Guest 내부에서 적법한 projection 또는 해당 일반 영상 출력 권한을 갖는 주체가 수행한다. 미러가 느려지면 최신 완성 프레임만 유지한다. 입력이 필요하면 세션 입력을 Guest display 0의 Guest 입력 경로에만 전달한다. 이 출력·입력 연결은 구현할 부분이다. [DMS 미러 권한][dms-mirror] · [SF virtual surface와 primary surface][sf-fb]

원본 SF는 internal primary에 secure 상태를 부여할 수 있다. 합성 후 primary 버퍼 하나만 보는 HAL은 일반 RGBA에 이미 들어간 `FLAG_SECURE` 레이어를 식별할 수 없다. 따라서 실제 사용자 화면의 primary 버퍼를 외부로 직접 복사하지 않는다. 외부 출력에는 secure 표시를 하지 않은 미러를 쓰고 secure 레이어 마스킹과 protected buffer의 readback 거부를 검증한다. 미지원 HDR·보호 메모리·device composition을 지원한다고 광고하지 않는다. 비동기 작업이 남아 있는 동안 반환하는 가짜 signaled fence나 무조건적인 `-1` 역시 허용되지 않는다. 동기 경로에서 계약상 허용되는 no-fence와 실제 작업 실패는 별도로 기록한다. [primary 보안 상태][sf-sec] · [비보안 출력의 layer 검사][out-sec] · [동기 submit][gl-sync]

### 재사용할 부분과 SSAL이 제공할 부분

- **그대로 재사용** — 해당 GSI의 SF/libgui/libui, RenderEngine, BLAST/BufferQueue, Scheduler/EventThread/BitTube, DMS/LocalDisplayAdapter/LogicalDisplayMapper. Framework AIDL과 legacy C++ Parcel을 Rust로 다시 구현할 이유가 없다. 고정값을 주는 Mock SF는 진단 시 특정 호출의 도달점만 좁힌다. 아래 성공 단계에는 포함하지 않는다.
- **이식할 AOSP 구현** — r4 Goldfish `Composer/ComposerClient`의 서비스·display 관리와 초기 hotplug, `ComposerResources`의 buffer cache, `VsyncThread`, `ClientFrameComposer`의 CLIENT 협상 구조. 원본 `DisplayFinder`와 `ClientFrameComposer`는 에뮬레이터 또는 DRM에서 출력을 찾고 flush한다. 그 부분을 Guest 고정 config와 메모리 sink로 교체해야 한다. `NoOpFrameComposer`는 실제 프레임 출력 시험에 쓸 수 없다. Cuttlefish의 minigbm 및 mapper 패키지는 인터페이스와 배치의 참조이며 Galaxy용 완성품이 아니다. [Goldfish HAL][gold] · [초기 hotplug][gold-client] · [DRM present][gold-frame] · [Cuttlefish 패키지][cf-pack]
- **버퍼 공급** — 우선 DRM master나 VM 전용 장치 없이 동작하는 Android arm64 allocator/mapper 세트가 있는지 확인한다. 없으면 Guest 소유 공유 FD에 선형 SDR 버퍼를 할당하는 AIDL allocator/mapper5 이식 또는 구현이 범위에 들어간다. HAL 모듈명, usage 검증, plane metadata, lock/unlock, import/free, 앱 ABI까지 필요하다. 단순 memfd 할당만으로 EGLImage 호환을 보장할 수 없다. r4 SwiftShader Android 구현에도 AHardwareBuffer plane lock/unlock 경로가 있다. [Gralloc5 로딩][gr5] · [SwiftShader AHB][ss-ahb]
- **SSAL 통합** — Guest private Binder를 먼저 준비하고 Guest가 소유한 VINTF device manifest·HAL 선언·mapper 모듈·linker 설정을 Guest mount namespace에서 일치시킨다. allocator와 composer를 명시적으로 기동해 준비된 뒤 Guest SF를 기동하고, 두 이름이 실제 응답할 때 framework 부팅을 이어 간다. 이미지 rc의 UID/group·필요 권한을 대조하고 SF 재시작의 영향은 Guest zygote 안에 가둔다. 기존 supervisor allowlist 및 프로세스 종료 관리를 확장할 지점이다. 기존 SystemSuspend의 **framework** VINTF 성공과 graphics **device** HAL 선언 발견은 별도 시험이다. [기동 allowlist](../src/guest/initrc.rs) · [GSI rc](../out/init-preflight-extract/system/etc/init/surfaceflinger.rc) · [Guest VINTF 실측](guest-vintf-system-suspend-20261119.md)
- **SELinux** — 기존 Guest 정책·라벨을 재사용하며 Guest SF·composer·allocator·출력 소비자에 필요한 도메인/전이, Guest ServiceManager add/find, 방향별 Binder call/transfer와 FD use, 모듈 read/map 및 공유 버퍼 접근만 가산한다. 앱/SF/consumer의 mapper 로드도 각각 검증한다. Host Binder·hwservicemanager 또는 vendor 전체 접근을 여는 규칙, Host 라벨 교체, permissive 전환은 설계에 없다. broker안만 세션 socket과 지정된 Host helper의 좁은 권한이 추가된다. 동적 규칙 제거에 의존하지 않고 프로세스·FD·mount 수명을 세션에 묶는다. [Guest 정책 생성](../src/guest/selinux/mod.rs) · [private Binder](../src/guest/binder.rs)

## 5. 먼저 할 최소·비파괴 실험과 전환 조건

아래는 **후속 검증안**이다. 같은 부팅·세션의 Guest SID, mount namespace, Binder device identity와 PID로 증거를 연결한다. Host 관측은 전후의 SF PID, primary ID/mode/power, One UI 가용성과 boot ID를 읽기만 한다. 원본 userdata는 실험 대상으로 열지 않는다.

| 순서 | 최소 실험 | 관측값과 결정 |
|---|---|---|
| A. 실제 제공물 식별 | GSI SF/libui build ID와 가능하면 제작 manifest를 대조한다. 사용할 ELF·mapper의 필요한 ABI, Guest linker 경로, Guest `isDeclared`, 명시적 service lookup, 프로세스 안 mapper load를 확인한다. Host 자원 후보는 기존 manifest/장치 정보를 읽기만 한다. | 선언 누락, 미기동, namespace 로드 실패를 구분한다. Galaxy vendor 전체를 노출하거나 Host composer에 `createClient`를 시험할 필요가 없다. |
| B. 렌더러·gralloc 판별 **(먼저 투자할 실험)** | SF/system_server 없이 Guest의 두 프로세스로 작은 SDR 버퍼를 교환한다. 앱 texture/render용과 primary client-target용 실제 usage를 각각 사용한다. 한쪽에서 EGLImage/AHardwareBuffer를 import해 두 색·순번을 번갈아 그리고 반대쪽에서 올바른 stride로 결과를 확인한다. CPU read가 허용되지 않는 target은 읽기 가능한 별도 target으로 복사한다. | EGL renderer/driver명, format/usage, import 결과, 서로 다른 예상 픽셀, 지연시킨 acquire를 기다리는지, 반환 뒤 재사용·FD 회수가 되는지 확인한다. pbuffer clear만 성공하면 보류한다. Vulkan 후보는 먼저 `SYNC_FD` 기능을 조회한다. software GL과 앱 HWUI 양쪽에서 통과하면 주 설계를 유지한다. |
| C. HAL과 SF만 기동 | private Binder의 Guest HAL과 원본 SF를 기동한다. 모의 패널 한 개, SDR 한 모드로 초기 callback/시각, SF physical ID와 active mode, 두 서비스 응답을 기록한다. Guest native Surface에 움직이는 테스트 패턴을 보내 validate→CLIENT→client target→present가 반복되는지 본다. | 두 이름이 없으면 마지막 경계를 RE / service 조회 / createClient / hotplug / gralloc로 분류한다. 두 이름이 있어도 pixel·fence가 틀리면 primary 출력 실패다. 앱과 HAL 사이를 오가는 buffer를 재사용하고 consumer를 잠시 늦춰도 stale/torn frame·무한 대기가 없어야 한다. |
| D. Framework와 뷰어 | 같은 backend에서 Guest system_server를 시작한다. 아래 다섯 관문을 순차 관측하고 Guest 입력으로 화면을 바꾼다. viewer 분리·재연결, 일반 영역과 secure 시험 영역을 섞은 화면, 세션 종료 뒤 Host 상태를 확인한다. | DMS만 멈추면 주소/layout/token/mode specs를, SystemReady 이후 멈추면 최초 미완료 서비스와 WM/app layer·버퍼·출력 중 마지막 성공 지점을 기록한다. secure 영역 누출은 외부 출력 실패다. Guest 종료 후 One UI가 계속 동작하고 Guest mount/process/FD가 회수돼야 한다. |

**차선책을 선택할 시점.** B에서 소프트웨어 렌더러·allocator 간 버퍼 호환 또는 성능이 목표를 막고, 동일 테스트가 세션 전용 Host offscreen 자원으로 통과할 때 broker로 전환한다. 복사 출력만 막히면 출력만, 할당이 막히면 호환 가능한 버퍼 공급만 옮긴다. Guest RenderEngine이나 앱의 EGL 자체가 막히면 별도 Guest driver frontend가 있는 렌더링 중개안부터 검증한다. C의 hotplug/config 실패는 두 설계가 공유하는 Guest composer 결함이므로 여기서 broker로 바꿔도 해결되지 않는다. Host 패널 제어·Host Binder 위임 또는 임의 GPU ioctl 전달이 반드시 필요하다는 결과가 나오면 해당 경로를 기각한다. Guest Native SF는 Host와 독립적으로 소유 가능한 기존 display/HAL이 발견될 때만 순위를 재평가한다.

## 6. 단계별 성공 기준

| 관문 | 해당 세션에서 보존할 합격 증거 |
|---|---|
| **Binder 등록** | Guest SF PID·SID와 private Binder identity를 식별한다. Guest 클라이언트가 두 이름을 조회하고 원본 AIDL의 preference/overlay 조회와 legacy transaction 왕복을 확인한다. `service list` 행이나 PID 단독은 불충분하다. |
| **DMS 생성** | 동일 Guest system_server가 생성자를 반환하고 `onStart`를 거쳐 Guest `display` 서비스를 게시한다. `dumpsys display`가 응답하고 이전 `nativeGetCompositionDataspaces` 대기에서 벗어난다. |
| **DefaultDisplay** | Guest SF의 physical ID/token·mode와 DMS의 local device 주소 및 logical display **0**을 대응시킨다. VirtualDisplayAdapter도 등록돼 있고 `PHASE_WAIT_FOR_DEFAULT_DISPLAY`가 반환해 다음 부팅 단계에 진입한다. UI용으로 enabled 상태와 유효 크기·밀도도 확인한다. |
| **SystemReady** | 같은 Guest PID에서 WM과 DMS의 `systemReady`가 오류 없이 반환하고 AMS의 `systemReady` callback이 실행돼 `PHASE_ACTIVITY_MANAGER_READY`를 통과한다. WM/DMS 예외를 catch하고 진행할 수 있어 trace 끝 표시만으로 판정하지 않는다. 앱 실행 검증 때는 `PHASE_THIRD_PARTY_APPS_CAN_START` 도달도 기록한다. [SystemServer의 세 호출][ss-wm] · [DMS][ss-dms] · [AMS][ss-ams] |
| **Guest UI** | Guest display 0의 Launcher 또는 테스트 Activity가 focus를 얻고 실제 app buffer가 SF layer에 latch된다. Guest 외부 뷰어에 서로 다른 프레임이 표시되고 Guest 입력 한 번에 예상 화면으로 바뀐다. 해당 transaction·present와 뷰어 픽셀을 연결하며, Host primary 상태와 One UI가 유지된다. `sys.boot_completed`, 정적 이미지 하나, vsync 카운터만으로는 충족하지 않는다. |

프로젝트 최종 인수에는 위 UI 관문 뒤에 **One UI 복구 확인**이 남는다. graphics 서비스 기동은 명시적으로 시작한 Guest 세션에만 묶고 Host 부팅 시 자동 기동 항목이나 영구 display 설정을 추가하지 않는다. 별도로 허가된 하드 재부팅 시험에서 One UI가 자기 userdata와 원래 primary로 기동하고 Guest 그래픽 서비스가 자동으로 살아나지 않는지 확인한다.

현재 실기기 증거는 **첫 관문 이전**이다. AOSP에서 확인한 대체 primary 경로가 설계 결정의 근거이며, 구현 착수 여부를 결정할 새 증거는 실험 B의 버퍼·픽셀·동기화 왕복이다. 이 판정에서 빌드, 실기기 HAL/SF 실행, 정책·이미지 변경, 하드 재부팅 복구 시험은 수행하지 않았다.

[main]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/main_surfaceflinger.cpp#L44
[sf-re]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/SurfaceFlinger.cpp#L879
[re]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/renderengine/RenderEngine.cpp#L35
[gl]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/renderengine/skia/SkiaGLRenderEngine.cpp#L141
[ch]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/DisplayHardware/ComposerHal.cpp#L26
[ac]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/DisplayHardware/AidlComposerHal.cpp#L242
[hc]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/DisplayHardware/HidlComposerHal.cpp#L220
[sf-init]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/SurfaceFlinger.cpp#L976
[sf-hot]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/SurfaceFlinger.cpp#L4019
[hw-id]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/DisplayHardware/HWComposer.cpp#L1244
[sched]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/SurfaceFlinger.cpp#L4980
[sf-fb]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/SurfaceFlinger.cpp#L4357
[sf-alloc]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/SurfaceFlinger.cpp#L4217
[fb]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/DisplayHardware/FramebufferSurface.cpp#L70
[surf]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/gui/Surface.cpp#L218
[bqp]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/gui/BufferQueueProducer.cpp#L1578
[ga]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/ui/GraphicBufferAllocator.cpp#L54
[gm]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/ui/GraphicBufferMapper.cpp#L60
[sf-end]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/SurfaceFlinger.cpp#L1052
[publish]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/main_surfaceflinger.cpp#L142
[gr5]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/ui/Gralloc5.cpp#L50
[ac-clear]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/DisplayHardware/AidlComposerHal.cpp#L272
[gl-sync]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/renderengine/skia/SkiaGLRenderEngine.cpp#L345
[sc-tx]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/gui/SurfaceComposerClient.cpp#L1201
[grbuf]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/libs/ui/GraphicBuffer.cpp#L464
[sf-sec]: https://github.com/LineageOS/android_frameworks_native/blob/26f530caefb3217766469d9731ee602c83f48e84/services/surfaceflinger/SurfaceFlinger.cpp#L4141
[dms-start]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/DisplayManagerService.java#L708
[lda]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/LocalDisplayAdapter.java#L125
[lda-flag]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/LocalDisplayAdapter.java#L753
[ldm-add]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/LogicalDisplayMapper.java#L757
[ldm-fallback]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/LogicalDisplayMapper.java#L1374
[ldm-layout]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/LogicalDisplayMapper.java#L1235
[layout]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/layout/Layout.java#L86
[dms-wait]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/DisplayManagerService.java#L756
[dms-notify]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/DisplayManagerService.java#L2519
[ldm-get]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/LogicalDisplayMapper.java#L315
[dms-ad]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/DisplayManagerService.java#L2363
[vda]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/VirtualDisplayAdapter.java#L164
[vda-flags]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/VirtualDisplayAdapter.java#L604
[lda-light]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/LocalDisplayAdapter.java#L1904
[dms-mirror]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/core/java/com/android/server/display/DisplayManagerService.java#L1985
[ss-wm]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/java/com/android/server/SystemServer.java#L3176
[ss-dms]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/java/com/android/server/SystemServer.java#L3243
[ss-ams]: https://github.com/LineageOS/android_frameworks_base/blob/1ef04f03546366e85f414b6ca5306305d18aa1ef/services/java/com/android/server/SystemServer.java#L3360
[a-sf]: https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r4/services/surfaceflinger/SurfaceFlinger.cpp#985
[a-dms]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r4/services/core/java/com/android/server/display/DisplayManagerService.java#758
[a-ldm]: https://android.googlesource.com/platform/frameworks/base/+/android-16.0.0_r4/services/core/java/com/android/server/display/LogicalDisplayMapper.java#757
[cf-vm]: https://android.googlesource.com/device/google/cuttlefish/+/android-16.0.0_r4/host/libs/vm_manager/crosvm_manager.cpp#72
[cf-pack]: https://android.googlesource.com/device/google/cuttlefish/+/android-16.0.0_r4/shared/graphics/device_vendor.mk#50
[vk-sync]: https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r4/libs/renderengine/skia/VulkanInterface.cpp#330
[ss-sem]: https://android.googlesource.com/platform/external/swiftshader/+/android-16.0.0_r4/src/Vulkan/VkPhysicalDevice.cpp#1158
[ss-ahb]: https://android.googlesource.com/platform/external/swiftshader/+/android-16.0.0_r4/src/Vulkan/VkDeviceMemoryExternalAndroid.cpp#317
[a-hot]: https://source.android.com/docs/core/graphics/hotplug#handling-common-scenarios
[gold-comp]: https://android.googlesource.com/device/generic/goldfish/+/android-16.0.0_r4/hals/hwc3/Composer.cpp#26
[a-bq]: https://source.android.com/docs/core/graphics/arch-bq-gralloc
[hal-client]: https://android.googlesource.com/platform/hardware/interfaces/+/android-16.0.0_r4/graphics/composer/aidl/android/hardware/graphics/composer3/IComposerClient.aidl#188
[a-sync]: https://source.android.com/docs/core/graphics/sync
[gold-vsync]: https://android.googlesource.com/device/generic/goldfish/+/android-16.0.0_r4/hals/hwc3/VsyncThread.cpp#160
[out-sec]: https://android.googlesource.com/platform/frameworks/native/+/android-16.0.0_r4/services/surfaceflinger/CompositionEngine/src/OutputLayer.cpp#359
[gold]: https://android.googlesource.com/device/generic/goldfish/+/android-16.0.0_r4/hals/hwc3/
[gold-client]: https://android.googlesource.com/device/generic/goldfish/+/android-16.0.0_r4/hals/hwc3/ComposerClient.cpp#471
[gold-frame]: https://android.googlesource.com/device/generic/goldfish/+/android-16.0.0_r4/hals/hwc3/ClientFrameComposer.cpp#129
