## SurfaceFlinger

### 1. 제공해주신 로그 분석

1. **`Permission failure: ACCESS_SURFACE_FLINGER / ROTATE_SURFACE_FLINGER / INTERNAL_SYSTEM_WINDOW (uid=10105)`**
   - `18450`은 Guest `surfaceflinger`이며, Guest의 `/data/system/packages.list` 기준 **`uid=10105`는 `com.android.calculator2`(계산기 앱)**입니다.
   - 일반 앱이 `SurfaceFlinger`와 바인더 통신할 때 `SurfaceFlinger`가 시스템 권한 보유 여부를 확인하면서 일반 앱이므로 `denied`가 찍힌 **정상(무해한) 로그**입니다.
   - 앞부분의 `pid=0`은 `oneway` 바인더 호출 시 커널 바인더 드라이버가 `callingPid`를 `0`으로 전달하기 때문에 나타나는 현상이고, `pid=21895`는 당시 계산기 앱의 동기 호출입니다.

2. **`E SurfaceFlinger: trackPendingFrame: Invalid present fence`**
   - [main.rs](../services/virtual-composer/src/main.rs#L324-L353)에서 `presentDisplay` 처리 시 `ReleaseFences`만 반환하고 `PresentFence`를 반환하지 않기 때문에 `SurfaceFlinger`가 프레임마다 출력하는 로그입니다. 현재 `virtual-composer` 구현상 발생하는 현상이며 설정 앱 실행 실패와는 무관합니다.

---

### 2. 설정 앱(`com.android.settings`)이 안 켜지는 원인

Guest의 `/data/system/dropbox/`에 해당 시각(`07:02`)의 `com.android.settings` 크래시 로그 2건이 기록되어 있습니다.

1. **`system_app_crash@1795212162481.txt` (`07:02:42.477`, PID `21363`)**
   - `com.android.settings.sound.MediaOutputPreferenceController.onStart` (`MediaOutputPreferenceController.java:130`)
   - → `LocalMediaManager.registerCallback` (`LocalMediaManager.java:128`)
   - 내부 `InfoMediaManager` 인스턴스가 `null`인 상태에서 `registerCallback()`을 호출해 **`NullPointerException`** 발생.

2. **`system_app_crash@1795212170102.txt` (`07:02:50.098`, PID `21779`)**
   - `com.android.settings.SubSettings` (`ConnectedDeviceDashboardFragment.onAttach`, `ConnectedDeviceDashboardFragment.java:94`)
   - → `BluetoothUtils.isAudioSharingUIAvailable` → `BluetoothUtils.isAudioSharingSupported` (`BluetoothUtils.java:736`)
   - `BluetoothAdapter`가 `null`인 상태에서 `BluetoothAdapter.isLeAudioBroadcastSourceSupported()`를 호출해 **`NullPointerException`** 발생.

#### 근본 원인
- [device_vintf.rs](../src/guest/concurrent/device_vintf.rs#L46-L48)에서 Guest에 `android.hardware.bluetooth` 및 `android.hardware.bluetooth_le`를 `<unavailable-feature>`로 비활성화하고 있습니다.
- 이로 인해 Guest에서 `BluetoothAdapter`가 `null`로 반환되며(`InfoMediaManager` 초기화에도 영향), Android 16 (`BP4A.251205.006`) `Settings` / `SettingsLib`가 이에 대한 `null` 가드 없이 메서드를 호출하면서 해당 프래그먼트/화면 진입 시 즉시 `NullPointerException`으로 크래시합니다.

---

### 해결 방향 (참고)
- **빠른 검증용**: `Settings`에서 `BluetoothAdapter` / `LocalMediaManager` null 체크가 누락된 부분을 우회하거나, Guest에서 최소한의 stub/더미 `bluetooth_manager` 서비스(또는 `android.hardware.bluetooth` feature 노출 여부 검토)를 제공해 `BluetoothAdapter`가 `null`을 반환하지 않도록 하는 방향을 검토할 수 있습니다.