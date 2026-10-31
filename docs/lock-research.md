# LineageOS 23.2 인증 HAL 우회 구조 조사

먼저 확인된 핵심은 Android 16에 이미 인증 HAL 의존성을 줄이는 경로가 구현되어 있다는 점입니다. 특히 화면 잠금을 설정하지 않는 사용자는 Gatekeeper와 Weaver를 상당 부분 사용하지 않고 Synthetic Password를 관리할 수 있습니다.

다만 이것이 KeyMint까지 완전히 제거할 수 있다는 뜻은 아닙니다.

LineageOS 23.2의 소스와 Android 16 QPR2의 인증 코드를 조사한 결과, 다음과 같이 구분됩니다.

| 구성 요소               | 기존 우회·대체 경로                          | 판단       |
| ------------------- | ------------------------------------ | -------- |
| Weaver HAL          | HAL이 없으면 Gatekeeper 경로로 전환           | 지원       |
| Gatekeeper HAL      | 잠금 비밀번호가 없으면 LSKF 검증 생략              | 조건부 지원   |
| AuthSecret HAL      | GSI 실행 시 호출 생략                       | 지원       |
| Reboot Escrow       | GSI 실행 시 처리 생략                       | 지원       |
| KeyMint / Keymaster | 화면 잠금 여부와 별도로 Keystore에서 사용          | 추가 검토 필요 |
| FBE / vold          | 잠금이 없어도 Synthetic Password와 연결될 수 있음 | 별도 문제    |

특히 중요한 사실은 Android 16이 이미 비밀번호 없는 사용자를 위한 별도 코드 경로를 갖고 있다는 것입니다. 단순히 잠금화면 UI를 비활성화하는 것과는 다릅니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://android.googlesource.com\&sz=32)

Git at Google+2



## 1. GSI에서는 AuthSecret 호출을 이미 건너뛰도록 구현했습니다

LineageOS 23.2의 실제 `LockSettingsService.java`에 다음 코드가 있습니다.

[LineageOS 23.2 — LockSettingsService.java](https://github.com/LineageOS/android_frameworks_base/blob/lineage-23.2/services/core/java/com/android/server/locksettings/LockSettingsService.java?utm_source=chatgpt.com)

```
private void onSyntheticPasswordKnown(
        int userId, SyntheticPassword sp, boolean justCreated) {
    if (mInjector.isGsiRunning()) {
        Slog.w(TAG, "Running in GSI; skipping calls to AuthSecret and RebootEscrow");
        return;
    }

    mRebootEscrowManager.callToRebootEscrowIfNeeded(
            userId, sp.getVersion(), sp.getSyntheticPassword());
    callToAuthSecretIfNeeded(userId, sp, justCreated);
}
```

즉 Android 측에서 GSI가 Host의 인증 관련 상태를 변경하면 안 되는 상황을 이미 고려한 것입니다. 여기서 `AuthSecret`은 일반적인 PIN 인증을 담당하는 Gatekeeper와는 별개입니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



다만 중요한 예외가 있습니다. `isGsiRunning()`은 실제로 다음 속성을 검사합니다.

```
SystemProperties.getInt("ro.gsid.image_running", 0) > 0
```

이는 기본적으로 DSU/GSI 부팅 상태를 나타내는 속성입니다. SSAL처럼 별도의 방식으로 Android 시스템을 전환했다면 자동으로 `true`가 된다고 볼 수 없습니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



또한 GSI 분기는 AuthSecret에 비밀값을 전달하는 호출을 생략하지만, `systemReady()`의 `getAuthSecretHal()`에서는 여전히 HAL 서비스 검색을 시도합니다. HAL에 대한 접근 자체를 피해야 한다면 이 초기화 경로까지 별도로 처리해야 합니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub



`ro.gsid.image_running=1`을 강제로 설정하는 방법은 권하지 않습니다. `gatekeeperd`에서도 이 속성을 확인하여 Gatekeeper 사용자 ID에 1,000,000 오프셋을 적용하고, 일부 상태 정리 동작을 변경하기 때문입니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub



## 2. 비밀번호를 설정하지 않으면 Gatekeeper를 호출하지 않는 경로가 존재합니다

실제로 더 중요한 발견은 `SyntheticPasswordManager.java`입니다.

비밀번호가 비어 있고 Weaver를 사용하지 않을 경우, LineageOS 23.2는 Gatekeeper에 비밀번호를 등록하지 않고 `secdiscardable`을 사용하는 Synthetic Password protector를 생성합니다.

복원할 때도 비밀번호 핸들이 없으면 Gatekeeper의 `verifyChallenge()`를 생략합니다. 따라서 신규 사용자가 PIN·패턴·비밀번호를 전혀 설정하지 않는다는 조건에서 Gatekeeper 인증 HAL을 사용하지 않는 것이 가능합니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



반대로 기존 Synthetic Password가 Weaver를 이용해 암호화되어 있다면 Weaver가 사라졌을 때 복원에 실패할 수 있습니다. 기존 데이터를 유지한 상태에서 단순히 HAL을 없애는 것은 안전한 전환 방법이 아닙니다.

### Weaver 우회를 위한 기존 설정

LineageOS 23.2에는 다음 리소스가 이미 존재합니다.

```
<bool name="config_disableWeaverOnUnsecuredUsers">true</bool>
```

기본값은 `false`입니다. 이를 제품 오버레이에서 활성화하면 잠금이 없는 사용자에 한해 Weaver 사용을 생략할 수 있습니다. PIN을 설정한 사용자까지 Weaver를 전역 비활성화하는 옵션은 아닙니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



## 3. PIN·패턴 설정 자체를 막는 공식 기능도 있습니다

SSAL의 현재 방향에 특히 적합해 보이는 부분입니다.

LineageOS 23.2의 `LockSettingsService`는 다음 기기 기능을 확인합니다.

`android.software.secure_lock_screen`

이 기능이 없으면 `setLockCredential()`에서 비어 있지 않은 PIN·패턴·비밀번호 설정을 `UnsupportedOperationException`으로 거부합니다. 따라서 별도 잠금화면 패치를 하지 않고도 Framework 수준에서 인증 수단 설정을 차단할 수 있습니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



더 흥미롭게도, LineageOS의 `SystemConfig`는 시스템 XML의 `unavailable-feature`를 지원합니다.

가령 시스템 이미지의 `/system/etc/sysconfig/ssal-lockscreen.xml`에 다음을 포함하는 방법을 검토할 수 있습니다.

```
<?xml version="1.0" encoding="utf-8"?>
<permissions>
    <unavailable-feature
        name="android.software.secure_lock_screen" />
</permissions>
```

이는 실제 Android 16 코드에서 지원하는 기능 제거 메커니즘입니다. 다만 빌드 시 강제로 활성화된 읽기 전용 기능은 제거가 거부될 수 있으므로 실제 기기에서 `pm list features` 결과를 확인해야 합니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



이 방법의 장점은 인증 HAL 내부를 패치하지 않고 잠금 설정이 가능한 기기라는 선언 자체를 철회한다는 점입니다. 단, 기존 잠금 정보를 해제하거나 암호화 키를 변환하는 기능은 아닙니다.

## 4. KeyMint만은 여전히 별도 문제입니다

LineageOS 23.2의 `SyntheticPasswordCrypto`는 PIN이 없는 경우에도 `AndroidKeyStore`에 SP protector 암호화 키를 보관합니다.

`sid == 0`이면 사용자 인증에 대한 키 바인딩은 생략하지만, Keystore 자체의 사용은 계속됩니다. 또한 Keystore2는 TEE 보안 수준의 KeyMint 또는 Keymaster 인스턴스를 필수로 구성하려고 합니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://raw.githubusercontent.com\&sz=32)

GitHub+1



다행히 완전한 하드웨어 KeyMint가 없는 개발 환경을 위한 소프트웨어 구현은 존재합니다.

`android.hardware.security.keymint-service.nonsecure`

LineageOS 23.2의 하드웨어 인터페이스 소스에도 포함되어 있습니다. 하지만 소스에서도 명시적으로 보안이 보장되지 않는 구현이라고 설명하며, 일반적으로 Vendor 측 서비스 구성과 VINTF·SELinux 처리가 필요합니다. GSI에 단순히 실행 파일 하나를 추가하면 해결되는 수준은 아닙니다.&#x20;

[image](https://www.google.com/s2/favicons?domain=https://github.com\&sz=32)

GitHub



## SSAL에 적용한다면

현재처럼 사용자가 잠금 비밀번호를 설정하지 않는다는 전제를 유지한다면, 저는 다음 구성을 우선 검토하겠습니다.

Secure Lock Screen 기능 제거

`unavailable-feature`로 PIN·패턴·비밀번호 설정 자체를 Framework 수준에서 차단합니다.

잠금 없는 사용자에 대한 Weaver 생략

`config_disableWeaverOnUnsecuredUsers=true`를 적용합니다.

AuthSecret만 선택적으로 생략

DSU 플래그를 위조하는 대신 SSAL 전용 플래그로 `getAuthSecretHal()`과 비밀값 전달 분기를 제어하는 편이 명확합니다.

KeyMint·Keystore는 별도 검증

비밀번호가 없어도 필요한 경로이므로 기존 구현을 유지하거나 소프트웨어 KeyMint 등 대체 구현의 호환성을 확인해야 합니다.

실기기에서 이 구성이 부팅까지 성공하는지는 아직 검증하지 않았습니다. 특히 기존 CE 데이터나 SP protector를 재사용하는 경우에는 신규 사용자 생성과 다른 문제가 발생할 수 있습니다.

결론적으로 LineageOS 23.2는 인증 HAL이 없는 환경을 상당 부분 고려했습니다. 인증 우회를 새로 만드는 것보다, 이미 존재하는 잠금 없는 Synthetic Password 경로와 Secure Lock Screen 기능 비활성화를 활용하는 편이 SSAL에 더 적합합니다. 남은 핵심 의존성은 Gatekeeper보다는 Keystore2와 KeyMint, 그리고 실제 Guest 사용자 데이터의 암호화 상태입니다.