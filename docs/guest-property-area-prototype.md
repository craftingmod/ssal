# Guest Property Area 오프라인 프로토타입 — 2026-10-31

합성 입력에서 Android 16 r2 AOSP property-info serializer의 exact/prefix 조회와 Bionic `prop_area`의 생성, 최초 값 기록, 파일 재매핑과 읽기가 통과했다. 별도 sentinel 파일은 Guest 기록의 영향을 받지 않았다. **실제 Android Guest의 격리나 Enforcing 동작은 아직 입증되지 않았고, 이 프로토타입은 Property Service가 아니다.** 두 시험은 독립적이다. serializer가 반환한 context로 area를 선택하는 통합 경로는 아직 없다.

## 실행과 범위

Windows, Bun, 인터넷, Visual Studio 2022 Community C++ 도구와 clang-cl이 필요하다. 다른 설치 경로는 [실행 스크립트](../scripts/property-area-prototype/run.ps1)의 `vc`를 수정한다. `out/`에 고정 태그의 소스를 다운로드하고 SHA-256을 확인해 빌드하며, 매 실행마다 임의 이름의 시험 디렉터리를 만들고 삭제한다. 기존 GSI 및 기기 파일을 사용하지 않는다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/property-area-prototype/run.ps1
```

2026-10-31 로컬 실행 결과: 합성 context 두 개의 직렬화, exact/prefix 조회 통과. Bionic `prop_area`의 `add`/`find`로 별개 Guest와 sentinel 파일에 같은 이름의 다른 값 및 Guest 전용 값을 기록하고, 재매핑 후 값과 부재 확인 통과. 같은 파일에 대한 중복 생성은 거부됐다. 기본 128 KiB area, magic/version, offset 기반 trie와 `prop_info` 구현을 사용한다. 이때 쓰기는 **새 property 추가**이며 기존 property 갱신, concurrent reader/writer, serial/futex, long value, `ro.*` write-once는 시험하지 않았다.

[Bionic Android 16 r2](https://android.googlesource.com/platform/bionic/+/android-16.0.0_r2/libc/system_properties/prop_area.cpp)의 `allocate_obj` 이후 trie 로직 및 `prop_info.cpp`는 고정 해시 원본을 사용한다. `open`/`ftruncate`/POSIX `mmap`/`fsetxattr` 부분은 [Win32 시험 어댑터](../scripts/property-area-prototype/adapter.cpp)로 교체했고 atomic·Bionic 헤더도 호환 shim이다. 파일 매핑은 Windows `CreateFileMapping`/`MapViewOfFile`이며 실제 Android mmap, 권한, SELinux 및 syscall 동등성을 뜻하지 않는다. AOSP system/core serializer/parser도 기존 [시험 도구](../scripts/property-aosp/harness.cpp)와 shim을 재사용한다. 합성 context는 실제 정책 타입으로 선언하거나 라벨링하지 않는다.

sentinel은 로컬의 별도 모의 파일이다. 실제 Host property area를 열거나 수정하지 않았고 소켓을 만들거나 연결하지 않았다. 따라서 데이터가 섞이지 않는 fixture는 확인했지만, Android namespace의 Host 경로 차단, 기존 프로세스가 상속한 FD, `/proc` 경유 접근, Host socket 연결 차단 및 프로세스 간 권한 격리는 **미검증**이다. `property_info`와 serial area의 완전한 Android 파일 집합도 이 시험이 만들지 않는다.

## 현재 실효 정책 읽기 전용 재조회

2026-10-31 21:21 KST, 연결된 SM-S937N, fingerprint `samsung/psqksx/psq:17/CP2A.260605.016/S937NKSSBDZJ2_OKRBDZJ2:user/release-keys`, 전역 Enforcing, 조회 주체 `u:r:ksu:s0`, 커널 최대 policy version 33. `selinuxfs/context`에 NUL 종료 context를 쓰는 조회만 수행했다. 이는 selinuxfs의 조회 트랜잭션이며 정책 변경이나 기기 property 파일 생성이 아니다.

| 결과 | 타입 |
|---|---|
| `EINVAL` 재확인 12 | `custom_version_prop`, `legal_url_prop`, `native_binder_stats_prop`, `odm_cast_prop`, `persist_sysui_builder_extras_prop`, `persist_sysui_ranking_update_prop`, `recovery_update_prop`, `sf_hs_mode_prop`, `usb_uvc_config_prop`, `vendor_hwc_prop`, `vendor_persist_nfc_prop`, `xtra_control_prop` |
| 유효, 이전 미조회 2 | `vendor_ctl_port-bridge_prop`, `vendor_ipacm-diag_prop` |
| 유효, 별도 serial | `properties_serial` |

라벨은 모두 `u:object_r:<타입>:s0`이다. 이 결과는 당시 KernelSU가 반영된 실효 정책의 전체 context 유효성만 나타낸다. `EINVAL`의 원인을 타입 부재로 확정할 수 없고, 유효하더라도 파일 생성·라벨링·접근이 허용된다는 뜻이 아니다. 정책 전체를 export/hash하지 못한 기존 한계가 있으므로 정책 identity나 전후 불변성은 완전하게 입증되지 않았다. 순정 삼성 정책의 결과도 unknown이다. 전체 523개 및 실제 대상 도메인별 AV는 이번에 재조회하지 않았다.

재조회는 다음처럼 실행할 수 있다. `su` 및 selinuxfs 조회 권한이 필요하다. `printf`의 실패 메시지가 `Invalid argument`인지 확인해야 하며 임의 실패를 EINVAL로 간주해서는 안 된다.

```powershell
adb shell su -c 'getenforce; id; getprop ro.build.fingerprint; date -Iseconds; for t in custom_version_prop legal_url_prop native_binder_stats_prop odm_cast_prop persist_sysui_builder_extras_prop persist_sysui_ranking_update_prop recovery_update_prop sf_hs_mode_prop usb_uvc_config_prop vendor_hwc_prop vendor_persist_nfc_prop xtra_control_prop vendor_ctl_port-bridge_prop vendor_ipacm-diag_prop properties_serial; do printf "%s " "$t"; printf "u:object_r:%s:s0\0" "$t" > /sys/fs/selinux/context && echo OK || echo FAIL; done'
```

## 실제 Enforcing 실행에 필요한 계약과 차단 요소

아래는 확인할 후보이며 정책 적용 지시나 최소 allow 집합이 아니다. 실제 Guest writer/client의 SID, 파일의 초기 SID, 최종 SID, filesystem SID, DAC와 mount 옵션을 정하고 각 조합의 AV와 동작을 확인해야 한다.

| 구성 | 필요한 조건과 남은 확인 |
|---|---|
| property context | 523개 전체 및 `property_info`, `properties_serial`, 디렉터리·socket 라벨의 현재 유효성. 위 12개 해결과 두 유효 라벨의 실제 권한은 미정. 합성 라벨은 실기기 유효성이 없다. |
| 생성과 라벨 | writer에 부모 `dir`의 search/add_name/write, 초기 inode의 file create 및 open/read/write/getattr/setattr/map 등 실제 syscall별 권한. 라벨 변경은 기존 inode `relabelfrom`, 새 타입 `relabelto`, 새 타입과 filesystem의 `associate`, 유효 context 및 DAC/capability와 라벨 지원이 필요하다. |
| mount | Guest 전용 mount namespace와 별도 inode를 갖는 tmpfs 후보, 적절한 크기·소유권·mode 및 per-inode SELinux 라벨 지원. 단일 `context=` mount는 개별 라벨을 막을 수 있다. 실제 superblock SID와 옵션을 검증해야 한다. mount namespace만으로 열린 FD와 socket이 사라지지는 않는다. |
| 클라이언트 | 각 enforcing Guest 도메인별 디렉터리 탐색, `property_info`, serial 및 대상 area의 read/open/getattr/map과 DAC, 서로 다른 context의 접근 경계. 기존 Host와 같은 SID에 허용을 추가하면 Host에도 영향이 생길 수 있다. |
| service | Guest 전용 socket, peer 인증 및 `property_service:set`, 이름·타입 검사, 기존 값 업데이트와 serial/futex, `ro.*` 규칙, Guest userdata의 `persist.*` 저장/복구를 구현해야 한다. `ctl.*`, `sys.powerctl`은 Host에 전달하지 않도록 별도 설계한다. |
| 격리·호환 | Host area/socket 경로와 상속 FD 차단, `/proc`·대체 경로 음성 시험, Guest build/boot 입력 출처, 전체 context 선택 및 AOSP 클라이언트 호환성. 별도 userdata와 인증 자원 분리는 별도 검증이다. |

## 원복과 후속 시험

이번 시험은 정책 적용, 기기 mount, Guest init/Framework, 인증 HAL 호출을 수행하지 않았으므로 기기 원복 대상은 없다. 로컬 시험 디렉터리는 자동 삭제하며 빌드 산출물은 `out/property-area-prototype`에 남는다. 향후 기기 시험 전에는 Guest 전용 mount와 프로세스·FD·socket의 생성 및 종료 순서를 문서화하고, 실패 시 Guest 프로세스 종료 후 전용 mount와 임시 자원을 제거해야 한다. 커널 전역의 동적 정책 변경이나 재부팅 시 자동 재적용 규칙은 별도 승인과 복구 검증이 필요하다. 하드 재부팅 후 정책·mount·자동 재적용 상태 및 One UI 정상 동작을 확인하기 전에는 하드 재부팅만으로 복구된다고 주장할 수 없다.

기존 근거와 더 상세한 정책 후보는 [SELinux 가능성 조사](guest-property-selinux-feasibility.md), 입력 범위는 [AOSP serializer 검증](guest-property-validation-v2.md)을 참조한다.
