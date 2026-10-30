# 독립 Binder 디바이스·IPC 시험

`ssal probe-binder PROFILE_NAME`은 prepare와 같은 임시 rootfs를 만든 뒤 독립 binderfs와 최소 C++ 서버·클라이언트를 실행하고 정리한다. 일반 `prepare`는 이 시험을 자동 실행하지 않는다. 호스트 servicemanager, Zygote, SurfaceFlinger를 정지·교체하지 않는다. 설치된 데몬과 별개로 시험 워커를 실행해 검증할 수도 있다.

구현은 [`binder_probe.rs`](../src/binder_probe.rs), root 내 실행·해시 확인은 [`guest_probe.rs`](../src/guest_probe.rs), IPC 헬퍼는 [`native/binder-probe`](../native/binder-probe)에 있다. Rust는 장치·mount·수명을 관리하고 C++은 AOSP libbinder를 사용한다. Binder IPC 프로토콜을 자체 구현하지 않는다.

## 실행

```sh
/system/bin/sh /data/adb/modules/ssal/restart.sh
/data/adb/modules/ssal/bin/ssal probe-binder profile1
```

새 CLI·데몬을 설치한 뒤 실행한다. 준비 과정의 rootfs·fscrypt·linkerconfig·VINTF 진단은 기존처럼 수행된다. Android 서비스의 전역 `launch_enabled=false`는 유지하며 이 명령은 검증된 private 장치에 한정된 시험 프로그램만 실행한다.

## 디바이스 관리

1. private mount namespace의 게스트 `/dev/binderfs`에 새 binderfs를 `max=4,nosuid,noexec`로 mount한다. `nodev`는 장치 접근이 필요하므로 사용하지 않는다. 공유 `/dev`에 새 디렉터리나 노드를 직접 만들지 않는다.
2. 새 `binder-control`에 `BINDER_CTL_ADD`를 호출해 `ssal-probe`라는 장치를 만든다. 일부 Android 커널은 새 binderfs에도 binder/hwbinder/vndbinder를 미리 생성하므로 `binder` 이름의 EEXIST를 피한다.
3. ioctl 응답의 major/minor, 실제 character device의 rdev와 fdinfo mount ID가 일치하고 호스트 Binder와 rdev가 다른지 확인한다. 게스트 `/dev/binder`가 이 장치를 가리키도록 필요한 bind mount만 추가한다.
4. `BINDER_VERSION`으로 arm64 프로토콜 8을 확인한다. 이 시점은 장치 생성·열기 성공이며 IPC 성공은 아니다.
5. 헬퍼 종료 후 fd와 alias bind를 해제하고 binderfs를 일반 unmount한다. 생성한 mount ID가 남아 있지 않은지와 호스트 `/dev/binder`의 identity가 보존됐는지 확인한다.

hw/vnd 장치의 통신·격리는 시험하지 않는다. 전체 게스트 Binder·HAL 분리로 확대 해석하지 않는다. 장치 번호가 다르다는 사실 외에 새 mount와 ioctl 생성 경로를 함께 확인하지만, 서비스 레지스트리 격리는 Test B에서 별도 확인해야 한다.

## 최소 IPC 헬퍼 — Test A

`ssal-binder-probe`는 다음 순서로 동작한다.

- 게스트 root에서 fresh exec하며 부모의 Binder FD·ProcessState를 재사용하지 않는다.
- libbinder를 초기화하기 전에 fork하여 별도 서버·클라이언트를 만든다.
- 두 프로세스 모두 요청한 장치와 실제 열린 FD의 identity를 확인한다. libbinder의 기본 드라이버 fallback에 의존하지 않는다. Rust가 연결한 게스트 `/dev/binder`도 private 장치다.
- 서버는 BBinder 객체를 context manager로 등록하고 클라이언트의 시험 transaction에 응답한다. 클라이언트는 nonce와 서버 PID를 확인한다. AOSP servicemanager의 등록·검색 프로토콜은 실행하지 않는다.
- 두 프로세스의 실제 SELinux 컨텍스트를 기록한다. 현재 시험은 `ksu` 관리 도메인이며 Android 서비스 도메인 통과가 아니다.
- 헬퍼가 서버를 종료·회수하고 Rust가 전용 프로세스 그룹과 FD를 정리한다. 서버 준비 대기는 5초, 바깥 실행 제한은 20초다.

헬퍼는 모듈에서 RO 코드 뷰로 제공한다. 실행 때는 생성한 linkerconfig의 unrestricted section을 이용하도록 게스트 `/data/local/tmp`의 충돌하지 않는 임시 파일에 RO bind한다. 종료 후 bind와 파일을 제거한다.

`Binder probe summary:`는 각 항목을 `passed/failed/not_run/unavailable`로 독립 기록한다. `device_created`, `device_opened`, `context_manager`, `ipc`, `servicemanager`, `android_service_selinux`, `host_registry_isolation`, `cleanup`을 별도로 표시한다. 실패 상세는 `failure`에 기록한다. Test A 성공은 `validation_scope=management_domain_ipc_only`이며 서비스 기동 계약의 `private_framework_binder` 전체 통과로 변환하지 않는다.

## 빌드와 이미지 일치 검사

기본 Rust 빌드는 IPC 헬퍼를 생성하지 않는다. IPC 헬퍼를 함께 배포하려면 실제 게스트 이미지의 arm64 `libbinder.so`, `libutils.so`, `libc++.so`를 준비한다. 호스트 One UI의 라이브러리를 대신 사용하지 않는다.

```sh
bash scripts/build-binder-probe.sh /src/PATH_TO_GUEST_LIBRARIES
```

스크립트는 공식 AOSP `android-16.0.0_r2` 플랫폼 헤더를 `.cache/android16-binder`에 받아 실제 게스트 라이브러리와 링크한다. 플랫폼 C++ 라이브러리를 사용하므로 공개 NDK ABI만 사용하는 프로그램이 아니다. 플랫폼용 libc++를 링크하며 앱용 libc++_shared.so를 요구하지 않는다. Android 플랫폼 트리에서 빌드할 수 있는 Android.bp도 제공한다.

출력은 `out/bin/ssal-binder-probe`와 JSON manifest다. manifest에는 헬퍼·소스·빌드 스크립트·세 게스트 라이브러리의 SHA-256, 헤더 revision과 ABI 검증 범위를 기록한다. 패키징은 소스·스크립트·바이너리의 stale 여부를 확인한다. 실행 직전에도 헬퍼와 실제 게스트 라이브러리 해시를 비교하며 다르면 실행을 거부한다. 라이브러리 자체는 모듈에 포함하지 않는다.

해시 일치는 잘못된 이미지 조합을 방지하는 조건이며 모든 C++ ABI 호환성의 증명이 아니다. 이 헬퍼가 사용하는 API는 실제 IPC 시험으로 확인한다. 게스트 이미지의 라이브러리가 바뀌면 재빌드해야 한다. 헬퍼가 없으면 디바이스 시험만 수행하고 IPC는 unavailable로 기록한다.

## 2026-10-31 기기 검증

연결된 SM-S937N의 등록된 Android 16 게스트 이미지에서 임시 워커로 확인했다. 설치된 SSAL 데몬을 교체하지 않았다.

- host Binder `507:1`, private Binder `507:8`, 프로토콜 8.
- private context manager 등록과 서버·클라이언트 echo 성공.
- 서버·클라이언트 컨텍스트 `u:r:ksu:s0`.
- private 노드 라벨 `u:object_r:binderfs:s0`. servicemanager 도메인에서의 접근은 아직 미검증이다.
- private Binder mount 정리와 rootfs 잔여 mount 검사 성공, 세션 loop backing 55개 해제 확인.
- 호스트 Zygote/SurfaceFlinger의 PID 유지, SELinux Enforcing 유지.

이는 Host registry에 guest 서비스가 보이지 않는다는 Test B의 증명이 아니다. 다음 단계는 새 binderfs 세션에서 guest servicemanager의 실제 도메인·service_contexts·등록/검색/호스트 비노출을 검증하는 것이다. Property 초기화·HAL 중계와 전체 Android 부팅은 그 뒤의 작업이다.
