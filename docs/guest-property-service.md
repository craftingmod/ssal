# Guest property server — 2026-11-05

`ssal-property-service`는 `rsproperties = 0.6.0`의 area/serial/futex를 사용하는 전용 exec worker다. upstream 서버 대신 SSAL이 Android V1/V2 쓰기, peer 신원·SELinux 인가, 값 타입, 초기화 후 `ro.*` 봉인, 영속 저장을 처리한다. `prost 0.14`로 AOSP Android 16 `init/persistent_properties.proto`와 같은 형식을 읽고 쓴다.

## 저장 계약

- 경로는 Guest **`/data/property/persistent_properties`**로 고정한다. JSON 저장이나 Host persist 복사는 없다. protobuf outer repeated record는 tag 1, record의 optional string name/value는 tag 1/2다.
- root 소유 0700 디렉터리와 0600 파일만 허용한다. symlink, 비정규 파일, hardlink, 잘못된 owner/mode를 거부한다. 디렉터리 FD 기준 `openat/renameat`와 세션 전체 writer lock을 사용한다.
- 전체 집합을 `persistent_properties.tmp`에 O_EXCL로 기록하고 file fsync → rename → directory fsync → area 반영 후 성공을 응답한다. startup에는 committed 파일을 읽은 후 남은 `.tmp`를 제거한다.
- 저장/area 실패는 오류 응답 후 서버 종료다. rename 이후 실패는 디스크에 새 값이 있을 수 있다. supervisor는 Guest 전체를 종료하고 area와 클라이언트를 재생성해야 한다. 기존 reader를 유지한 서버 단독 재시작은 지원하지 않는다.
- 손상된 protobuf를 지우거나 빈 집합으로 덮어쓰지 않는다. 파일을 보존하고 시작을 거부한다. 최대 파일 크기는 4 MiB다.
- 이미지 기본값 위에 저장된 `persist.*`를 적용한다. `next_boot.persist.*`는 실제 persist 속성의 타입·권한으로 검사하고 다음 startup에 승격한다. 다른 `next_boot.*`, legacy 개별 persist 파일 마이그레이션은 지원하지 않는다.

## 실행

기존 `scripts/build-android.sh`가 `out/bin/ssal-property-service`를 만들고 모듈의 `bin/`에도 패키징한다. supervisor는 Guest `/run/ssal/property-service`에 준비·라벨링하고 새 프로세스로 실행한다.

```sh
/run/ssal/property-service --config /run/ssal/property-service.json
```

예시의 namespace/identity는 **Host에서 전환 전에 수집한 실제 값**으로 바꾼다. 설정은 supervisor가 소유한다.

```json
{
  "host_mount_namespace": "mnt:[HOST_NAMESPACE]",
  "host_property_identity": [123, 456],
  "host_socket_identity": [123, 789],
  "host_data_identity": [321, 654],
  "host_persistent_identity": [321, 987],
  "property_contexts": ["/run/ssal/guest_property_contexts"],
  "build_props": ["/run/ssal/guest_build.prop"]
}
```

필수 조건은 별도 namespace/root·독립 userdata·빈 private tmpfs `/dev/__properties__`·Host와 다른 `/dev/socket`, `/data`, `/data/property` identity다. `/data/property`를 미리 만들고 라벨링한다. 전역 SELinux Enforcing과 SID `u:r:ssal_property:s0`를 확인한다. Guest permissive 실험에서도 property_service:set은 명시적 allow를 요구한다. `/dev/socket/property_service_for_system`도 없어야 한다.

directory/info/serial/socket 라벨은 각각 `ssal_guest_property_dir`, `ssal_guest_property_info`, `ssal_guest_property_serial`, `ssal_guest_property_socket`이다. 기본 area는 `ssal_guest_property_area`, context별 area는 입력 context를 사용한다. 라벨 설정과 readback이 모두 통과해야 ready JSON을 출력한다.

worker는 시작 시 3 이상 상속 FD를 닫는다. supervisor가 stdin/로그 FD·Guest root/proc 노출·exec 전이·세션 소유권을 보장하고 ready 이후 client를 새로 exec한다. Rust PropertyConfig만 바꾸어 기존 Bionic 프로세스를 전환하지 않는다.

입력은 Guest `/system`, `/system_ext`, `/product`, `/vendor`, `/odm`, `/run/ssal` 안에서 해석한다. 명시한 파일 순서대로 뒤의 값이 우선하고 import는 거부한다. 이미지별 boot 파생값·전체 파일 목록·우선순위의 완성은 첫 부팅 후속 작업이다. `ro.property_service.version=2`는 서버가 추가한다.

읽기는 Bionic RO mmap, 쓰기는 Guest `/dev/socket/property_service`다. UID/GID/PID와 SO_PEERSEC를 얻고 context/type lookup 및 selinuxfs property_service:set을 검사한다. 소켓 0666은 연결만 허용한다. 요청 전체 읽기는 2초, V2 name/value는 1024/8192바이트로 제한하며 쓰기는 직렬화한다. `ctl.*`, `sys.powerctl`, `selinux.restorecon_recursive`는 거부하고 Host로 전달하지 않는다.

최초 fixture는 context 파일에 `persist.ssal_probe u:object_r:ssal_guest_property_area:s0 exact uint`, build.prop에 `persist.ssal_probe=1`을 사용한다. [정책 후보](../scripts/guest-domain-poc/property-service-candidate.rule)는 이 fixture용 Guest delta이며 완성된 GSI 정책이 아니다. 누락된 Guest 타입은 최소 정책으로 보완하며 Host 도메인에 broad allow를 추가하거나 전역 permissive로 바꾸지 않는다. 실행 정책은 이번 작업에서 변경하지 않았다.

## 검증과 한계

Linux/Android core 8개 시험에서 protobuf 고정 wire fixture·손상 입력, context/type 상속, V1/V2 경계, 별도 RO mmap/futex, 권한·타입·ro/control 거부, 저장 실패, lock/symlink, staged persist 복구와 Host namespace 기동 거부를 확인했다. 정책 후보 27개 문장도 설치된 ksud의 parser check를 통과했다. 이는 정책 적용·실효 권한 검증을 뜻하지 않는다.

SM-S937N의 별도 mount namespace에서 실제 삼성 Bionic getprop/setprop 쓰기·읽기, 거부 후 3회 재시도 처리, 휘발값/persist 구분과 area 재생성 후 복구도 통과했다. `/data/property`에는 새 임시 디렉터리를 bind해 실제 파일시스템에 저장했다. Host 영속 파일 해시, property/socket/data 디렉터리 identity, fingerprint 해시, boot ID, Enforcing이 전후 일치했다. [기록](../out/property-runtime-20261105.txt).

ABI 시험은 KSU SID와 기존 시험용 라벨 및 합성 allow/deny를 사용했다. **전용 ssal_property 도메인의 production serve·실제 Guest MAC 인가 검증은 남아 있다.** 정책 export가 EINVAL이어서 전체 정책 해시 불변은 증명하지 않았다. 정책 쓰기는 하지 않았다. 전체 supervisor와 `switch`는 활성화하지 않았다.

ignored Android 시험은 root와 `SSAL_PROPERTY_DEVICE_TEST=1`을 요구한다. 실패 시 namespace thread 종료로 전용 mount가 사라지고, 성공 시 normal unmount와 identity 복구도 확인한다. 전원 차단 내구성과 하드 재부팅 후 One UI 복구는 미검증이다.
