# SSAL Phase 6B — Guest installd/artd Functional Validation

2026-11-04, SM-S937N, Android 17 Host / Android 16 SDK 36 Guest.

## 결과 요약

| 검증 | 결과 | 근거 |
|---|---|---|
| Phase 5B 회귀 | **PASS** | Guest property/FD 경계, shell probe, Private Binder AIDL 호출 및 Host control socket 차단 |
| Phase 6A 회귀 | **PASS** | 공통 launcher가 Guest `installd`·`artd`를 시작하고 Private Binder에서 각각 `android.os.IInstalld`, `com.android.server.art.IArtd` descriptor를 읽음 |
| Phase 6B `IInstalld` 생성·삭제 | **PASS** | 동일 공통 launcher의 Phase 6B-Fix r3가 Private Binder에서 create/delete RPC와 Guest userdata backing을 재확인 |
| `IArtd.dexopt` 및 OAT/VDEX | **BACKLOG** | 이번 Phase의 설치·삭제 판정과 분리. 2026-11-03 Phase 2 실행에만 성공 증거가 있으며 6B-Fix 반복은 중단 |
| Host 영향 및 cleanup | **PASS** | 이번 회귀의 before/after snapshot 동일, global Enforcing 유지, Host 주요 서비스 PID 유지, Guest process/mount/cgroup/loop 정리 확인 |

Phase 6B의 `IInstalld` 생성·삭제 범위는 r3의 Enforcing Host + Guest 전용 permissive domain 실기기 증거로 **PASS**다. `artd.dexopt`와 OAT/VDEX는 별도 backlog이며 이 PASS를 낮추지 않는다. Phase 6B-Fix 반복은 종료했고 Zygote/system_server는 시작하지 않았다.

## 이번 실행의 Phase 5B/6A 회귀

기존 `--guest-services-6a-worker`와 Phase 5B 공통 경로를 그대로 실행했다. 입력은 기존 Guest 전용 profile `phase5a-bringup-20261104` 및 Android 16 system image다. stage·snapshot·로그는 `/dev/ssal-common-launcher` tmpfs에 두어 Host `/data`에는 쓰지 않았다. 유일한 영구 데이터 경로는 지정된 Guest userdata였다.

- Host global SELinux는 실행 전후 `Enforcing`; boot ID, PID 1 mountinfo, `/data` identity, property/Binder endpoint identities, 표본 property, 핵심 프로세스 신원 및 진단 service registry snapshot이 동일했다.
- before/after snapshot SHA-256은 각각 `5e197890b106a1c3ada0b05fd39b5165539e2abcb87c728526f4d266f47c488b`였다.
- Phase 5B shell/property/FD probe와 Private Binder 507:5 AIDL `add(17,25)=42`, `echo`, callback 검증이 통과했다.
- Phase 6A `installd` descriptor 응답은 `android.os.IInstalld`; `artd` 응답은 `com.android.server.art.IArtd`. 두 client 모두 Guest SDK 36, UID 1000, `u:r:ssal_guest_probe:s0`, Binder FD `/dev/binderfs/binder` 507:5에서 응답했다.
- Guest 서비스와 client 프로세스는 모두 종료/reap됐고 cgroup cleanup, rootfs 잔여 mount 검사 및 55개 APEX loop 해제가 통과했다. Host `installd` PID 2607 및 핵심 Host PID는 snapshot 간 동일했다.
- 첫 회귀 시도는 staging helper 파일 mode가 0700이라 UID 1000인 Phase 3 client가 실행하지 못해 실패했다. helper를 0755로 고친 재실행에서 통과했다. Host 영향은 없었고 첫 시도도 Guest 프로세스/mount/loop cleanup 경로를 통과했다.

## AIDL 호출 및 과거 Guest 산출물

기존 `native/binder-probe/main.cpp`의 Android 16 Parcel 인코딩을 사용한 과거 Phase 2 실행은 실제 Guest Private Binder transaction에서 성공했다. 호출 인수는 이 helper와 [Phase 2 device 결과](phase2-data-isolation-device-20261103.json)에 기록돼 있다.

- `IInstalld.createAppData`: package `com.android.ssal.phase2`, user 0, flags 3, appId 10000, seInfo `default:targetSdkVersion=36`, target SDK 36으로 CE/DE 앱 데이터를 Guest userdata에 생성했다. 이어 `destroyAppData`로 같은 package/user/flags 데이터를 삭제했고 두 경로가 사라졌음을 확인했다. helper는 `IInstalld` descriptor 확인 후 transaction 응답 parcel과 예외 코드를 검사했다.
- `IArtd.isAlive`, `getCancellationSignal`, `dexopt`: SDK 36 Guest, APK `/data/app/com.android.ssal.phase2/base.apk`, ISA `arm64`, compiler filter `verify`, reason `cmdline`, 작은 test APK, 취소되지 않은 결과를 사용했다. logging FD는 Guest `/data/local/tmp/phase2-dex2oat.log`로 전달했다.
- 과거 dexopt 응답은 성공, output 17,516 bytes, wall time 419 ms / CPU 10 ms였다. Guest userdata에서 생성된 `classes.dex`는 17,296 bytes (SHA-256 `21735da0b20ff04b7e54d7a9dc996574cb035d297dfc3976f542a301cf301204`), `classes.vdex`는 220 bytes (SHA-256 `1e50aac12926edce6d288a7ca00038d6626e6ae85cc162e5e154e9715d0f3734`)였다.
- 이 과거 실행은 `u:r:installd:s0` 및 `u:r:artd:s0`에서 수행한 Phase 2 시험이며 이번 Host Enforcing 조건의 반복 증거가 아니다. 해당 결과의 SELinux mode와 기존 제한은 원문 보고서를 따른다.

## 판정 범위

r3에서 `createAppData`와 `destroyAppData`가 같은 Private Binder session에서 성공했고, CE/DE 경로의 UID와 Guest userdata inode를 확인했다. Host service domain이나 global SELinux mode는 바꾸지 않았다. `artd.dexopt` 통합과 산출물 검증만 별도 backlog로 남긴다. 이 결과는 Zygote/system_server 부팅을 포함하지 않는다.

## 범위

Host `/data` 및 `/data/vendor` 파일에는 쓰지 않았다. Host 서비스·init·property·SELinux policy를 중지, 재시작, 변경하지 않았다. Guest 전용 userdata 밖의 파일을 삭제하지 않았다. Full Host `/data` content digest는 이번 snapshot에 포함하지 않았으며, 결과는 process/property/mount/Binder 경계 증거로 한정한다.
