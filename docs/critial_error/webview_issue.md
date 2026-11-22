# WebView Multi-Process Black Screen Issue Report (`ssal`)

## 1. 개요 (Summary)
- **증상**: `ssal` 게스트 환경(`org.lineageos.jelly`)에서 WebView를 멀티프로세스 모드로 실행할 경우, `--single-process` 플래그를 제외하고는 화면이 검은색으로만 렌더링됨(크래시 및 명시적 에러 로그 없음).
- **근본 원인**: `ssal`의 게스트 SELinux 정책 생성 시 호스트 커널 `mlsconstrain`이 참조하는 전역 호스트 attribute(`app_data_file_type`, `appdomain_tmpfs`) 연결이 누락됨. 이로 인해 `Jelly`가 `cache/` 임시 파일 FD를 `sandboxed_process0`로 `SCM_RIGHTS` 전송할 때 커널 `selinux_file_receive()`가 MLS 카테고리 불일치로 FD를 차단(`MSG_CTRUNC`)하여 Mojo 채널/렌더링 초기화가 조용히 실패함.
- **조치**: `src/guest/selinux/mod.rs` 및 `src/guest/selinux/native.rs`에서 호스트 MLS attribute 매핑 및 `typeattribute` 허용 목록에 `app_data_file_type`, `appdomain_tmpfs`를 추가하여 해결 (`setenforce 1` 상태에서 정상 렌더링 확인).

---

## 2. 원인 분석 (Root Cause)

### 2.1. 프로세스 간 SELinux 컨텍스트 및 MLS 불일치
실제 동작 시 각 주체와 객체의 SELinux 컨텍스트는 다음과 같음:
- **브라우저 (`org.lineageos.jelly`)**: `u:r:ssal_p0002_untrusted_app:s0:c101,c256,c512,c768`
- **격리 렌더러 (`com.android.webview:sandboxed_process0`)**: `u:r:ssal_p0002_isolated_app:s0:c512,c768`
- **전달 대상 캐시 파일 (`cache/.org.chromium.Chromium.*`)**: `u:object_r:ssal_p0002_app_data_file:s0:c101,c256,c512,c768`

AOSP의 `system/sepolicy/private/mls` (`mlsconstrain`)는 `isolated_app`(`s0:c512,c768`)처럼 카테고리(`c101,c256`)가 다른 주체가 이미 열린 `app_data_file` FD를 `read`/`write`할 때, 대상 파일 타입이 **`app_data_file_type`** (또는 `appdomain_tmpfs` / `mlstrustedobject`) attribute에 속한 경우에만 예외적으로 통과시킴.

### 2.2. `ssal` SELinux 정책 생성 누락
1. **`src/guest/selinux/mod.rs` (`L876-893`)**: 호스트 커널의 `mlsconstrain`이 참조하는 호스트 attribute 중 `mlstrustedsubject`, `mlstrustedobject`만 게스트 타입에 부여하고 **`app_data_file_type`**, **`appdomain_tmpfs`**는 누락됨.
   *(참고: TE `allow` 규칙 자체는 `mod.rs` `L1005-1044`에서 `ssal_p0002_isolated_app_all` → `ssal_p0002_targets_app_data_file_type`으로 정상 변환되어 있었음.)*
2. **`src/guest/selinux/native.rs` (`L80-94`)**: `PolicyCommand::owned()`의 `cmd == 5` (`typeattribute`) 허용 목록에도 `mlstrustedsubject`, `mlstrustedobject`만 포함되어 있었음.

### 2.3. 왜 에러 로그 없이 블랙스크린으로만 나타났는가?
1. **커널 `SCM_RIGHTS`의 `MSG_CTRUNC` 처리**: `Jelly`가 `openat(..., O_RDWR|O_CREAT)`로 파일을 여는 것까지는 성공했으나, `sandboxed_process0`가 `recvmsg()`로 FD를 수신할 때 커널(`scm_detach_fds` → `security_file_receive`)이 첫 번째 FD에서 MLS 거부를 반환하면서 `EACCES` 대신 `msg_controllen=0, msg_flags=MSG_CTRUNC`로 FD만 잘라냄.
2. **릴리스 WebView의 무로그 처리**: 릴리스 빌드에서는 `DCHECK(!(msg.msg_flags & MSG_CTRUNC))`가 비활성화되어 있어, `ChannelPosix`가 크래시 대신 해당 Mojo 메시지/핸들을 조용히 실패 처리하면서 렌더러 프로세스는 살아있고 화면만 검게 남음.
3. **`audit` / `logd` 관측 손실**: 호스트 `logd`가 커널 `audit_pid`를 점유하고 있어 `dmesg`로 `avc: denied`가 내려오지 않았고, 동시에 `audit: rate limit exceeded`로 다량의 `avc` 이벤트가 드롭되어 호스트/게스트 양쪽 로그에서 누락됨.

---

## 3. 진단 및 진행 과정 (Investigation Timeline)

1. **Zygote / 스레드 / Binder 스폰 확인 (`ps -eZ`, `ps -T`)**
   - `ssal_p0002_webview_zygote`로부터 `sandboxed_process0`가 정상 포크되었고, 내부 스레드 `Chrome_ChildIOT`, `CrRendererMain`, `Compositor`, `Preload scanner`가 모두 생존해 있음을 확인.
   - → 프로세스 스폰, `setupConnection()`, 초기 Mojo `socketpair` 핸드셰이크, RELRO 매핑, HTML 파싱 진입까지는 정상 통과함을 확인.
   - *(부수 확인: `--disable-gpu --disable-gpu-compositing` 테스트 시 Android WebView 미지원으로 인해 Activity View 생성 자체가 실패함을 확인하고 원복.)*

2. **`strace`를 통한 `sandboxed_process0` 시스콜 추적**
   - `fcntl(fd, F_GET_SEALS) = -1 EINVAL` 및 `memfd_create("", ~0) = -1 EINVAL` 관측 → 직후 `ioctl(..., ASHMEM_GET_PROT_MASK)`와 `mmap(..., MAP_SHARED)`가 정상 성공했고 `memfd_create(~0)`은 Chromium의 `ChannelLinux` 정상 프로브임을 확인(`ashmem` 문제 배제).
   - `/dev/__properties__/`, `/dev/cpuctl/`, `/dev/blkio/` 노이즈를 제외하고 전체 시스콜 실패를 필터링한 결과, `Chrome_ChildIOT`의 `recvmsg(87, ...)`에서 `174`바이트 Mojo 메시지(`num_handles = 1`)만 반복적으로 **`msg_controllen=0, msg_flags=MSG_CTRUNC`**가 발생함을 포착 (동일 소켓의 `/dev/ashmem` FD 수신은 모두 성공).

3. **SELinux 이분법 검증 (`setenforce 0`)**
   - `setenforce 0` 전환 즉시 멀티프로세스 WebView가 정상 렌더링됨을 확인 → SELinux `Enforcing` 차단이 유일한 직접 원인임을 확정.

4. **송신 측(`Jelly`) `SCM_RIGHTS` FD 역추적 및 라벨 대조**
   - `ssal_p0002_zygote` 산하 `Jelly` 프로세스를 `strace`로 추적하여 `174`바이트 `sendmsg` (`cmsg_data=[159]`)의 원본 FD를 특정:
     ```text
     openat(AT_FDCWD, "/data/user/0/org.lineageos.jelly/cache/.org.chromium.Chromium.8MdBHY", O_RDWR|O_CREAT|O_TRUNC, 0600) = 159
     sendmsg(142, {..., iov_len=174}, ..., cmsg_data=[159]) = 174
     ```
   - `mountinfo` 및 `ls -ldZ`로 `Jelly`의 `cache`가 게스트 마운트 네임스페이스에 정상 격리되어 있고 라벨이 `u:object_r:ssal_p0002_app_data_file:s0:c101,c256,c512,c768`임을 확인.
   - `/dev/ashmem`(`s0` / `mlstrustedobject`)은 통과하고 `ssal_p0002_app_data_file:s0:c101,c256,c512,c768`만 `ssal_p0002_isolated_app:s0:c512,c768`로 전달될 때 실패한 점에서 호스트 MLS attribute 연결 누락으로 최종 특정.

---

## 4. 수정 사항 (Fix)

1. **`src/guest/selinux/mod.rs`**
   - 호스트 MLS attribute 매핑 대상에 `"app_data_file_type"`, `"appdomain_tmpfs"` 추가 (`L876-893`).
   - 캐시된 `plan.json` 재생성을 위해 `VERSION`을 `80` → `81`로 상향 (`L16`).
   - `guest_mls_trusted_types_inherit_host_mls_attributes` 단위 테스트에 `app_data_file_type` 상속 검증 추가 (`L2699-2715`).

2. **`src/guest/selinux/native.rs`**
   - `PolicyCommand::owned()`의 `cmd == 5` (`typeattribute`) 허용 목록에 `"app_data_file_type"`, `"appdomain_tmpfs"` 추가 (`L85-94`).

---

## 5. 검증 결과 (Verification)

- **빌드**: `bun run build` 성공 (`out/ssal-module.zip` 패키징 완료)
- **단위 테스트**: `cargo test --lib guest_policy` — `36 passed, 0 failed` (`2 ignored` fixture tests)
- **실기기 동작 검증**: SELinux `Enforcing` (`setenforce 1`) 상태에서 `org.lineageos.jelly` 멀티프로세스 WebView 정상 렌더링 확인

---

## 6. 회고 및 재발 방지 포인트 (Lessons Learned)
- **컨테이너/SELinux 디버깅 우선순위**: `logd`/`audit` 로그가 비어 보이더라도 `dontaudit` 및 `audit: rate limit exceeded`로 누락될 수 있으므로, 초기 단계에서 `setenforce 0` 같은 이분법 스위치를 우선 확인한다.
- **`strace` 활용**: 무로그 블랙스크린이나 IPC 정지 증상에서는 `-e trace=...` 필터로 범위를 좁히기 전에 전체 시스콜을 수집한 뒤 `/dev/__properties__/` 등 반복 노이즈를 `grep -v`로 제거해 `EACCES`, `EPERM`, `MSG_CTRUNC`를 확인하는 편이 누락 없이 빠르다.
- **호스트-게스트 SELinux 분리 시 전역 attribute 주의**: 호스트 커널 `mlsconstrain`에 직접 참조되는 전역 attribute(`mlstrustedsubject`, `mlstrustedobject`, `app_data_file_type`, `appdomain_tmpfs` 등)는 게스트 타입 접두사 변환 시 반드시 호스트 attribute 상속을 유지해야 한다.

---

## 7. 노트 (인간이 작성함)

이거 디버깅하고 고친다고 LLM 주간 한도가 60% 증발함

뭔 이딴 SELinux 3중 격리 정책이 다있는지 어지러움

안드로이드 10년 넘게 썼는데 이런 구조가 있다는 것 자체를 난생 처음 들음

WebView는 직접 구현 안 하고 내장 WebView를 쓰자는 교훈을 얻음

Google Ai Studio 최고