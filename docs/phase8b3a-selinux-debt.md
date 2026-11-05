# Phase 8B-3A — SELinux 부채 목록

이 문서는 정적 비교에서 관찰한 차이와 다음 런타임 단계에서 확인할 항목을 분리한다. Guest에만 있는 type이나 permission은 구현 후보이며 자동 NO-GO로 보지 않는다. 아래의 P1/P2 표시는 테스트 순서 제안이고, 부팅 필수성의 증명은 아니다.

## P0 — Guest system_server 진입 및 격리 차단

| 항목 | 근거 / 상태 | 최소 보완 및 Host 영향 |
|---|---|---|
| Stock final SID 공유 | GSI native specialization은 u:r:system_server:s0를 하드코딩한다. 저장된 Host binary는 system_server_startup → system_server의 setcurrent/dyntransition 권한을 보유한다. 같은 SID는 독립 Guest identity가 아니다. | Phase 8B-2의 Guest-specific startup/final SID source patch와 Guest-only domain scaffold를 계속 사용한다. Host system_server 규칙 변경 없음. Stock shared SID로 실행하면 Host/Guest 경계 위험이 큼. |
| 실제 Guest zygote의 시작 전이 미확인 | 저장된 Host binary에는 ssal_guest_probe 및 제안 Guest startup/final type이 없다. Guest GSI CIL의 zygote → system_server_startup rule은 실행 중 SSAL zygote의 source ssal_guest_probe를 증명하지 않는다. | 다음 정책 스냅샷에 실제 Guest source와 Guest 전용 목적 type이 있는지 검사하고 transition 경로를 대조한다. Guest-only source/target로 한정한다. 이 결과만으로 Guest allow를 추정하지 않는다. |

위 두 항목은 identity/transition gate다. 두 항목은 “없는 Guest type/attribute는 만들면 안 된다”는 뜻이 아니다. Guest-only 정의와 좁은 전환 규칙으로 검증을 계속한다.

## P1 — Bootstrap 후보, 아직 필수성 미확인

| 항목 | 정량 / 관련성 | 다음 확인 |
|---|---|---|
| Source allow 부족 후보 | Guest-only 1,132 tuples 중 853은 Host에 없는 51 target type에 걸려 비교 불가; 나머지 279는 Host-present type에 있으나 Host allow와 불일치. | 제한된 Guest 부팅 로그에서 실제 AVC의 Guest source/type, 대상, class, permission을 기록한다. P0/P1 승격은 첫 부팅 호출 의존성으로 판단한다. |
| Binder / service / property 권한 | Host-present type 차이는 binder 6, service_manager 2, property_service 1. | 초기 Binder transaction, 필수 service 등록, property access의 실제 순서를 확인한다. Private Guest endpoint label은 유지한다. |
| 파일·프로세스·socket 권한 | 차이 279 중 file/dir/link/device/pipe/fd 합계 234, socket class 합계 24, process 12. Guest child capability 및 /proc 경계는 미관찰. | 실제 bootstrap에서 접근한 객체에 한해 Guest-specific 최소 권한을 검토하고 signal, ptrace, capability, cgroup 동작을 별도 경계 시험한다. |
| Context-invalid 표본 | 이전 patch-plan.json의 37 invalid 항목 중 18 type이 Guest system_server source allow의 target 집합과 겹침. 18개 전부 required_for_boot=unknown, runtime_use=unverified. | 현재 Guest/Host policy와 context source에서 재검증한 뒤 실제 첫 부팅 AVC가 증명하는 항목만 처리한다. 2026-10-31 검사 결과를 현재 kernel의 EINVAL로 간주하지 않는다. |

18개 교집합 type: adbroot_service, ashmem_compat_memfd_context_file, fingerprint_hidl_service, hal_fingerprint_oppo_compat_exec, lineage_globalactions_service, lineage_hardware_service, lineage_health_interface_service, lineage_livedisplay_service, lineage_profile_service, lineage_trust_service, native_binder_stats_prop, persist_sysui_builder_extras_prop, persist_sysui_ranking_update_prop, smcinvoke_device, xtra_control_prop, mediashell_app, qcrilam_app, updater_app.

Context type가 정책에 없다는 사실은 해당 서비스가 bootstrap에 필요하다는 증거가 아니다. 사용자 데이터, TEE, radio, fingerprint, Host property 또는 Host Binder label을 재사용하지 않는다.

## P2 — 기능 확장 및 후순위 후보

| 항목 | 관찰 | 처리 기준 |
|---|---|---|
| Lineage 전용 서비스 및 앱 | 96 Guest-only type 이름 중 일부가 Lineage service/app label이다. | 서비스가 실제 부팅 중 호출되는지 관찰하기 전에는 만들거나 권한을 열지 않는다. |
| 선택 Vendor HAL / 장치 type | Host/Guest 정책 type universe가 다르고 일부 Guest target 이름은 Host binary에 없다. Host-only permission도 Guest 요구 권한으로 취급하지 않는다. | /dev/hwbinder, /dev/vndbinder, KeyMint/TEE/radio/fingerprint 등 Host endpoint는 기본 Guest 경로에서 연결하지 않는다. |
| 전이 부수 차이 | system_server source type_transition은 Host 13 / Guest 12이며 Host-only system_server_wrapfd record 하나가 있다. | 실제 사용이 확인되지 않으면 유지하거나 보완하지 않는다. |

정책 source의 Guest-only attribute 이름은 기존 inventory에서 21개였다. 비교용 compiled type universe에서는 32개 이름이 Host binary에 없으며, 이 중 어떤 것도 system_server source allow rule의 attribute operand로 직접 쓰이지 않았다. 새 공용 attribute membership을 추가하면 Host의 기존 규칙 확장 범위가 바뀔 수 있으므로 Guest-only namespace에 한정하고 효과를 재분석한다.

## 최소 보완 경로와 오류 구분

1. **먼저 identity를 분리한다.** [Phase 8B-2 Guest patch](../scripts/guest-domain-poc/phase8b2-guest-gsi.patch)와 [Guest-only 전이 초안](../scripts/guest-domain-poc/phase8b2-domain-transition.rule)은 review candidate다. 현재 GSI나 live policy에 적용하지 않았다.
2. **Host를 enforcing으로 둔다.** AVC 수집이 필요하면 Guest 전용 transition/final domain의 제한된 permissive를 이용하고, Host system_server, Host zygote, global policy에는 permissive나 추가 allow를 넣지 않는다. 수집 후 enforcing 검증 전에 permissive 문을 제거한다.
3. **필요한 규칙만 만든다.** 실제 AVC가 가리키는 Guest source에서 Guest가 소유한 target으로 class/permission을 한정한다. Guest-only type/attribute가 없다면 최소 정의를 추가하고 이어서 검증한다. 광범위한 Host domain이나 공용 attribute를 대상으로 하지 않는다.
4. **EACCES와 EINVAL을 구별한다.** 유효한 SID에서 허용되지 않은 permission은 enforcing AVC/EACCES 후보이며 좁은 Guest allow로 해결할 수 있다. 알 수 없는/유효하지 않은 context type은 EINVAL 후보이므로 permissive만으로 해결되지 않는다. 현재 37-item 목록은 과거 검사이며 이번 active binary의 재검증 결과가 아니다.

이 보고서에서는 allow rule을 추가하거나 적용하지 않았다. 전체 Guest GSI 정책에서 neverallow/genfs 검증이 해결되지 않았으므로 최종 enforcing 부채 목록은 runtime AVC 및 유효한 Guest 정책 compile을 거친 뒤에 확정한다.
