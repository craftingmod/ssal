# 이전 부팅 커널 패닉 조사

- 기기: Samsung SM-S937N (PSQ)
- 조사 대상: 재부팅 후 현재 로그가 아닌 직전 부팅의 보존 커널 로그
- 원본: `last_kmsg.txt` (기기 `/proc/last_kmsg`, 2,097,136 bytes, 20,594 lines)
- 커널: `6.6.127-android15-8-p87b1ce1-abogkiS937NKSSBDZJ2-4k`, build `4ada8571dcf2ef127627ffc0429891950f882248`
- 추정 발생 시각: 2026-11-06 04:37:03 KST. 직전 `!@Sync`의 커널 경과시간/시각 58259.766598 / 04:36:41.511 (원본 line 17534)와 패닉 58281.236108을 비교한 근사치.

## 결론

직전 부팅은 일반 종료 로그가 아니라 커널 BUG로 끝났습니다. `include/linux/task_integrity.h:150`의 BUG가 `five_task_free+0x40/0x70`에서 발생했고, task 정리 중 RCU callback 경로(`__put_task_struct → delayed_put_task_struct → rcu_do_batch → rcu_nocb_cb_kthread`)에서 처리되고 있었습니다. 커널은 이를 `Oops - BUG: Fatal exception in interrupt`로 기록했습니다. Samsung panic upload cause와 QCOM Apps Watchdog bite가 뒤따라 하드웨어 watchdog 재부팅으로 이어졌습니다.

패닉 직전 기록에는 audit backlog rate limit(원본 18183–18184)과 KernelSU의 `handle_setresuid from 0 to 1000`(18186)이 있습니다. 시간상 근접하지만 현재 덤프만으로 이 이벤트가 원인이라고 단정할 수 없습니다. 핵심 로그와 호출 스택은 `panic-excerpt.txt`에 원본 행 번호와 함께 발췌했습니다.

## 수집 한계

`adb logcat -L -b all -d`는 `Logcat read failure: No such file or directory`로 실패해 이전 부팅 logcat은 회수하지 못했습니다. 재부팅 후 `/sys/fs/pstore`는 비어 있었고, `/proc/last_kmsg`가 유일하게 확보된 이전 부팅 커널 기록입니다. 현재 부팅의 로그는 조사 대상에 포함하지 않았습니다.
