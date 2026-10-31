# Guest SELinux Live PoC — 중단 기록

2026-10-31 기기 `R5CY52JC03H`에서 승인 후 전용 임시 디렉터리에 빌드 산출물을 전송했다. 기기에서 계산한 세 파일의 SHA-256은 로컬에서 승인된 값과 모두 달랐고 파일 길이도 launcher 668, identity 668, query 60 bytes로 잘못됐다. 승인 전 계획의 해시 불일치 중단 조건에 따라 즉시 중단했다. 원인은 아직 확정하지 않았다.

`ksud sepolicy patch`는 한 번도 실행하지 않았고, SELinux 라벨 변경, Guest 도메인 전환 및 재부팅도 하지 않았다. 전용 디렉터리와 그 안의 세 파일을 삭제하고 경로가 없음을 확인했다. 전후 부팅 ID `c0f129b3-1ba5-4b78-8246-58dae210994e`, global Enforcing 및 두 신규 context의 EINVAL이 유지됐다. 지정된 세 AV 결과·sequence, 두 모듈 정책 파일 해시, init/vendor_init/servicemanager/zygote64/system_server/surfaceflinger의 PID·start time·context·exe는 전후 일치했다. 이 관찰은 전체 Host 상태 불변이나 One UI 복구를 증명하지 않는다. [전후 원본](../out/guest-domain-live/before.json), [사후 원본](../out/guest-domain-live/after.json)을 보존했다.

승인된 원본 launcher SHA-256은 `885ea174c6c9e777d5fd470334b521f5483479761b4e5faac12a2b4a91e6743b`, identity는 `155709304ee012e9d803b4dfe02da4cfd5d9a0bba2cd5588f36a5a66604dba9c`, query는 `f269b6a667800f996f9d4eda53fb566ee995f76f112ee0f1e0e98e54656ee1aa`였다. 각각 기기에서 얻은 잘못된 해시는 `9bdee87b26d126df218b819451f15e4100142e14aa397879455e0fecd28f457b`, `61f0ed44f62ac032ea8137a8c508ee8a6353828f4c23e0ceff8771c95346de00`, `e4fe89567edf7e7c73b3c0e8165783acb2b19472e20da55df5b43006c21260c4`다. 손상된 파일은 실행하지 않았다.

재시도에는 바이너리 안전 전송 방식과 root 소유 전용 디렉터리, 기기에서의 SHA-256 확인을 먼저 확보해야 한다. 해시가 일치한 후에도 기존 계획의 context, AV, relabel, mount 및 enforcing 중단 조건을 그대로 적용해야 한다.
