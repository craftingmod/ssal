# Phase 8B-3A — 결과

## 최종 상태: PARTIAL — Stock shared SID 실행 승인 없음

Host active binary와 Guest 분석용 composite를 SETools로 읽고 attribute 확장 후 실효 access-vector 튜플을 차분했다. 주요 비교는 재현 가능한 JSON으로 저장했다. 그러나 Guest 완성 policy가 neverallow 및 genfs 검증을 통과하지 못했으므로 결과는 static partial이다. 실제 Guest system_server는 실행하지 않았고, Host 정책이나 GSI도 변경하지 않았다.

Stock GSI의 최종 context는 u:r:system_server:s0이며 Host와 공유된다. 저장된 Host binary에서 system_server_startup의 setcurrent/dyntransition to system_server 권한은 보이나, 실제 Guest zygote source와 Guest 전용 startup/final type이 해당 binary에 없어 초기 전이는 미확인이다. 따라서 Stock shared SID 실행을 허용하지 않는다.

## 입력 및 해시

| 입력 | SHA-256 |
|---|---|
| Host active binary policy | 577b6b469b8b914ae3b62ab79fa9f36088d611bb3991a56864c106f24d61a723 |
| LineageOS 23.2 GSI image | 7b9ba62e8b48b6e40432be949ae0858a8971175c79502550e74691222d3889ff |
| Host plat_sepolicy.cil | 425aba8b73da746a6338a3d42f6dfd20b5bfdd02163928f1aee0b7b333ab03c9 |
| Host system_ext_sepolicy.cil | 3ea88731ec5753c3d6803c9cf85cdaeae507bfbb6d64ecdca650438575736b5c |
| Host product_sepolicy.cil | 7b25f3b8af6373c43ade1725a7cee70b97a81d34c15ff146f473940fc8c01aa4 |
| Host vendor_sepolicy.cil | a06d7a774089c364a9ba33a177e35000d9ce0ea83ed351251ce06567eba2f3d1 |
| Host plat_pub_versioned.cil | 32f3a336016d2b76733291942e97ecc193d830e88fa95e1bc48d381d091ec9b0 |
| Host plat_sepolicy_vers.txt | eeca818079e5046c4dac8c144e375a211c660816162dff7596765a5b06427050 |
| Guest plat_sepolicy.cil | be4eb2bcc7c1fe5bec30ec686b8ac1df28eec0eefcc48b9f541fd2f8cfffa167 |
| Guest system_ext_sepolicy.cil | 74dd0be2cbcf599baede7e1cd5d25529cdb72976b5ab8f880b498c8cdf55ef60 |
| Guest product_sepolicy.cil | 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b |
| Guest API 202404 mapping | 43db2e1852dc8b2e15e8f1efabcfd73c963626814c8dd7bf111b41ecfb97a6a7 |
| Guest API 202404 compat mapping | 894306fc43e65914167097a9edc97bd3a14ea95f6c65ef8bb385ba1aa93f9b45 |
| Guest supplemental genfs 202504 | 480d503e7730236b659230d16b3946b628394d529dabfef67c679281fd98357b |
| Guest supplemental genfs 202604 | 3bdfcfba699936cb12d007fee7bca2feb1a88c75cc947f98b14c55fe4932b0d3 |
| Collected patch-plan.json | 843d97ae962b88a67a09da3e8e08d176bbb66ecc8eb0d68402f5de8e9f57ec01 |
| Selected image, policy, context, and triage inputs | [65-file manifest](phase8b3a-inputs.sha256), SHA-256 cdeab62cadf26b602c003edcd4d2baaa41fa92085f657dfc9e1d8966a37a8b0b |

The manifest includes all selected Host and Guest file, service, property, seapp, hwservice, keystore and TEE service contexts, plus the policies, image and triage plan listed above. The canonical extracted input directory is out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/. Host vendor API version is 202404; Guest supplies the matching 202404 mapping.

The analysis binary is a temporary artifact, not a loadable policy: /tmp/ssal-secilc/guest-plus-host-vendor-av-final.bin, SHA-256 4883aab6674881495aad41c45f8765e8d24cb93fa39f7ecce2da125afe3a40ba.

## Tooling 및 재현

- WSL distribution: Ubuntu 26.04.
- SETools 4.6.0 and secilc 3.9-1 were extracted under /tmp; system packages were not installed.
- The analyzer is [phase8b3a_policy_diff.py](../scripts/phase8b3a_policy_diff.py). The normalized full result is [phase8b3a-system-server-policy-diff.json](phase8b3a-system-server-policy-diff.json), SHA-256 6a5d8d919983b0d72e5a768143b4d6c8e7f5a36a4841a080e72d11960af7f398 (phase8b3a-system-server-policy-diff-v1, 15,324,368 bytes).
- Synthetic unit tests are in [test_phase8b3a_policy_diff.py](../scripts/test_phase8b3a_policy_diff.py).

The completed synthetic check command was:

```sh
wsl -d Ubuntu-26.04 -- sh -lc 'PYTHONPATH=/mnt/v/workspace/Toy/ssal/scripts python3 -m unittest test_phase8b3a_policy_diff -v'
```

**Result: PASS — 3 synthetic tests.** They cover attribute expansion, Guest-only target attribute membership, set differences, and comparable coverage.

The successful AV-only composite was compiled with secilc -N -m -M true -G -c 30. Its inputs were Guest platform/system_ext/product CIL, Host plat_pub_versioned.cil, Guest API 202404 and compat mappings, and a temporary Host vendor CIL copy with genfs lines removed. The temporary Guest platform CIL copy had the Android-only functionfs_seclabel policycap line removed because upstream secilc 3.9 does not recognize it. The Guest supplemental 202504/202604 genfs CIL files were not included. -N disables neverallow checks. No temporary file was written into the GSI or source CIL tree.

The command used for the analysis composite was:

```sh
secilc -N -m -M true -G -c 30 -o /tmp/ssal-secilc/guest-plus-host-vendor-av-final.bin \
  /tmp/ssal-secilc/guest-plat.cil \
  /mnt/v/workspace/Toy/ssal/out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/guest/system_ext/etc/selinux/system_ext_sepolicy.cil \
  /mnt/v/workspace/Toy/ssal/out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/guest/product/etc/selinux/product_sepolicy.cil \
  /mnt/v/workspace/Toy/ssal/out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/host/vendor/etc/selinux/plat_pub_versioned.cil \
  /mnt/v/workspace/Toy/ssal/out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/guest/system/etc/selinux/mapping/202404.cil \
  /mnt/v/workspace/Toy/ssal/out/selinux-check/2026-10-30T21-06-36-556Z-feba58ef/guest/system/etc/selinux/mapping/202404.compat.cil \
  /tmp/ssal-secilc/vendor-no-genfs.cil
```

The comparison command was:

```sh
PYTHONPATH=/tmp/ssal-setools/root/usr/lib/python3/dist-packages:/mnt/v/workspace/Toy/ssal/scripts \
python3 /mnt/v/workspace/Toy/ssal/scripts/phase8b3a_policy_diff.py \
  /mnt/v/workspace/Toy/ssal/out/selinux-check/2026-11-04-host-active-policy.bin \
  /tmp/ssal-secilc/guest-plus-host-vendor-av-final.bin \
  /mnt/v/workspace/Toy/ssal/docs/phase8b3a-system-server-policy-diff.json
```

## Validity limits and checks

- A normal Guest CIL compile with neverallow checking enabled failed with 889 neverallow and 16 neverallowx diagnostics. These are static compiler findings, not runtime AVCs. The analysis candidate's successful -N compile is not evidence that these assertions pass.
- A full Guest plus Samsung vendor compile that retained genfs declarations failed with Problems processing genfscon rules. The collected patch plan records the iso9660 / and udf / Guest declarations conflicting with Host vendor vfat /. The AV-only candidate removed vendor genfs declarations to make rule enumeration possible; it is not a valid runtime merge.
- SETools reported the saved Host binary as policy version 30, with 4,988 types, 520 attributes, 90 constraints, and zero typebounds. The analysis Guest candidate had 4,611 types, 488 attributes, 97 constraints, and zero typebounds. The Guest candidate lists backuptool, phhsu_daemon, tkcore, and ueventd as permissive types; this is a property of the offline analysis candidate, not a live device policy change.
- The source-CIL inventory's 21 Guest-only attribute names and compiled candidate's 32-name difference refer to different policy universes. Type/attribute name equality does not prove object identity or runtime relevance.
- The saved Host binary does not contain ssal_guest_probe, ssal_guest_system_server_startup, or ssal_guest_system_server. Earlier runtime notes identify the Guest zygote as ssal_guest_probe; the saved binary therefore cannot establish its live transition permissions. Active KernelSU additions may also differ from the snapshot.
- The previous 37 context-invalid results and the 18-name overlap are triage inputs only. Their boot relevance is unknown, and they were not rerun against the current live kernel.
- No Guest system_server fork, SystemServer.main()/run(), AVC collection, Host policy modification, Global/Host permissive change, GSI rebuild, or live policy load occurred. Runtime child capabilities, signal/ptrace access, PID-shared /proc behavior, and Host negative-boundary tests remain unknown.

## 권고

The 8B-3A comparison meets the main static comparison objective but remains **PARTIAL** under the requested exit criteria because the Guest policy universe was incomplete and could not pass full compile validation. Continue to 8B-3B only for Guest-specific transition and boundary validation using the Phase 8B-2 design. Keep Host enforcing and avoid the stock shared system_server SID. Resolve runtime-driven Guest-only types/permissions incrementally; missing Guest-only SELinux symbols are implementation work when safely contained, not automatic NO-GO conditions.

Related prior evidence: [Phase 8B-2 transition analysis](phase8b2-selinux-transition.md), [Phase 8B-2 results](phase8b2-results.md), [Phase 8A Host boundaries](system-server-phase8a-host-boundaries.md), and [SELinux reuse assessment](selinux-reuse-assessment-20261104.md).
