# Device-side evidence report (publication-safe)

## Summary

- **28 observed facts (O1–O28)**, each backed by an exact retained line or command output.
- **10 inference-only claims (I1–I10)** — these are hypotheses, not measurements, and must be labelled as such in any publication.
- One observed root grant; every later attempt ended in reboot, with markers absent and no readable kernel panic log.
- All hash / CRC / vermagic checks were **read-only and offline**; the verification notes explicitly state no device was used.
- Reproduce with the generic commands shown per item; no absolute locations are supplied anywhere in this report.

## 0. Provenance and rules used

Sources were four kinds of retained artifacts: (a) a device-side logcat capture relayed to a host over adb, (b) shell captures taken after a reboot, (c) kernel messages pulled after a failed run, and (d) read-only offline build-verification notes. An item is **OBSERVED** only when a literal line or command output exists in one of those artifacts. Everything else is **INFERENCE** and appears only in section 5. Commands use placeholders such as `<artifact>` and `<manager-apk>`; no device addresses, ports, credentials or private repository identifiers are reproduced.

---

## 1. Observed device identity (measured)

**O1 — Kernel release.** Exact lines in three independent captures:

```
I dfroot  : kernel version: 5.4.274-qgki-30957850-abG998USQSJHZB1
[INFO]   release           = 5.4.274-qgki-30957850-abG998USQSJHZB1
5.4.274-qgki-30957850-abG998USQSJHZB1
```

Reproduce: `adb shell uname -r`; `adb logcat -d -b all | grep 'kernel version'`.

**O2 — Model, manufacturer, Android version, security patch level**, from the on-device loader log:

```
I dfroot  : manufacturer: samsung
I dfroot  : model: SM-G998U
I dfroot  : android version: 15
I dfroot  : security patch: 2026-01-01
```

Reproduce: `adb shell getprop ro.product.model`; `adb shell getprop ro.build.version.release`; `adb shell getprop ro.build.version.security_patch`.

**O3 — Build identifier and CSC.** The device-comparison notes record build `AP3A.240905.015.A2.G998USQSJHZB1`, CSC `TMB`. The relay capture independently shows:

```
D SWT_Utils: isFotaUpgrade : currentPDAVersion = G998USQSJHZB1, currentCSCVersion = G998UOYNJHZB1, currentQBId = 106867230, storedPDAVersion = G998USQSJHZB1, storedCSCVersion = G998UOYNJHZB1, storedQBId = 106867230
I StubUtils: getCSC() cscVersion[TMB]
I DigitalKey: [Feature] Device version from PDA ('G998USQSJHZB1'): 'ZB1'
```

Reproduce: `adb shell getprop | grep -iE 'build|csc|firmware'`.

**O4 — Vendor/system release split and KMI choice**, measured during setup:

```
I dfroot  : ro.vendor.build.version.release = 11
I dfroot  : ro.build.version.release        = 15
I dfroot  : vendor and system releases disagree, using vendor 11 over system 15
I dfroot  : android11 is not a module for kernel 5.4 (1 candidate) - taking the nearest one
I dfroot  : Kernel 5.4 android11 -> Using KMI: android15-5.4
```

**O5 — SELinux state.** The root-proof capture ends with:

```
=== getenforce ===
Permissive
```

and the pulled kernel log contains `KernelSU: transive_to_domain: stubbed (permissive carries)`. Reproduce: `adb shell getenforce`; `adb shell su -c getenforce`.

**O6 — `kptr_restrict`.** The retained device notes state `kptr_restrict=4, uid 2000`, and the live kernel-symbol capture contains the symbol `ffffffc012e52b90 D kptr_restrict`. Limitation: no captured stdout line of `cat /proc/sys/kernel/kptr_restrict` exists among the retained artifacts, so the numeral `4` is *recorded in notes*, not re-measured here. Reproduce: `adb shell id; adb shell cat /proc/sys/kernel/kptr_restrict`.

---

## 2. Observed root proof events

All lines in this section come from one on-device capture written by the helper.

**O7 — Timestamp of the capture:** `Sun Nov 22 01:01:33 UTC 2026`.

**O8 — `su` identity**, exact output:

```
uid=0(root) gid=0(root) groups=0(root) context=u:r:shell:s0
```

**O9 — Capabilities**, exact output (tab-separated in the original):

```
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
```

**O10 — Manager LKM state**, exact line:

```
kernelsu 311296 4 - Live 0x0000000000000000 (O)
```

Reproduce: `adb shell lsmod | grep kernelsu`; `adb shell cat /proc/modules | grep kernelsu`.

**O11 — Loaded-module snapshot from a later run**, exact first lines:

```
Module                  Size  Used by
kernelsu              262144  0
df_self                20480  0 [permanent]
```

**O12 — Root-only markers present in that capture**, exact output:

```
-r---w---- 1 root root 0 2026-11-21 18:40 /dev/dfINIT
-r---w---- 1 root root 0 2026-11-21 18:40 /dev/dfTP_OK
-r---w---- 1 root root 0 2026-11-21 18:36 /dev/dfm0
-r---w---- 1 root root 0 2026-11-21 18:36 /dev/dfr0
-r--r--r-- 1 root root 4 2026-11-21 18:40 /dev/dfws
```

**O13 — Manager version**, exact line: `versionName=v3.2.5-o1s`.

**O14 — Kernel-side grants** in the pulled `dmesg` after that run, exact lines (four grants, same format):

```
[  877.243996] KernelSU: ksu su grant: sh(2000) exec /system/bin/sh (cred+real, persistent)
[  877.245580] KernelSU: Samsung KDP task-scoped credential install pid=31510 uid=0 euid=0
[  877.285792] KernelSU: ksu su grant: sh(2000) exec /system/bin/sh (cred+real, persistent)
[  877.287248] KernelSU: Samsung KDP task-scoped credential install pid=31511 uid=0 euid=0
```

Reproduce: `adb shell su -c 'dmesg | grep -i kernelsu'` (or pull `dmesg` immediately after the run).

---

## 3. Observed failure events

**O15 — Reboots.** Each post-reboot capture contains the same literal pair plus a short uptime, e.g.:

```
=== estado ===
2000
5.4.274-qgki-30957850-abG998USQSJHZB1
 12:45:08 up 2 min,  0 users,  load average: 11.35, 6.19, 2.43
reboot
reboot
```

Two other captures show `14:05:13 up 4 min, 0 users, load average: 11.43, 6.66, 2.68` and `13:43:04 up 2 min, 0 users, load average: 18.55, 6.40, 2.30`, each followed by the same `reboot` / `reboot` pair.

**O16 — Markers and collector absent after failures**, exact lines:

```
ls: /data/local/tmp/dfroot-captura: No such file or directory
ls: /dev/df: No such file or directory
ls: /dev/dfm0: No such file or directory
ls: /dev/dfm5: No such file or directory
ls: /dev/dfm6: No such file or directory
ls: /dev/dfme2: No such file or directory
```

App-side logs were likewise missing: `cat: files/dfroot-native.log: No such file or directory`, `cat: files/dfroot-ui.log: No such file or directory`, `cat: files/dfroot-last-run.json: No such file or directory`.

**O17 — No readable panic evidence**, exact lines:

```
ls: /sys/fs/pstore: Permission denied
cat: /sys/fs/pstore/console-ramoops-*: No such file or directory
cat: /proc/last_kmsg: Permission denied
cat: /proc/sys/kernel/tainted: Permission denied
```

**O18 — Instrumented run cut at the hook.** The host-relayed log contains, in order:

```
11-21 14:00:02.865 20109 20133 I dfroot  : === init ===
11-21 14:00:02.869 20109 20133 I dfroot  : Triggering hook...
```

and then no further lines from that process. The post-run analysis records `FIN del logcat` at ~14:00:02.88 and device start ~14:01:13, and explicitly lists the absent strings: `libc++: loading custom module`, `kernel module: launching bootstrap`, `ksud`, `bootstrap:`, `=== cleanup ===`, `=== exploit success ===`.

**O19 — Boot reason recorded in the post-run notes:** `bootreason=reboot` (the same notes record `/sys/fs/pstore` and `dmesg` as `Permission denied` from the shell). Reproduce: `adb shell getprop | grep -i bootreason`.

**O20 — Diagnostic-module parameter rejections** in the pulled kernel log, exact lines:

```
[  877.348520] glprobe: `ffffffc01040019c' invalid for parameter `p_futex_wait_requeue_pi'
[  877.348529] glprobe: `ffffffc0103fce48' invalid for parameter `p_do_futex'
[  877.348533] glprobe: `ffffffc01040071c' invalid for parameter `p_arm64_sys_futex'
```

plus equivalent rejections for the socket- and select-family parameters.

**O21 — Safeplace denial** in the earlier pulled kernel log, exact line:

```
[  701.166514] [DEFEX] Safeplace violation [task=timeout (/system/bin/toybox), child=/system/system_ext/bin/ksud, uid=0]
```

(two more identical lines follow at `701.226151` and `701.251573`).

**O22 — Upstream loaders failed cleanly, without reboot.** Literal app output:

```
* app version: 4.7
* manufacturer: samsung
* model: SM-G998U
* android version: 15
* security patch: 2026-01-01
* kernel version: 5.4.274-qgki-30957850-abG998USQSJHZB1
...
Unsupported kernel 5.4 android 11
patch: ERROR - failed to patch files
```

The other loader produced `Device not auto-detected`, no engine log lines, no `/dev/df*` markers, and `su: inaccessible or not found`. The comparison notes state `No hubo reboot` and `Sin root. Sin reboot en esta ronda.`

---

## 4. Observed build / verification results

All items in this section are from read-only offline verification; the notes state `Solo lectura; SIN device` and `NO se usó device`.

**O23 — SHA-256 of three rebuilt artifacts** (verified with `sha256sum <artifact>`):

| Artifact (generic) | sha256 |
|---|---|
| Rebuilt KernelSU LKM | `e6ad6fec4c59ab94ccdc522fbc5d5c703552f92775b04d91efcb697191bf3d87` |
| Rebuilt loader APK | `5991c8bf93fac05b0add544aaf17bec197fc4253bec1eb3dae1a8e7fa6a5660b` |
| Manager APK | `b4a059ace71de2fa65cc7f12b1c58d55fc23ab25e057ee4230ce779742abe450` |

**O24 — Module metadata** (`readelf -p .modinfo <lkm>` / `strings <lkm>`), exact values:

```
vermagic=5.4.274-qgki-30957850-abG998USQSJHZB1 SMP preempt mod_unload modversions aarch64
```

Also present: `KernelSU: welcome to KernelSU version 32601` (manager package name omitted deliberately) and `KernelSU: patch_text disabled for this Samsung target: dst=0x%lx len=%zu`. An older certificate hash string is reported as present; a different one is reported as `ausente (sin coincidencias)`.

**O25 — Symbol coherence.** `readelf -s <lkm>` versus the live kernel-symbol capture: **175 SHN_ABS symbols, 175/175 addresses matched exactly (address + name), 0 discrepancies**. Examples quoted: `commit_creds=ffffffc0105078c8`, `_text=ffffffc010258000`.

**O26 — Signature coherence.** `apksigner verify -v --print-certs <manager-apk>` returned `v2=true` with `v1/v3/v3.1/v4=false` and:

```
Signer #1 certificate SHA-256 digest: c371061b19d8c7d7d6133c6a9bafe198fa944e50c1b31c9d8daa8d7f1fc2d2d6
```

The `EXPECTED_HASH` compiled into the LKM is the same value; the verification notes mark this `MATCH`.

**O27 — CRC table.** `readelf -x __versions <lkm>`: **154 entries, 9856 B**, byte-identical to the original module (`cmp` → idénticos), including `module_layout` CRC `0xd7250e17`.

**O28 — Other measured hashes and counts from the verification notes:**

- Built-in kernel module: `67ee9e18f1d4d131d34e16c11e40bc307ea9e6e312abd202814072474368a720`, 284920 B, `ET_REL aarch64`.
- DirtyFrag 5.4 LKM: prefix `cc9911ea…`, 16888 B, **7/7 CRCs** (includes the `selinux_enforcing` fix).
- KernelSU LKM chosen for the upstream path: prefix `bbe0ff47…`, 285312 B, **154/154 CRCs**.
- Other KernelSU build: prefix `56261d4a…`, 505072 B, **139 CRCs**.
- Diagnostic probes: 304440 B / 27 CRCs, 219456 B / 7 CRCs, 206336 B / 5 CRCs.
- Inventory totals: 156 modules, 42 unique SHA-256 values, 34 with the exact vermagic string from O24.
- Downloaded loaders: `9e193ffdaada8577e14a04fb19403256b3fa4991fae1331c7956e083c098a7b1` (84071 B) and `f00a1ad6d1e8aa9acd2360a2f84e9db66ca84a0ab13102384f72da8f5db348bc` (156697894 B), published = obtained.
- Archive check recorded as passing: `sha256sum -c SHA256SUMS.txt` over 8 files; a signed release APK is recorded with sha256 `036a16035cf0e8e11dd513d6c8729892252a165583ca258dd15531c40aac6540`, and a relay APK with `f7fa63e299c35f5663c67b4cc1298c21d5c2b1d951f76951ba1736f284b442c8` (314433 B).

---

## 5. Inference-only claims (label as hypotheses in the publication)

- **I1 — Cause of the reboots.** The reconciled conclusion says `dfroot` patches `task_defex_*` entries that the manager module has already patched, and does so with a three-word stub that overwrites the PAC/BTI preamble without preserving it → fatal exception/panic in milliseconds → watchdog or ~70 s boot. Confidence recorded as **MEDIA**: high that the fault is in the text patch, low that RKP is the mechanism. This is reasoning, not a measurement.
- **I2 — CFI ruled out.** Based on CFI-shadow type hashing being address-indexed and on the absence of `.cfi_jt` for the four patched functions. No CFI panic line was captured; the exclusion is an argument from source and kallsyms, not an observed event.
- **I3 — RKP mechanism.** An initial "high confidence RKP blocked the write" assessment was explicitly downgraded to **BAJA** after noting that the manager module detects RKP and still patches kernel text successfully on this device.
- **I4 — UMH as cause.** `UMH_WAIT_EXEC` was assessed as not explaining this reboot (a denied exec wakes the waiter with `-EACCES`); the suggested switch to `UMH_NO_WAIT` is a recommendation, not a measured fix.
- **I5 — Stop-machine vs panic.** With no readable kmsg/pstore from the failed boot, the notes state it is impossible to distinguish "immediate panic + ~70 s encrypted boot" from "stop_machine freeze + ~70 s watchdog".
- **I6 — KASLR validity.** The 175 prelinked addresses are asserted valid only for the boot that produced the kernel-symbol snapshot; no uptime, boot_id or `/proc` was available offline, and the notes explicitly say device reachability at capture time `no se puede demostrar`. This is an open risk, not an observation.
- **I7 — Loader verdict.** "Upstream loaders fail cleanly because 5.4 is unsupported, and the hand-built 5.4 module is what caused the reboots" is the conclusion drawn from O22 and O15–O18 — a causal attribution, not a direct measurement.
- **I8 — DEFEX helper context.** The idea that a usermode-helper child with `mm == NULL` is allowed by DEFEX is explicitly marked `por confirmar en dmesg`; O21 shows a Safeplace denial for a different exec path.
- **I9 — Residual delivery risks.** Possible manager rejection of the home-built module, RKP blocking hooks, and a sepolicy-injection stub are listed as risks in the working notes; none was observed.
- **I10 — Second-hand history.** Notes state an earlier chain reached `uid=0` with marker `dfm6` and that later breakage was module/daemon/manager generation mismatch, not the exploit. No raw log line for that session is retained among the evidence artifacts, so treat it as a reported claim.

---

## 6. What is *not* claimed

No observation here proves that the reboots have a specific root cause (I1–I5 remain hypotheses), that the prelinked addresses match the current boot (I6), or that a clean run produces full root from an untrusted-app context. Offline hash/CRC/vermagic checks establish integrity of the artifacts only, not device acceptance. No IP address, port, credential, private repository name, or personal username is reproduced in this report.
