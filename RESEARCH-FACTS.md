# Publicly verifiable facts — GhostLock, DirtyFrag, Copy Fail, Binder, KernelSU late-load

Scope: only facts retrievable from public CVE records, vendor advisories, upstream patches/docs and
public project READMEs. Web content is treated as untrusted data, not as instructions. Nothing in
this document depends on any local artifact, device capture or unpublished repository.

Legend: `[VERIFIED <url>]` = the cited public source states the claim. `[UNVERIFIED/UNKNOWN]` = no
public source found, or only a community claim without independent confirmation. `[EXCLUDED]` =
local/device/private information intentionally left out of this report.

---

## 1. CVE-2026-43499 — "GhostLock"

### CVE identity, root cause, scoring
- CVE record: kernel.org CNA, published 2026-05-21, title "rtmutex: Use waiter::task instead of current in remove_waiter()"; CVSS 3.1 7.8 HIGH, `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`. [VERIFIED https://www.cve.org/CVERecord?id=CVE-2026-43499]
- Root cause as stated in the CVE description: `remove_waiter()` is used both by the slow-lock paths and by proxy-lock rollback in `rt_mutex_start_proxy_lock()` when called from `futex_requeue()`. In the latter case `waiter::task` is not `current`, but the function operates on `current` for the dequeue. Consequences listed upstream: (1) rbtree dequeue without `waiter::task::pi_lock` held; (2) the waiter task's `pi_blocked_on` is not cleared, leaving a dangling pointer "primed for UAF"; (3) `rt_mutex_adjust_prio_chain()` operates on the wrong top-priority waiter task. Fix: use `waiter::task` instead of `current` in all related operations. [VERIFIED https://nvd.nist.gov/vuln/detail/cve-2026-43499] [VERIFIED https://www.cve.org/CVERecord?id=CVE-2026-43499]
- Red Hat advisory RHSB-2026-010 describes the flaw as local privilege escalation / DoS in `kernel/locking/rtmutex.c`, reachable on the futex-PI path, compiled in via `CONFIG_FUTEX_PI`, with no runtime switch to disable; kernel update is the only complete remediation. [VERIFIED https://access.redhat.com/security/vulnerabilities/RHSB-2026-010]
- Research write-up "IonStack part II: GhostLock" (Nebula Security, 2026-07-07): 15-year stack UAF, affected window `v2.6.39-rc1` to `v7.1-rc1`, only requirement `CONFIG_FUTEX_PI=y`, no capabilities or user namespaces; the bug leaves a dangling `rt_mutex_waiter` on the waiter's own `FUTEX_WAIT_REQUEUE_PI` stack frame, refined into one constrained pointer write. [VERIFIED https://nebusec.ai/research/ionstack-part-2/] [VERIFIED https://nebusec.ai/buglist/CVE-2026-43499/]
- Public full-chain PoC is in the Nebula Security / CyberMeowfia repository under `IonStack/CVE-2026-43499`; write-ups describe a write into `inet6_protos[IPPROTO_UDP]`, a CPU-entry-area pivot and a `core_pattern`-based root step. [VERIFIED https://tuxcare.com/blog/ghostlock-cve/] [VERIFIED https://nebusec.ai/buglist/CVE-2026-43499/]
- Google kernelCTF reward of $92,337 to VEGA / Nebula Security (2026-06-30). [VERIFIED https://www.securityweek.com/15-year-old-linux-vulnerability-ghostlock-earns-researchers-92k-from-google/] [VERIFIED https://tuxcare.com/blog/ghostlock-cve/]

### Fix commits and fixed versions
- Upstream fix commit `3bfdc63936dd` ("rtmutex: Use waiter::task instead of current in remove_waiter()"), merged in mainline 7.1; reported upstream 2026-04-18/20, backported 2026-05-04. [VERIFIED https://git.kernel.org/linus/3bfdc63936dd4773109b7b8c280c0f3b5ae7d349] [VERIFIED https://tuxcare.com/blog/ghostlock-cve/]
- First fixed point releases listed by public trackers: 5.10.261, 5.15.212, 6.1.175, 6.6.140, 6.12.86, 6.18.27, 7.0.4; mainline >= 7.1. Anything in the 2.6.39–7.0 window without a backport is treated as vulnerable. [VERIFIED https://kimmo.cloud/ghostlock/] [VERIFIED https://nvd.nist.gov/vuln/detail/cve-2026-43499]
- NVD CPE ranges list affected branches starting at 2.6.39 (e.g. up to 6.1.175, 6.2–6.6.140, 6.7–6.12.86, 6.13–6.18.27, 6.19–7.0.4); no 5.4 fixed release appears in these public fixed-version lists. [VERIFIED https://nvd.nist.gov/vuln/detail/cve-2026-43499] [VERIFIED https://kimmo.cloud/ghostlock/]
- Distribution examples: Ubuntu 26.04 LTS fixed in 7.0.0-27.27; Debian fixed in 6.1.176-1 / 6.12.86-1 / 7.0.4-1 etc.; AlmaLinux 8/9/10 fixed in `kernel-4.18.0-553.141.2.el8_10`, `kernel-5.14.0-687.24.1.el9_8`, `kernel-6.12.0-211.32.1.el10_2`. [VERIFIED https://www.itsc.cuhk.edu.hk/all-it/information-security/information-security-alerts/linux-kernel-local-privilege-escalation-vulnerability-ghostlock-cve-2026-43499/] [VERIFIED https://almalinux.org/blog/2026-07-09-ghostlock/]

### Official Android app and supported kernels
- The upstream Android app is `YuKongA/ghostlock-app`: "GhostLock uses CVE-2026-43499 to gain temporary root on supported Android kernels and load KernelSU"; support requires an exact `uname -r` match. [VERIFIED https://github.com/YuKongA/ghostlock-app/blob/main/README.md]
- Its supported-devices list, sorted ascending by kernel version, starts at `5.10.236-android12-9-...` and then contains 5.15.x, 6.1.x, 6.6.x and 6.12.x builds; no 5.4 entry appears in the retrieved list. [VERIFIED https://github.com/YuKongA/ghostlock-app/blob/main/docs/kernel_profiles/SUPPORTED_DEVICES.md]
- An issue on that repository, discussing 5.4-qgki devices, records the verdict "Kernel 5.4.x is not supported by GhostLock by design. All working profiles are GKI 5.15+ ... the KernelSnitch technique doesn't work on 5.4" (heap hardening on vendor 5.4 kernels). [VERIFIED https://github.com/YuKongA/ghostlock-app/issues/272]
- A public fork states support by kernel family `5.10 · 5.15 · 6.1 · 6.6 · 6.12`, with "kernels outside these families have no derivation template and are currently out of scope", and reports measured success on those families. [VERIFIED https://github.com/HDILP/robust-ghostlock-app]
- A separate fork's README claims the affected range starts at 5.7 (vs. 2.6.39 in the CVE record); this discrepancy exists between public sources and is not resolved here. [VERIFIED https://github.com/JoinChang/ghostlock-oneplus] [VERIFIED https://nvd.nist.gov/vuln/detail/cve-2026-43499]

### Known public 5.4 ports and their status
- `gitchw/ghostlock-cve-2026-43499`: ARM32 (armv7l), Huawei Watch 4 Pro, kernel 5.4.210; README explicitly states KASLR disabled, no PAN/SMAP, no PXN (stack/BSS executable), no CFI/PAC; exploit uses a 15-byte `prctl(PR_SET_NAME)` stack spray, ARM shellcode on the executable kernel stack and `commit_creds`. Its documented prerequisites are absent on a stock ARM64 kernel with KASLR, PXN and CFI; no public source verifies this port working on such a kernel. [VERIFIED https://github.com/gitchw/ghostlock-cve-2026-43499] [UNVERIFIED/UNKNOWN for ARM64/CFI portability]
- `R0rt1z2/GhostLock`: temporary root for an Amazon Fire TV Stick 4K Max on 4.14 kernels, adapted from the CyberMeowfia exploit; cites the ARM32 repo above as a reference. [VERIFIED https://github.com/R0rt1z2/GhostLock]
- `JoinChang/ghostlock-oneplus`: locked-bootloader Android; UMH/ashmem route requiring "C ashmem" with a static miscdevice in BSS; README names OnePlus 13, OPPO Pad 4 Pro and 5.10/6.1 C-ashmem devices. [VERIFIED https://github.com/JoinChang/ghostlock-oneplus]
- `k-o-n-t-o-r/ghostlock-sm-g990b`: a public repo claiming a Samsung Galaxy S21 FE 5G (`SM-G990B`, `r9q`) build on kernel `5.4.289-qgki-...` reaches a uid-0 daemon and SELinux permissive with no persistence, over two clean boots; it describes tracefs KASLR leak, `mm_struct` slab leak, `pselect6` stack hold, `rb_erase` redirecting ashmem fops, configfs R/W and a CFI-jump-table UMH call. These are README claims; this report did not reproduce them independently. [VERIFIED https://github.com/k-o-n-t-o-r/ghostlock-sm-g990b/blob/master/README.md] [VERIFIED https://github.com/k-o-n-t-o-r/ghostlock-sm-g990b/blob/master/docs/TECHNICAL.md]
- `NghiaMaster/ghostlock_5.4_xperia` origin README documents an Honor 80 GT port on 5.10.168–5.10.236 MagicOS builds, with several builds marked verified and others not verified on real hardware; the 5.4 string is in the repository name, not in the documented verified kernel table. [VERIFIED https://github.com/NghiaMaster/ghostlock_5.4_xperia/blob/main/README_origin.md]
- Third-party tracker: GhostLock status "possibly vulnerable; app doesn't work on 5.4 by design" on 5.4-qgki devices. [VERIFIED https://github.com/HirokiAkihiko/dirtyfrag-research]

---

## 2. CVE-2026-43284 / CVE-2026-43500 — "Dirty Frag"

### CVEs, affected range, mechanism, fixes
- CVE-2026-43284 (xfrm/ESP variant): `xfrm: esp: avoid in-place decrypt on shared skb frags`. `MSG_SPLICE_PAGES` can attach pipe pages directly to an skb; TCP marks such skbs `SKBFL_SHARED_FRAG`, but the IPv4/IPv6 datagram append paths did not, so an ESP-in-UDP packet built from shared pipe pages looks like an ordinary uncloned nonlinear skb and ESP input takes the no-COW fast path, decrypting in place over pages the skb does not own. Fix: set `SKBFL_SHARED_FRAG` in the datagram splice paths and make ESP input fall back to `skb_cow_data()` when the flag is present. [VERIFIED https://nvd.nist.gov/vuln/detail/cve-2026-43284]
- NVD CPE ranges: 4.11–5.10.255, 5.12–5.15.205, 5.16–6.1.171, 6.2–6.6.138, 6.7–6.12.87, 6.13–6.18.28, 7.0–7.0.5; fixed releases 5.10.255, 5.15.205, 6.1.171, 6.6.138, 6.12.87, 6.18.28, 7.0.5. Formally, 5.4 falls inside the 4.11–5.10.255 range. [VERIFIED https://nvd.nist.gov/vuln/detail/cve-2026-43284] [VERIFIED https://www.wiz.io/vulnerability-database/cve/cve-2026-43284]
- Fix commit: mainline `f4c50a4034e62ab75f1d5cdd191dd5f9c77fdff4` (netdev 7 May 2026, mainline 8 May 2026); NVD also points to stable commit `52646cbd00e765a6db9c3afe9535f26218276034`. [VERIFIED https://tryhackme.com/room/cve202643284] [VERIFIED https://nvd.nist.gov/vuln/detail/cve-2026-43284]
- CVE-2026-43500 (RxRPC variant): "rxrpc: Also unshare DATA/RESPONSE packets when paged frags are present"; the DATA/RESPONSE handlers linearise only when `skb_cloned()`, so an uncloned skb carrying externally owned paged frags (`SKBFL_SHARED_FRAG` from splice-into-UDP, or a frag list) reaches in-place decryption via `skb_to_sgvec()`. Ubuntu records "introduced by d0d5c0c, fixed by aa54b1d". [VERIFIED https://ubuntu.com/security/CVE-2026-43500] [VERIFIED https://www.tenable.com/cve/CVE-2026-43500]
- Discovery/public PoC: discovered by Hyunwoo Kim (@v4bel); public exploit at `V4bel/dirtyfrag`. The chain pairs the ESP 4-byte store with the RxRPC variant (used to create the namespace) for root; a Metasploit module was added 2026-05-21. [VERIFIED https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/37474] [VERIFIED https://www.tenable.com/blog/dirty-frag-cve-2026-43284-cve-2026-43500-frequently-asked-questions-linux-kernel-lpe] [VERIFIED https://www.wiz.io/vulnerability-database/cve/cve-2026-43284]
- `MSG_SPLICE_PAGES` is an internal `sendmsg()` flag introduced by David Howells' patch series that replaced `->sendpage()`; TCP and UDP support landed for v6.5. [VERIFIED https://lore.kernel.org/lkml/20230627172446.5d42f023@kernel.org/T/] [VERIFIED https://lwn.net/Articles/927682/] [VERIFIED https://lwn.net/Articles/934967/]

### Why public research calls it dead on 5.4
- A public research repo states: DirtyFrag "❌ Dead — Needs MSG_SPLICE_PAGES (kernel 6.5+)"; "the bug exists in 5.4 (code from 4.11), but the exploit requires `MSG_SPLICE_PAGES` UDP support for the page-cache write primitive. This was introduced in kernel 6.5. On 5.4, `splice()` to UDP does a regular copy — no shared page attachment." [VERIFIED https://github.com/HirokiAkihiko/dirtyfrag-research]
- The upstream PoC's issue tracker gives the same root cause: on 6.1, `udp_sendpage()` sets `MSG_SPLICE_PAGES` but `__ip_append_data()` has no handler for it and falls through to the copying path; the zero-copy path that plants a page-cache page as an skb frag only exists from ~6.5, so 6.1 is "not vulnerable" in practice. [VERIFIED https://github.com/V4bel/dirtyfrag/issues/23]
- Public Android ports describe "accidental mitigation, typically seen on kernel 6.1"; their supported-KMI tables start at 5.10 and mark 5.10 as untested in at least one fork. [VERIFIED https://github.com/diabl0w/DFRoot/tree/master] [VERIFIED https://github.com/datfooldive/DFRoot]

### Hardened fork with a custom splicehelper on 5.4
- In the public Android DirtyFrag projects, `splicehelper` is a small userside helper written into `crash_dump64` with the CBC primitive; it bridges `vendor_file` reads (SELinux domain transition) and pipe splices for IV computation. It runs in userspace and leaves the kernel's `MSG_SPLICE_PAGES` handling unchanged. [VERIFIED https://github.com/mitschud/DirtyFrag/blob/master/README.md] [VERIFIED https://github.com/mitschud/DirtyFrag/blob/master/app/src/main/jni/exp.c]
- A custom userspace splicehelper alone does not restore the missing 5.4 kernel fast path. No public source was found documenting a 5.4 kernel fork that backports `MSG_SPLICE_PAGES`/`skb_splice_from_iter()` plus the vulnerable missing `SKBFL_SHARED_FRAG` behaviour and demonstrates a working page-cache write there. [UNVERIFIED/UNKNOWN]

---

## 3. CVE-2026-31431 — "Copy Fail"

- Upstream description: `crypto: algif_aead - Revert to operating out-of-place`; introduced in 4.14 by commit `72548b093ee38a6d4f2a19e6ef1948ae05c181f7`; fixed in 6.18.22 (`fafe0fa2995a0f7073c1c358d7d3145bcc9aedd8`), 6.19.12 (`ce42ee423e58dffa5ec03524054c9d8bfd4f6237`) and 7.0 (`a664bf3d603dc3bdcf9ae47cc21e0daec706d7a5`). [VERIFIED https://www.openwall.com/lists/oss-security/2026/04/29/23]
- Mechanism: AF_ALG socket (family 38, `SOCK_SEQPACKET`) bound to `authencesn(hmac(sha256),cbc(aes))`; pages of a readable file are spliced into the AEAD socket; `authencesn` writes 4 scratch bytes (ESN `seqno_lo`) at `dst[assoclen + cryptlen]`, giving a controlled 4-byte write into the page cache of any readable file. [VERIFIED https://github.com/Sl4cK0TH/CVE-2026-31431-PoC/blob/master/README.md] [VERIFIED https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds]
- Affected range: mainline 4.14–6.18.21, 6.19.0–6.19.11, 7.0-rc1–rc6; 5.4.x and other older LTS lines have no upstream fix listed and need a distribution backport. [VERIFIED https://github.com/xn0kkx/CVE-2026-31431_CopyFail_LinuxKernel_LPE] [VERIFIED https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds]
- Working public PoC: a ~732-byte standalone Python script in the Theori repository (`copy_fail_exp.py`); verified publicly on Ubuntu 24.04, Amazon Linux 2023, RHEL 10.1 and SUSE 16. [VERIFIED https://www.openwall.com/lists/oss-security/2026/04/29/23] [VERIFIED https://github.com/theori-io/copy-fail-CVE-2026-31431] [VERIFIED https://www.sysdig.com/blog/cve-2026-31431-copy-fail-linux-kernel-flaw-lets-local-users-gain-root-in-seconds]
- A community README claims CISA KEV listing; no KEV record was retrieved here. [UNVERIFIED/UNKNOWN]
- Android 5.4 config: `CONFIG_CRYPTO_USER_API_AEAD` (tristate, depends on NET) exists in the Android common kernel 5.4 Kconfig; newer Android Kconfig text labels it deprecated and advises enabling only when needed. Existence of the symbol does not prove it is enabled in any particular vendor defconfig. [VERIFIED https://android.googlesource.com/kernel/common/+/refs/tags/android12-5.4.300_r00/crypto/Kconfig] [VERIFIED https://android.googlesource.com/kernel/gs/+/431907c026fb80a4fc2a482bde3f2d913ef39c37/crypto/Kconfig]
- Whether AF_ALG/`algif_aead` is actually enabled on any specific vendor 5.4.274-qgki build: [UNVERIFIED/UNKNOWN]

---

## 4. Binder CVEs on 5.4-era Android kernels

- CVE-2023-20938: UAF in `binder_transaction_buffer_release` from improper input validation, Android ID A-257685302, published 2023-02-28, local EoP. [VERIFIED https://nvd.nist.gov/vuln/detail/cve-2023-20938]
- Google Android Red Team: the bug affected all Android devices using GKI 5.4 and 5.10; initial fix in the February 2023 bulletin, complete root-cause fix (CVE-2023-21255) in the July 2023 bulletin. [VERIFIED https://androidoffsec.withgoogle.com/posts/attacking-android-binder-analysis-and-exploitation-of-cve-2023-20938/]
- Ubuntu lists it fixed in the 5.4 series at `5.4.0-144.1` (focal). A 5.4 kernel built after those bulletins would normally carry a fix, but a particular vendor's backport status is not publicly established here. [VERIFIED https://ubuntu.com/security/CVE-2023-20938] [UNVERIFIED/UNKNOWN for any specific vendor build]
- CVE-2022-20421 "BadSpin": UAF in `binder_inc_ref_for_node`, Android ID A-239630375, published 2022-10-11, CVSS 7.8; fixed in the October 2022 Android Security Bulletin; public PoC referenced as `0xkol/badspin`. [VERIFIED https://nvd.nist.gov/vuln/detail/cve-2022-20421] [VERIFIED https://source.android.com/docs/security/bulletin/2022-10-01] [VERIFIED https://www.tenable.com/cve/CVE-2022-20421]
- Ubuntu lists BadSpin fixed in the 5.4 series at `5.4.0-136.153`. [VERIFIED https://ubuntu.com/security/CVE-2022-20421]
- Third-party 5.4-qgki research table records BadSpin as "tried, no success — builds OK, loops without winning the race" and CVE-2023-20938 as "vulnerable (both), not yet attempted", on Xiaomi 5.4-qgki devices, not on any Samsung build. [VERIFIED https://github.com/HirokiAkihiko/dirtyfrag-research]

---

## 5. KernelSU LKM / late-load (official docs and upstream sources)

- Official docs list three runtime modes in `KSU_RUNTIME_MODE`: `built-in` (GKI), `lkm` (module at boot), `late-load` (module after boot); module scripts also receive `KSU_UAPI_VER` and `KSU_LATE_LOAD`. [VERIFIED https://kernelsu.org/guide/module.html] [VERIFIED https://github.com/tiann/KernelSU/blob/main/website/docs/guide/module.md?plain=1]
- LKM mode does not replace the device kernel; the stock kernel stays and `ksuinit` loads `kernelsu.ko` before the stock init. [VERIFIED https://kernelsu.org/guide/installation.html] [VERIFIED https://kernelsu.org/guide/module.html]
- `ksud late-load` loads the module after the system is fully booted, detects the current KMI and loads the matching `kernelsu.ko` from embedded assets, then performs the initialization normally done at boot. [VERIFIED https://kernelsu.org/guide/module.html]
- Late-load limitations (official comparison table): no initrc injection, no `preinit`, kprobe hooks for ksud (`execve`/`read`/`fstat`/`input`) skipped, safe-mode detection always disabled, boot log capture skipped, Magisk coexistence check skipped, no `post-fs-data` event reported to kernel, `boot-completed` set directly during init; `KSU_LATE_LOAD=1` and kernel info flag `0x4` are set. `system.prop`, OverlayFS mount, `post-mount.sh`, `service.sh` and `boot-completed.sh` still run. [VERIFIED https://kernelsu.org/guide/module.html] [VERIFIED https://github.com/tiann/KernelSU/blob/bec9c134/website/docs/guide/module.md?plain=1]
- Initrc injection happens extremely early (when init reads `init.rc`) and is unavailable in late-load mode because system-call hooks are not installed. [VERIFIED https://kernelsu.org/guide/module.html]
- Late-load script order: load `.ko` → extract binaries/handle updates/load SELinux rules/init features → `late-load.d/` and module `late-load.sh` (blocking) → `system.prop` → metamodule OverlayFS mount → `post-mount` (blocking) → `service` (non-blocking) → `boot-completed` (non-blocking). [VERIFIED https://kernelsu.org/guide/module.html]
- UAPI matching: `KSU_UAPI_VER` increments on breaking kernel-driver changes; upstream changed the manager to warn and force an LKM update on mismatched UAPI instead of strict version-code equality. `ksud` uses `ensure_uapi_version_matched()` to block module installation and skip post-fs-data/service/boot-completed handling on mismatch. [VERIFIED https://github.com/tiann/KernelSU/pull/3516] [VERIFIED https://github.com/tiann/KernelSU/pull/3406] [VERIFIED https://github.com/KernelSU-Next/KernelSU-Next/commit/111170990801277fe26a0a0716bfd0a5be04130a]
- Soft reboot exists as an emulated manager/ksud feature (`setprop` + zygote; waitsys and service-death handling commits). A public module doc notes that after late-load a soft reboot can replay `post-fs-data.sh`, while restarting only Zygote or `system_server` does not. [VERIFIED https://github.com/tiann/KernelSU/pull/3406] [VERIFIED https://github.com/tiann/KernelSU/pull/3800] [VERIFIED https://modules.kernelsu.org/en/modules/yukizygisk/]
- Kernel-side module signature verification is a generic kernel facility (`CONFIG_MODULE_SIG`, `CONFIG_MODULE_SIG_FORCE`, `scripts/sign-file`); a mismatched signature blocks loading when enforcement is on. [VERIFIED https://docs.kernel.org/admin-guide/module-signing.html]
- The manager APK is verified by a certificate/hash baked into the `.ko`, so manager and LKM must come from the same release; a public community guide documents this, while the official docs consulted here do not. [VERIFIED https://github.com/RamenFast/zenfone9-root/blob/main/KERNELSU.md] [UNVERIFIED/UNKNOWN as an official-doc statement]
- The KernelSU Modules catalog FAQ says catalog module ZIPs are unsigned and no developer identity is verified. That statement covers module ZIPs; it does not cover the manager APK or the `.ko`. [VERIFIED https://developers.kernelsu.org/docs/faq]

---

## EXCLUDED (local, device-specific or private; not public evidence)

- All local backup material, manifests, analysis notes, incident/capture directories, kernel images, symbol/offset tables, per-boot addresses, device ports, device build identifiers, APK/module hashes, build logs and "verified on device" claims: [EXCLUDED] — none of it is publicly retrievable.
- All private/unpublished repositories, private toolchains and unpublished signing keys: [EXCLUDED].
- Claims about specific vendor hardening behaviour (module-signature policy, KDP/RKP/DEFEX behaviour, SELinux state symbol layout) on any particular Samsung build, and any claim that root was or was not obtained there: [UNVERIFIED/UNKNOWN].
- Any conclusion about whether the studied device is exploitable, or a recommendation to attempt exploitation, is deliberately not made in this document.
