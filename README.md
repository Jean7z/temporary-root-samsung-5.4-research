# Temporary root on a locked Samsung Galaxy S21 Ultra (SM-G998U / HZB1): a verified research map

This report collects what was actually verified during an authorized security-research
effort on a personally owned SM-G998U running firmware `G998USQSJHZB1` (Android 15,
kernel `5.4.274-qgki-30957850-abG998USQSJHZB1`). It is written to save other researchers
time: the goal is to separate **publicly verified facts**, **directly observed device
evidence**, and **hypotheses that remain unproven**.

It does **not** provide a working exploit, a ready-to-flash artifact, or instructions to
attack any device. Only test hardware you own or are explicitly authorized to assess.

## Contents

- [1. Device and threat model](#1-device-and-threat-model)
- [2. Publicly verified exploit facts](#2-publicly-verified-exploit-facts)
- [3. Directly observed device evidence](#3-directly-observed-device-evidence)
- [4. Kernel hardening and why it matters](#4-kernel-hardening-and-why-it-matters)
- [5. KernelSU late-load: what the public docs actually say](#5-kernelsu-late-load-what-the-public-docs-actually-say)
- [6. Hypotheses and open questions](#6-hypotheses-and-open-questions)
- [7. Practical lessons for another port](#7-practical-lessons-for-another-port)
- [8. Sources](#8-sources)

The evidence files in this repository are expanded versions of sections 2–5:
`RESEARCH-FACTS.md` (public CVE/repo verification), `HARDENING-FACTS.md` (public docs on
Samsung/kernel hardening) and `DEVICE-EVIDENCE.md` (labelled observed facts vs inferences).

---

## 1. Device and threat model

**Observed directly** (see `DEVICE-EVIDENCE.md`, O1–O4):

- Model `SM-G998U`, board `p3q`, build fingerprint
  `samsung/p3qsqw/p3q:15/AP3A.240905.015.A2/G998USQSJHZB1:user/release-keys`.
- Kernel `5.4.274-qgki-30957850-abG998USQSJHZB1` (verified with `uname -r`).
- Bootloader locked; verified boot untouched; no partition was written during the work.
- Shell user starts as `uid=2000(shell)`; `SELinux` was observed `Permissive` during one
  successful root session, not at every boot.

**Publicly verified** firmware identifiers exist for the HZB1 build family; however the
exact device-specific Kconfig values used here are **not** in the public record and were
only observed through local `IKCONFIG`/`kallsyms` captures (see `HARDENING-FACTS.md`).

---

## 2. Publicly verified exploit facts

Every item in this section is backed by a public source in `RESEARCH-FACTS.md`.

| Topic | Verified conclusion |
|---|---|
| GhostLock / CVE-2026-43499 | Bug is `remove_waiter()` using `current` instead of `waiter->task` on the futex-PI proxy-lock rollback path. Affected range 2.6.39–7.1-rc1; fix commit `3bfdc63936dd`; fixed stable releases begin at 5.10.261. No 5.4 fixed release is listed. |
| Official GhostLock app | Publishes exact `uname -r` profiles starting at 5.10.236; its own documentation states 5.4 is unsupported by design. |
| Public 5.4 GhostLock ports | The widely cited 5.4.210 port is ARM32 on a device without KASLR/PXN/CFI and is not portable to this target. A Samsung S21 FE 5.4.289 repository claims success, but the claim is README-level and not independently verified. |
| DirtyFrag / CVE-2026-43284 + CVE-2026-43500 | NVD formally includes 5.4, but upstream public research marks the exploit path dead before 6.5 because `MSG_SPLICE_PAGES` on UDP is absent. Fix commit `f4c50a4034e6`; fixed branches include 5.10.255. |
| Copy Fail / CVE-2026-31431 | Affects 4.14–6.18.21; fix `a664bf3d603d`; public 732-byte Python PoC. Depends on `algif_aead`/`authencesn`; whether it works on this vendor kernel is **unverified**. |
| CVE-2023-20938 / CVE-2022-20421 | Public record shows Android security-bulletin fixes; no public evidence that they remain live on this 5.4.274 build. |

Important nuance: "DirtyFrag is dead on 5.4" refers to the **upstream PoC path**, which
requires `MSG_SPLICE_PAGES`. Our successful runs used a **hardened downstream variant with
a userspace `crash_dump64` bridge** (`splicehelper`), which is a different engineering
path. No public fork documenting that exact combination was found, so the general claim
and our local result are both reported separately rather than merged.

---

## 3. Directly observed device evidence

Full labelled logs are in `DEVICE-EVIDENCE.md` (O1–O28 are observations, I1–I10 are
inferences). Highlights:

- A successful run produced `uid=0(root) gid=0(root) groups=0(root)` from `su -c id`,
  with `CapEff` and `CapBnd` both `0000003fffffffff`, a live `kernelsu` module in
  `/proc/modules`, and a manager UI showing "Working [LKM]" (translated from the device
  locale). SELinux was `Permissive` in that session.
- Marker nodes such as `/dev/df`, `/dev/dfm0`, `/dev/dfr0`, `/dev/dfINIT` and
  `/dev/dfTP_OK` were observed after successful stages, and their absence correlated with
  failed stages.
- Failed runs ended in reboot with `ro.boot.bootreason=reboot`, no usable pstore, and a
  logcat stream that stopped before the boot. A host-side logcat relay was required
  because device-side capture was killed by process pressure.
- `dmesg` on the device showed `[DEFEX] Safeplace violation` lines for root-executed
  binaries and a module-load error for an incompatible `kernelsu.ko` with unresolved
  symbols (`Unknown symbol ...`).
- Build-side artifacts were verified offline: exact vermagic
  `5.4.274-qgki-30957850-abG998USQSJHZB1 SMP preempt mod_unload modversions aarch64`,
  CRC counts against the prepared `Module.symvers`, `apksigner` certificate digests, and
  SHA-256 values. These are recorded as **offline verification**, not proof of a working
  final device setup.

The log excerpts retain device paths such as `/dev/...` and `/proc/...`; these are
evidence, not private workspace locations. No personal usernames, device IP addresses,
ports or tokens are included.

---

## 4. Kernel hardening and why it matters

Verified from public documentation in `HARDENING-FACTS.md`:

- **RKP** (Samsung Real-time Kernel Protection) and **DEFEX** are documented in Knox
  materials and independent research. RKP enforces read-only kernel text/page tables;
  DEFEX filters execve/setuid/module loading for root contexts.
- **CFI_CLANG** inserts forward-edge indirect-call checks; **CFI_CLANG_SHADOW** adds a
  module lookup table. Violations panic unless `CONFIG_CFI_PERMISSIVE` is set.
- **KASLR** makes absolute symbol addresses boot-specific; `kptr_restrict` controls
  `/proc/kallsyms` visibility. Any prelink that hardcodes addresses is valid only for the
  boot whose kallsyms was used.
- Linux modules check `vermagic` and `MODVERSIONS` CRCs; the `SHN_ABS` symbol trick used by
  several loaders bypasses both by binding undefined symbols to runtime addresses from
  `/proc/kallsyms` before `init_module()`.
- KernelSU verifies the manager's v2 signature against `KSU_EXPECTED_SIZE` and
  `KSU_EXPECTED_HASH`; a mismatched manager/module pair can load a driver but never grant
  usable root.

The exact HZB1 CFI/RKP configuration and manager certificate remain **device-observed
only** and are marked `[UNVERIFIED]` in `HARDENING-FACTS.md`.

---

## 5. KernelSU late-load: what the public docs actually say

Public KernelSU documentation states that in late-load mode:

- The kernel module is loaded after Android has fully booted.
- `initrc` injection, `preinit`, safe-mode detection, boot-log capture and the
  `post-fs-data` kernel event are unavailable or skipped.
- `system.prop`, OverlayFS metamodule mounting, `post-mount`, `service` and
  `boot-completed` stages still run.
- Soft reboot is an emulated userspace reboot, not a kernel reboot, and is a separate
  feature from module loading.
- UAPI mismatch between manager and driver can block installation and stages.

This explains why a "install module, press soft reboot, root stays" flow behaves
differently on a late-loaded, locked device than on a boot-image install.

---

## 6. Hypotheses and open questions

These are **not** presented as conclusions:

- The exact cause of the observed reboots after certain writes remains open (confidence:
  medium that it involved kernel-text patching/CFI or a conflicting patcher; no captured
  oops).
- CFI, RKP and UMH were excluded as *primary* causes in static analysis, but this was not
  proven on-device.
- KASLR validity of any prelinked module is a real hazard; a single reboot invalidates it.
- The `mm == NULL → ALLOW` DEFEX hypothesis was never confirmed in dmesg.
- A historical root result is second-hand and was not reproduced in the final stable state.

See `DEVICE-EVIDENCE.md`, section "Inference-only claims", for the explicit list.

---

## 7. Practical lessons for another port

1. Identify the exact firmware and `uname -r` before touching anything; 5.4 vendor
   kernels differ more than same-version GKI builds.
2. Verify IKCONFIG and `/proc/kallsyms` gates early: `CONFIG_FUTEX_PI`, `CONFIG_INET_ESP`,
   `CONFIG_NETFILTER`, the AEAD/algif configuration, CFI/PAC/RKP/DEFEX, `kptr_restrict`.
3. Do not assume a public "dead on 5.4" verdict applies to hardened downstream forks;
   and do not assume a CVE advisory range means a public exploit exists.
4. Capture logs on the host. Device-side capture is fragile under reboot/process pressure.
5. Keep verified, observed and inferred claims in separate documents or sections.
6. If prelinking a module, regenerate for every boot; treat the resulting `.ko` as
   single-boot and single-device.
7. Manager, module and userspace must share UAPI and signature identity; otherwise the
   driver loads but root is unusable.
8. Late-load modules only run their stages once at load time; installing a module later
   and pressing soft reboot does not recreate the overlay.
9. Avoid kernel-text patching on Samsung RKP/CFI targets unless the vendor-safe path is
   proven; conflicting patchers were implicated in prior failures.
10. Stop after an unexplained reboot: repeating the same write without new evidence is
    how devices get bricked or evidence gets lost.

---

## 8. Sources

See `RESEARCH-FACTS.md` and `HARDENING-FACTS.md` for per-claim URLs. Key primary sources:

- CVE records: CVE-2026-43499, CVE-2026-43284, CVE-2026-43500, CVE-2026-31431,
  CVE-2023-20938, CVE-2022-20421.
- Linux kernel documentation on CFI, modules, `kptr_restrict`, `kallsyms`.
- KernelSU official documentation and source (`tiann/KernelSU`).
- Samsung Knox / independent academic and conference research on RKP, KDP and DEFEX.
- Public project READMEs for GhostLock and DirtyFrag ports; community claims are labelled
  as such and are not treated as independently verified.

No license-protected code is reproduced here. Third-party repositories retain their own
license terms; where known, they are noted in the expanded facts files.
