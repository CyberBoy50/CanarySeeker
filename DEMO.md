# CanarySeeker — Demo

Real runs on the lab binaries, 25 November 2026. Every binary was
compiled in this repo from `test_bins/test_prog.c` with gcc 13.3.0
(the PE fixtures were written by `build_test_pe.py`).

## 1. The fully-hardened binary — 100/100, grade A

```bash
python run.py check test_bins/hardened
```

```
 Verdict table — hardened
──────────────────────────────────────────────────────────
 [Present ] [CC-001] RELRO
      GNU_RELRO present + bind-now (DF_BIND_NOW in DT_FLAGS) — Full RELRO.
 [Present ] [CC-002] Stack canary
      Symbol __stack_chk_fail found in .symtab.
 [Present ] [CC-003] NX
      GNU_STACK segment present without the execute flag (RW) — the stack is not executable.
 [Present ] [CC-004] PIE
      File type ET_DYN — position-independent executable.
 [Present ] [CC-005] FORTIFY
      1 fortified function(s): __strcpy_chk. Fortify score 100% (1 fortified, 0 still plain).
 [Present ] [CC-006] RPATH / RUNPATH
      No DT_RPATH or DT_RUNPATH in the dynamic section.
──────────────────────────────────────────────────────────
 Hardening score       : 100/100 (grade A)
 Findings              : 0 (none)
──────────────────────────────────────────────────────────
 Findings (0: 0 high, 0 medium, 0 low)
──────────────────────────────────────────────────────────
 [+] No findings at this severity — every applicable mitigation is present.
 [+] Report saved: canaryseeker_report.txt
```

Exit code 0. This is the binary every other one is compared
against: it was compiled with `-fstack-protector-all -pie -fPIE
-Wl,-z,relro,-z,now -Wl,-z,noexecstack -O2 -D_FORTIFY_SOURCE=2`.

## 2. The unhardened binary — 10/100, grade F

```bash
python run.py check test_bins/unhardened
```

```
 Verdict table — unhardened
──────────────────────────────────────────────────────────
 [Missing ] [CC-001] RELRO
      No GNU_RELRO segment — the GOT is fully writable.
 [Missing ] [CC-002] Stack canary
      No __stack_chk_fail symbol in .symtab — the binary was not compiled with stack protection.
 [Missing ] [CC-003] NX
      GNU_STACK segment has the execute flag (RWE) — the stack is executable.
 [Missing ] [CC-004] PIE
      File type ET_EXEC — the binary loads at a fixed address.
 [Missing ] [CC-005] FORTIFY
      No *_chk symbols — no fortified functions. 2 fortifiable function(s) used plainly: memcpy, strcpy.
 [Present ] [CC-006] RPATH / RUNPATH
      No DT_RPATH or DT_RUNPATH in the dynamic section.
──────────────────────────────────────────────────────────
 Hardening score       : 10/100 (grade F)
 Findings              : 5 (3 high, 1 medium, 1 low)
──────────────────────────────────────────────────────────
 Findings (5: 3 high, 1 medium, 1 low)
──────────────────────────────────────────────────────────
 [HIGH] [CC-001] RELRO: Missing
      Evidence: No GNU_RELRO segment — the GOT is fully writable.
      Fix: Link with -Wl,-z,relro,-z,now for Full RELRO.
 [HIGH] [CC-002] Stack canary: Missing
      Evidence: No __stack_chk_fail symbol in .symtab — the binary was not compiled with stack protection.
      Fix: Compile with -fstack-protector-strong (or -all).
 [HIGH] [CC-003] NX: Missing
      Evidence: GNU_STACK segment has the execute flag (RWE) — the stack is executable.
      Fix: Link with -Wl,-z,noexecstack.
 [MED] [CC-004] PIE: Missing
      Evidence: File type ET_EXEC — the binary loads at a fixed address.
      Fix: Compile and link with -pie -fPIE.
 [LOW] [CC-005] FORTIFY: Missing
      Evidence: No *_chk symbols — no fortified functions. 2 fortifiable function(s) used plainly: memcpy, strcpy.
      Fix: Compile with -O2 -D_FORTIFY_SOURCE=2.
 [+] Report saved: canaryseeker_report.txt
```

Exit code 1. Compiled with `-fno-stack-protector -no-pie
-Wl,-z,norelro -Wl,-z,execstack -O0 -U_FORTIFY_SOURCE`. Every
missing mitigation is a finding with a fix — that is the point of
the table: it does not just say "bad", it says what to change.

## 3. Partial RELRO — the interesting middle case

`partial_relro` is hardened in every way except one: it was linked
with `-Wl,-z,relro,-z,lazy` (lazy binding). The verdict is
**Partial**, not Missing:

```
 [Partial ] [CC-001] RELRO
      GNU_RELRO present but no bind-now flag — the GOT is read-only after relocation except .got.plt, which stays writable for lazy binding.
```

Score 90/100, grade A, exit 1. The lesson is in section 6.

## 4. PE fixtures — the same table, Windows flags

```bash
python run.py check test_pe/pe64_hardened.exe
python run.py check test_pe/pe64_unhardened.exe
```

`pe64_hardened.exe` — 100/100, grade A, exit 0:

```
 [Present ] [CC-007] PE ASLR
      DYNAMIC_BASE set + HIGH_ENTROPY_VA; .reloc section present.
 [Present ] [CC-008] PE DEP / NX
      NX_COMPAT set — data execution prevention is on.
 [Present ] [CC-009] PE CFG
      GUARD_CF set and load-config GuardCFCheckFunctionPointer is 0x6000.
 [n/a     ] [CC-010] PE SafeSEH
      64-bit PE — SafeSEH is a 32-bit concept (x64 uses table-based exception handling).
 [Present ] [CC-011] PE GS cookie
      Load-config SecurityCookie is 0x12345678 — stack cookies are in use.
 [Present ] [CC-012] PE Force Integrity
      FORCE_INTEGRITY set — the image must be signed to load.
 [Present ] [CC-013] PE isolation
      RT_MANIFEST resource present — the binary carries its own activation manifest.
```

`pe64_unhardened.exe` — 5/100, grade F, exit 1: ASLR Missing,
DEP Missing, CFG Missing, SafeSEH n/a, GS Missing, Force Integrity
Missing, isolation Missing.

The edge cases: `pe64_no_reloc.exe` has DYNAMIC_BASE set but no
`.reloc` section, so ASLR is reported Present with the note that it
is ineffective (the image cannot actually be rebased);
`pe32_partial_cfg.exe` has GUARD_CF set but a zero check-function
pointer, so CFG is Partial.

## 5. Batch mode — the whole test folder at once

```bash
python run.py check test_bins/
```

```
 Batch summary (16 binaries, 2 skipped)
  File                         Fmt  Score   Grade  Missing
──────────────────────────────────────────────────────────
  elf32_be                     ELF  100     A      0
  elf32_le                     ELF  90      A      1
  hardened                     ELF  100     A      0
  libtest.so                   ELF  100     A      0
  no_canary                    ELF  75      C      1
  no_fortify                   ELF  95      A      1
  no_nx                        ELF  75      C      1
  no_pie                       ELF  90      A      1
  partial_relro                ELF  90      A      1
  rpath                        ELF  90      A      1
  runpath                      ELF  90      A      1
  static                       ELF  90      A      1
  static_pie                   ELF  100     A      0
  stripped                     ELF  100     A      0
  test.o                       ELF  100     A      0
  unhardened                   ELF  10      F      5
──────────────────────────────────────────────────────────
 [!] Skipped test_bins/manifest.json — Not a binary I can check: test_bins/manifest.json is neither ELF nor PE
 [!] Skipped test_bins/test_prog.c — Not a binary I can check: test_bins/test_prog.c is neither ELF nor PE
 Worst                        : unhardened (10/100, grade F)
 Best                         : elf32_be (100/100, grade A)
```

The two skipped files are the manifest and the C source that live
in the same folder — they are not binaries, so the batch reports
them as skipped instead of crashing on them.

One report file holds every binary's verdict table, and the
summary ranks them — the worst binary is the one to fix first.

## 6. One mitigation, explained — why RELRO plus bind-now matters

**The finding:** `partial_relro` has a GNU_RELRO segment, so a
quick look says "RELRO is on". It is not, fully. RELRO works in
two steps, and the binary only took the first:

1. **GNU_RELRO** marks a part of the binary read-only *after* the
   dynamic linker finishes relocating it. That covers most of the
   GOT (Global Offset Table) — the table of addresses the binary
   jumps through to call library functions.
2. **Bind-now** (`-z now`, the `DF_BIND_NOW` / `DF_1_NOW` flag)
   makes the linker resolve *every* GOT entry at load time, so the
   whole GOT — including `.got.plt` — can be marked read-only.
   Without it, `.got.plt` stays writable because lazy binding
   still needs to fill it in on the first call to each function.

**What partial RELRO leaves open:** GOT overwrite. If an attacker
gets a write primitive (for example a buffer overflow that lets
them write an arbitrary address), the classic target is a GOT
entry: overwrite `printf`'s GOT entry with the address of
`system`, and the next `printf("...")` call runs `system`
instead. With Full RELRO the GOT is read-only, so that write
fails; with Partial RELRO the `.got.plt` entries are still
writable, so the attack still works — it just has to pick a
lazily-bound function.

**The fix is one linker flag:** `-Wl,-z,relro,-z,now`. That is the
difference between the `hardened` binary (Full RELRO, 100/100)
and the `partial_relro` binary (Partial RELRO, 90/100) — same
source code, same compiler, one flag apart. The tool shows it
because it reads the bind-now flag out of the dynamic section,
not just the segment.

## 7. Sample reports

- `sample_report_hardened.txt` — the hardened binary (0 findings)
- `sample_report_unhardened.txt` — the unhardened binary
  (5 findings, each with evidence and a fix)
- `sample_report_unhardened.json` — the same result as JSON
- `sample_report_batch.txt` — all 16 test binaries in one report
