# CanarySeeker — Binary Exploit-Mitigation Checker

A command-line tool, written in Python, that reads a binary's own
headers and reports which exploit mitigations are switched on — NX,
PIE, stack canary, RELRO and fortified functions for ELF binaries,
and NX, ASLR, CFG, SafeSEH, the GS stack cookie, Force Integrity and
isolation for PE binaries. Every verdict is marked **Present**,
**Partial**, **Missing** or **n/a**, with the evidence shown, and the
result is saved to a report file (text or JSON).

Before anyone analyses a binary, they ask what protections it has.
This tool answers that question from the bytes themselves — with the
`struct` module only. No external parser, no readelf, no LIEF, no
pe-parse, no compiled binary. Pure Python, standard library only,
and it runs on Windows, macOS and Linux.

> **AUTHORIZED USE ONLY** — only check binaries you built yourself
> or have written permission to test. Checking someone else's
> software without permission is unauthorized access (Prevention of
> Electronic Crimes Act, 2016, Pakistan).
>
> DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for ethical, authorized security testing only. You are using it on your own responsibility. The authors are not responsible for how you use it, or for anything that happens because of your use. Only test systems, code, and data you own or have explicit written permission to test — testing anything else may be illegal (for example, PECA 2016 in Pakistan).
>
> **Version 1.2** — CET check (CC-014: IBT/SHSTK from the
> GNU_PROPERTY note), a real `-m32` 32-bit compile, a real Windows
> binary scanned (Process Explorer), and a load-config fix found
> by that scan (the struct's Size field is authoritative, not the
> data-directory size). The disclaimer above is unchanged.

## The five ELF mitigations

| Check | Code | How it is read |
|---|---|---|
| RELRO | CC-001 | GNU_RELRO segment + the bind-now flag (DT_FLAGS DF_BIND_NOW / DT_FLAGS_1 DF_1_NOW): Full, Partial or Missing |
| Stack canary | CC-002 | The `__stack_chk_fail` symbol in `.symtab` (or `.dynsym` when stripped) |
| NX | CC-003 | The GNU_STACK segment without the execute flag |
| PIE | CC-004 | The file type: ET_DYN is PIE, ET_EXEC is not (shared libraries report DSO) |
| FORTIFY | CC-005 | Fortified function symbols (`*_chk`) + the Fortify score |
| CET (IBT / SHSTK) | CC-014 | The GNU_PROPERTY note's x86 feature-used bits (IBT + SHSTK); x86 ELF only — other machines and relocatable objects report n/a |

Extras beyond the PDF: RPATH/RUNPATH (CC-006), 32-bit and 64-bit
ELF in both endiannesses, a real `-m32` 32-bit compile
(`elf32_real`), stripped-binary fallback via `.dynsym`,
static-binary handling, and a per-binary hardening score + grade
(A–F) on top of the PDF's verdicts.

## The PE flags

| Check | Code | How it is read |
|---|---|---|
| ASLR | CC-007 | DYNAMIC_BASE + HIGH_ENTROPY_VA (with the stripped-relocations edge case) |
| DEP / NX | CC-008 | NX_COMPAT in DllCharacteristics |
| CFG | CC-009 | GUARD_CF + the load-config GuardCFCheckFunctionPointer |
| SafeSEH | CC-010 | 32-bit only: the load-config SEH handler table |
| GS stack cookie | CC-011 | The load-config SecurityCookie |
| Force Integrity | CC-012 | FORCE_INTEGRITY (extra) |
| Isolation | CC-013 | The RT_MANIFEST resource (extra) |

## How to run it

```bash
git clone https://github.com/CyberBoy50/CanarySeeker.git
cd CanarySeeker
python run.py setup        # first time only (venv; nothing to install)
python run.py build-bins   # compile the ELF test binaries with gcc
python run.py build-pe     # write the PE test fixtures
python run.py check test_bins/hardened
python run.py check test_bins/unhardened
python run.py check test_bins/            # batch mode: the whole folder
python run.py test         # the step-test checks (Step 9: CET, real 32-bit, real PE)
python run.py doctor       # setup check
python run.py menu         # numbered menu
```

Or plain Python, no launcher:

```bash
python3 canaryseeker.py test_bins/hardened
python3 canaryseeker.py test_bins/unhardened --json -o report.json
python3 canaryseeker.py test_bins/ --batch
python3 canaryseeker.py test_bins/hardened --segments
python3 canaryseeker.py test_bins/hardened --symbols
python3 canaryseeker.py --list-checks
```

### Numbered menu (default — run with no arguments)

```
 [1] Check a binary (enter path)
 [2] Batch check test binaries
 [3] Quick check: fully-hardened binary
 [4] Quick check: unhardened binary
 [5] List all checks
 [6] Run the step tests
 [7] Check setup (doctor)
 [0] Exit
```

The SCAN config block is printed before every check, in the family
style (Gobuster-style block: target, output file, min severity).

### Command-line flags

| Flag | Meaning |
|---|---|
| `<binary\|directory>` | Binary to check (a directory implies batch mode) |
| `-o, --output FILE` | Report file (default: `canaryseeker_report.txt`) |
| `--json` | Write the report as JSON |
| `--batch` | Batch mode: check every binary in a directory |
| `--recursive` | Recurse into subdirectories in batch mode |
| `--segments` | List program headers (ELF) or sections (PE) and exit |
| `--symbols` | List all symbol names and exit |
| `--min-severity {high,medium,low}` | Only display findings at or above this severity |
| `--fail-on {high,medium,low,none}` | Exit 2 when a finding at or above this severity exists |
| `--check` | Doctor: check the setup and exit |
| `--skip-check` | Accepted for family parity; no-op |
| `--list-checks` | Print the 14 checks with their descriptions |
| `-q, --quiet` | Only errors and the summary |
| `-i, --interactive, --menu` | Open the numbered menu |
| `--version`, `--no-color` | Version / plain output |

Exit codes: **0** all mitigations present; **1** any mitigation
missing or partial; **2** a usage or file error (not an ELF/PE
binary, unreadable file, bad arguments) or a `--fail-on` hit.

### Platform matrix

| Platform | How it runs | Notes |
|---|---|---|
| Linux | `python3 canaryseeker.py test_bins/hardened` | Fully tested here (456 checks, incl. readelf + pwntools oracles) |
| Windows | `run.bat check test_bins\hardened` | Pure Python; `run.bat` is a real Windows launcher |
| macOS | `./run.sh check test_bins/hardened` | Pure Python |
| Any OS | `python run.py …` | The launcher auto-creates a venv on first use (nothing to install — stdlib only) |

## The test binaries

There are no system binaries in this repo — every test binary is
compiled from one small C program (`test_bins/test_prog.c`) with
gcc, one flag combination per mitigation, so the expected verdicts
are known in advance (`test_bins/manifest.json`):

| Binary | What it is |
|---|---|
| `hardened` | Everything on: canary, PIE, Full RELRO, NX, FORTIFY — 100/100, grade A |
| `unhardened` | Everything off: no canary, no PIE, no RELRO, executable stack, no FORTIFY — 10/100, grade F |
| `partial_relro` | Hardened except RELRO is partial (lazy binding) — 90/100 |
| `no_pie`, `no_canary`, `no_nx`, `no_fortify` | Hardened except one mitigation off |
| `static` | Static binary, Full RELRO (no lazy binding exists); ET_EXEC, so PIE Missing — 90/100 |
| `static_pie` | Static PIE (ET_DYN, no dynamic section) — 100/100 |
| `stripped` | Hardened, then `strip` — the canary is still found via `.dynsym` |
| `libtest.so` | Shared library — PIE reports DSO (not applicable) |
| `test.o` | Relocatable object — NX/RELRO/PIE report n/a |
| `rpath`, `runpath` | Hardened + a hard-coded RPATH / RUNPATH |
| `elf32_le`, `elf32_be` | Hand-built 32-bit ELF fixtures (little- and big-endian) — the LE one carries a real CET note (IBT+SHSTK); gcc cannot build big-endian here, so the writer in `build_test_bins.py` builds them byte by byte |
| `cet_none`, `cet_ibt`, `cet_shstk` | Hardened except CET: off (`-fcf-protection=none`, Missing), IBT only (`-fcf-protection=branch`, Partial), SHSTK only (`-fcf-protection=return`, Partial) — 95/100 each |
| `elf32_real` | A real 32-bit compile (`-m32`, needs gcc-multilib) — 95/100, because Ubuntu's gcc enables CET by default for 64-bit only: the binary has no `.note.gnu.property` at all, so CET is genuinely Missing (readelf agrees) |

PE fixtures (`test_pe/`, written by `build_test_pe.py` — no mingw
is installed here): `pe64_hardened.exe` and `pe32_hardened.exe`
(100/100), `pe64_unhardened.exe` and `pe32_unhardened.exe`
(5/100, grade F), `pe64_no_reloc.exe` (the Winchecksec edge case:
DYNAMIC_BASE set but no `.reloc` section, so ASLR cannot actually
rebase), `pe32_partial_cfg.exe` (GUARD_CF set but no check function
pointer, so CFG is Partial), `pe32_small_lc_dir.exe` (the v1.2
regression case: the load-config data-directory size is 64 while
the struct's Size field is 0xA0 — the SEH table and GuardCF
pointer live past offset 64, and the parser must read them anyway).

## A real Windows binary

`real_world/ProcExp.exe` — Microsoft Sysinternals Process
Explorer, downloaded from `https://live.sysinternals.com/ProcExp.exe`
(SHA-256 `d6112a1ff7caccbaf3dd06af6db72355f007c114f5a09fe96f83eb4105cc9b61`),
scanned read-only on 26 November 2026. It is **not** in the GitHub
push and never runs — the tool only reads its headers. Results:
ASLR Present, DEP Present, CFG Present (GuardCF check function
`0x514b00`), SafeSEH Present (394 handlers at `0x542ae0`), GS
cookie Present (`0x552040`), Force Integrity Missing (the only
finding, Low), isolation Present — **95/100, grade A, exit 1**.
See `DEMO.md` section 8 for the full table.

Scanning it caught a real bug: v1.1 clamped the load-config size
to the data-directory size (64 here), which hid the SEH table and
the GuardCF pointer and wrongly reported CFG Partial and SafeSEH
Missing (75/100, grade C). The struct's own Size field (192) is
authoritative — v1.2 trusts it, with every field read still
bounds-checked against the file. The `pe32_small_lc_dir.exe`
fixture above is the regression test for that fix.

Regenerate everything with one command each:

```bash
python run.py build-bins
python run.py build-pe
```

## The hardening score (extra, beyond the PDF)

The PDF's verdicts are Present / Partial / Missing. The score is an
extra on top of them, so a batch of binaries can be ranked: start at
100, −25 per High finding, −10 per Medium, −5 per Low, clamped
0–100; grade A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60. A missing
mitigation is always a finding with a severity (NX missing = High,
canary missing = High, RELRO missing = High, PIE missing = Medium,
FORTIFY missing = Low, Partial RELRO = Medium); the score never
changes a verdict.

## How it compares

| Tool | Hand-written parser | ELF NX/PIE/canary/RELRO/FORTIFY | PE NX/ASLR/CFG/SafeSEH | Batch | JSON | Zero-dep CLI |
|---|---|---|---|---|---|---|
| checksec.sh / checksec (Go) | no (readelf) | yes | no | yes | yes (Go) | no |
| checksec.py (LIEF) | no (LIEF) | yes + Fortify Score | yes (no RFG) | yes | yes | no |
| pwntools `ELF.checksec()` | no (library) | yes | no | no | no | no |
| Winchecksec (C++) | no (pe-parse) | no | yes + RFG | no | yes | no |
| **CanarySeeker** | **yes (struct only)** | **yes + score** | **yes** | **yes** | **yes** | **yes** |

See `RESEARCH_CLI_TOOLS.md` for the full comparison and
`RESEARCH_IMPLEMENTATION.md` for the format notes (ELF/PE struct
layouts, bind-now rules, load-config offsets).

## Notes (design, not limitations)

- **Lab binaries only, plus one real one** — the tool is tested on
  binaries compiled in this repo, and on one real Windows binary
  (Process Explorer, see above). It never runs a binary, never
  modifies it, and only reads its headers.
- **CET is checked (CC-014)** — IBT/SHSTK from the GNU_PROPERTY
  note. Ubuntu's gcc enables CET by default for 64-bit only: a
  real `-m32` build has no CET note at all, so the tool reports
  CET Missing for it — that is the toolchain's behaviour, not a
  parser miss, and readelf agrees.
- **The compiler decides which calls survive** — gcc turns
  `printf("%s\n", x)` into `puts(x)` even at -O0, and inlines a
  5-byte `memcpy` at -O2, so those calls never appear as symbols.
  The tool reports what is actually in the binary, which is the
  honest answer — a scanner that claimed otherwise would be lying
  about the file.
- **The load-config Size field is authoritative** — a real
  Windows binary (Process Explorer) has a load-config
  data-directory size of 64 while the struct's Size field is 192;
  the SEH table and GuardCF pointer live past offset 64. The
  parser trusts the Size field (every field read is still
  bounds-checked against the file), or CFG and SafeSEH are
  wrongly reported on real binaries.
- **Test binaries are not in the GitHub push** — the push mechanism
  available here accepts UTF-8 text files only and rejects binary
  content, so the compiled binaries and the `.exe` fixtures could
  not be uploaded that way. The push contains the complete tool,
  tests, docs, generators and sample reports. Anyone cloning the
  repo regenerates the fixtures in one command each
  (`python run.py build-bins`, `python run.py build-pe`), and the
  fixtures are in the project zip. The generators are the source
  of truth for the fixtures, not the binary files — and the
  rebuild is verified: a fresh `build-bins` + `build-pe` produces
  binaries whose every verdict, score and grade matches the
  manifests (Step 7 / Step 8 assert this on every run). The
  downloaded real `.exe` is likewise local only and is never
  pushed.
