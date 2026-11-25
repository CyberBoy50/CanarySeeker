# CanarySeeker — Research: Similar Tools on the Internet / GitHub

Researched Wed 2026-11-25, before building. Sources are the web searches run
that day; claims below come only from those results and the tools' own pages.

## Name check (GitHub, search_repositories, `in:name`)

The PDF's name **CanaryCheck is TAKEN** (same name, same domain, same words):
- `cyber-site783/canarycheck` — "CanaryCheck — Your Own Binary Exploit-
  Mitigation Checker (ELF)". Somebody has already published this exact tool
  under this exact name. (The other hit, `ir0nstone/CanaryChecker`, fuzzes
  format-string attacks to pinpoint canary bypasses — a different tool.)
- CanaryLens is taken (1 — `rkb32/CanaryLens`, a Kubernetes canary rollout
  controller; different domain, but the name is used). BinGuard is taken (11).

**FREE (0 results): CanarySeeker, MitigationLens, HardeningLens.**

## 1. checksec.sh / checksec (Go) — the standard

- The original checksec.sh (Tobias Klein, Bash, v1.5) verifies which PaX
  security features are enabled in ELF executables: RELRO, stack canary, NX,
  PIE, ASLR, FORTIFY_SOURCE. Commands: `--file`, `--dir`, `--proc`,
  `--proc-all`, `--proc-libs`, `--kernel`, `--fortify-file`, `--fortify-proc`.
- How it checks (from the Infosec write-up): RELRO — `readelf` for a
  GNU_RELRO program header; canary — `readelf -s` for `__stack_chk_fail`;
  NX — `readelf -l`, the GNU_STACK line must NOT contain RWE; PIE — `readelf
  -h`, type EXEC means no PIE, DYN means PIE; RPATH/RUNPATH — the dynamic
  section.
- The current project is a Go rewrite (`slimm609/checksec`, maintained by
  Brian Davis): `checksec file|dir|proc|kernel|fortifyFile|fortifyProc`,
  output table/xml/json/yaml, kernel-config scanning, Clang CFI hints,
  FORTIFY level from annobin metadata, and a per-check value + status
  (green/yellow/red).
- Limits: a shell script (or a Go binary) that shells out to readelf — it
  does not parse the ELF format itself; no Python, no menu, no report file
  in the PDF's sense; the Go version needs a compiled binary.
- What CanarySeeker takes from it: the verdict model (Full/Partial/No RELRO,
  canary found/not found, NX enabled/disabled, PIE/DSO/No PIE) and the exact
  evidence rules. What CanarySeeker does differently: a hand-written
  `struct`-only ELF parser in pure Python (the PDF's whole point), a menu +
  text/JSON reports, and PE support in the same tool.

## 2. checksec.py (cingmanwu/checksec.py, PyPI 0.4.5)

- "Checksec tool in Python, Rich output, based on LIEF." Verifies the
  security properties of binaries on Linux and Windows. Supported formats:
  ELF, PE, Mach-O. Scan a file or a directory (recursively), JSON output.
- ELF checks: RELRO, Canary, NX, PIE, RPATH, RUNPATH, Symbols, Fortify,
  Fortified, Fortifiable, **Fortify Score** (checksec.sh does not have it).
  PE checks: ASLR (DYNAMIC_BASE, HIGHENTROPYVA), INTEGRITYCHECK,
  Authenticode, DEP, Manifest Isolation, SEH, SafeSEH, CFG, Stack Cookie.
  (Return Flow Guard is the one PE check Winchecksec has that checksec.py
  lacks.)
- Limits: depends on LIEF (a compiled C++ parsing library) and Rich — it
  parses through a library, not by hand; the last release was 2020.
- What CanarySeeker takes from it: the combined ELF+PE scope (the PDF's
  stretch item), the directory scan, and the Fortify Score idea. What
  CanarySeeker does differently: zero dependencies — hand-written `struct`
  parsing for both ELF and PE, no LIEF, no Rich.

## 3. pwntools — `ELF.checksec()` (the CTF one-liner)

- The exploit framework every CTF player uses: `python3 -c "from pwn import
  *; print(ELF('./chall').checksec())"` prints Arch / RELRO / Stack / NX /
  PIE / FORTIFY. `checksec --file=./chall` is the first command run against
  any new pwn challenge, and `pwn checksec` is the same check inside the
  framework.
- Limits: a library call inside a large framework (needs pwntools installed);
  it reports the checks, it is not a standalone findings report with a
  menu, batch mode or saved report.
- What CanarySeeker takes from it: the same five checks, and the lesson that
  this output is the first thing any binary analyst wants. Test role:
  pwntools (if installable) is a second oracle next to readelf.

## 4. Winchecksec (Trail of Bits, C++)

- Static detection of Windows security features in PE binaries, built for
  their Sienna Locomotive fuzzing/triaging system. Detects ASLR
  (`/DYNAMICBASE` with the stripped-relocations edge case, `/HIGHENTROPYVA`
  for 64-bit), code integrity (`/INTEGRITYCHECK`, Authenticode — the
  certificate check is unsupported on Linux), DEP/NX, manifest isolation
  (`/ALLOWISOLATION`), SEH and SafeSEH, CFG and Return Flow Guard, and the
  GS stack cookie. Two output modes: plain-text table (default) and JSON
  (`-j`/`--json`). Depends on pe-parse and uthenticode (vcpkg); unit tests
  use pegoat as the reference for the mitigations.
- On a vanilla Windows 10 (1803) install: ASLR 79%, DEP 79%, CFG 49%,
  SafeSEH 25%, GS 65% — a useful sense of how often each flag is actually on.
- Limits: C++ (needs a build), PE only, no directory scan, no ELF.
- What CanarySeeker takes from it: the PE flag set and the exact edge cases
  (DYNAMICBASE with stripped relocations must NOT count as ASLR; SafeSEH is
  a 32-bit-only concept). What CanarySeeker does differently: the same PE
  checks in pure Python `struct` parsing, in the same tool as the ELF checks.

## 5. bin-triage-toolkit (AndC100101100/bin-triage-toolkit)

- Fast, static, offline first-pass triage of ELF binaries for Attack &
  Defense / CTF: one neutral fact-base (`elf_facts`), read by a `pwn` lens,
  a `rev` lens and malware analyzers. Per binary: exploit mitigations (NX,
  PIE, canary, RELRO, FORTIFY, static, stripped), dangerous called functions
  mapped to primitives (`gets`→BOF, `system`→ret2system), heap surface, win/
  backdoor symbols, pwn strings, and a ranked attack-surface score. Uses
  checksec / readelf / nm / objdump when present; hands off to Ghidra,
  radare2, ROPgadget for deep work.
- Limits: a triage framework with optional heavy dependencies (pwntools +
  capstone, YARA, CAPA); scoring is a where-to-look aid, not a verdict.
- What CanarySeeker takes from it: the idea that static/stripped status
  belongs in the report next to the mitigations, and that a per-binary score
  helps rank a batch. What CanarySeeker does differently: the PDF's five
  checks done by hand, in one small tool, with the score as a clearly-marked
  extra (not the verdict).

## 6. Binary Analyzer MCP / qchecksec (QNX)

- Binary Analyzer: an MCP server that parses ELF with pure Python via
  pyelftools and detects NX, PIE, canaries and RELRO, with batch directory
  scans to JSONL and suspicious-symbol prioritisation.
- qchecksec: QNX's utility for ELF hardening properties (RELRO Full/Partial/
  None, canary, PIE incl. the "DSO" and "No ELF exec" cases, NX, RPATH,
  RUNPATH, FORTIFY incl. "unknown"), green/yellow/red verdicts.
- Limits: the first is an MCP server (not a CLI); the second is QNX-only.
  Both parse through a library or a platform tool, not by hand.
- What CanarySeeker takes from them: the DSO / not-applicable verdict cases
  (a shared library is not a PIE failure) and the green/yellow/red model.

## Comparison table

| Tool | Hand-written parser | ELF NX/PIE/canary/RELRO/FORTIFY | PE NX/ASLR/CFG/SafeSEH | Batch dir | JSON | Report file | Zero-dep CLI | Needs build/lib |
|---|---|---|---|---|---|---|---|---|
| checksec.sh / checksec (Go) | no (readelf) | yes | no | yes | yes (Go) | no | no | yes (Go bin) |
| checksec.py | no (LIEF) | yes + Fortify Score | yes (no RFG) | yes | yes | no | no | yes (LIEF) |
| pwntools checksec() | no (lib) | yes | no | no | no | no | no | yes (pwntools) |
| Winchecksec | no (pe-parse) | no | yes + RFG | no | yes | no | no | yes (C++ build) |
| bin-triage-toolkit | partial | yes + score | partial | yes | yes | yes | no | optional |
| **CanarySeeker (planned)** | **yes (struct only)** | **yes + score** | **yes** | **yes** | **yes** | **yes (text+JSON)** | **yes** | **no** |

## What CanarySeeker adds over everything found

1. **Hand-written ELF + PE parsers, zero dependencies** — `struct` only, the
   exact skill the PDF grades. No readelf, no LIEF, no pe-parse, no Go
   binary, no Java. The one tool in the list that reads both formats by hand.
2. **All three stretch items in v1.0** — PE support (Winchecksec-parity
   flags), batch mode (directory + recursive + summary table), JSON report.
3. **Beyond-PDF extras that make it clearly better than a plain AI build:**
   32-bit AND 64-bit ELF (both endiannesses); stripped-binary fallback
   (`.dynsym` when `.symtab` is gone); static-binary handling (no dynamic
   section is a clean verdict, not a crash); RPATH/RUNPATH check (checksec
   parity); fortified-function count + fortifiable list + Fortify score
   (checksec.py parity); a per-binary hardening score + grade (A–F) as an
   extra on top of the PDF's present/partial/missing verdicts; and a test
   matrix built by compiling real C programs with gcc, with readelf (and
   checksec/pwntools if installable) as independent oracles for every
   verdict.
4. **Menu + full CLI + text/JSON reports** — same interface family as
   SSTIProbe / RBACLens / PipeSentry / MemSeeker / APKSeeker.
5. **Cross-platform** — pure Python, runs on Windows, macOS and Linux
   (per the user's standing rule); PE fixtures are built by a Python PE
   writer, so no Windows machine or mingw is needed to test PE support.
6. **Lab-built test binaries** — a generator script compiles the test
   binaries from C source with gcc (every mitigation combination), so the
   repo stays text-only and the fixtures regenerate with one command on any
   machine (binary files cannot be pushed to GitHub with the push-files
   tool — the APKSeeker lesson).
