# CanarySeeker — Research: How to Implement It

Design notes from the research (Wed 2026-11-25). Format facts come from the
ELF specification (`elf.h`), the PE/COFF specification, and the tools' own
docs found in the searches (checksec.sh's readelf rules, Winchecksec's flag
list, checksec.py's PE table).

Environment here: `gcc 13.3.0` and `readelf` are installed; `checksec` is
NOT installed (try `apt install checksec` / pip pwntools in a test venv —
if neither works, readelf is the oracle; say so, do not fake it).

## 1. ELF header (struct only)

- Magic: first 4 bytes must be `\x7fELF`; anything else is a clean error
  ("not an ELF binary"), never a traceback. A text file must be rejected
  cleanly (PDF Step 1 test).
- `e_ident[4]` (EI_CLASS): 1 = 32-bit, 2 = 64-bit. `e_ident[5]` (EI_DATA):
  1 = little-endian, 2 = big-endian. The endianness picks the struct prefix
  (`<` or `>`); the class picks the layout. Support BOTH classes and BOTH
  endiannesses — a big-endian 32-bit binary must parse, not crash.
- 64-bit header: `"<16sHHIQQQIHHHHHH"` → e_type, e_machine, e_version,
  e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum,
  e_shentsize, e_shnum, e_shstrndx.
- 32-bit header: `"<16sHHIIIIIHHHHHH"` → same fields, 32-bit widths.
- `e_type`: 0 NONE, 1 REL (relocatable .o — PIE n/a), 2 EXEC, 3 DYN, 4 CORE.
  A truncated file (shorter than the header) is a clean error.
- Defensive parsing throughout: every offset/size is bounds-checked against
  the file length before reading; a corrupt header is a clean error.

## 2. Program headers — NX and RELRO

- Walk `e_phnum` entries at `e_phoff`, each `e_phentsize` bytes.
- 64-bit phdr: `"<IIQQQQQQ"` (p_type, p_flags, p_offset, p_vaddr, p_paddr,
  p_filesz, p_memsz, p_align). 32-bit phdr: `"<IIIIIIII"` (p_type, p_offset,
  p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align — note the different
  field order).
- `PT_GNU_STACK = 0x6474e551`. Flags: PF_X = 1, PF_W = 2, PF_R = 4.
  NX enabled = GNU_STACK present AND PF_X clear. GNU_STACK with PF_X set
  (`RWE`) = NX disabled. No GNU_STACK segment at all = NX disabled (old
  linkers default to an executable stack) — report it as missing with that
  evidence, not as "unknown".
- `PT_GNU_RELRO = 0x6474e552`. Present → at least Partial RELRO.
- `PT_DYNAMIC = 2` → the dynamic section lives here (p_offset/p_filesz).
  A binary with no PT_DYNAMIC is static: there is no lazy binding at all,
  so RELRO is effectively full when GNU_RELRO is present — report "Full
  (static — no lazy binding)" with that evidence, and bind-now as n/a.
- Report every segment type + flags in the verbose/list mode (PDF Step 2:
  must match `readelf -l` on the same binary).

## 3. Dynamic section — bind-now (Full vs Partial RELRO)

- Walk the dynamic entries at the PT_DYNAMIC offset: 64-bit `"<qQ"`
  (d_tag, d_val), 32-bit `"<iI"`, until `DT_NULL = 0`.
- `DT_FLAGS = 30`, `DF_BIND_NOW = 0x8`; `DT_FLAGS_1 = 0x6ffffffb`,
  `DF_1_NOW = 0x1`. Either flag set → bind-now on.
- RELRO verdict: no GNU_RELRO → "Missing"; GNU_RELRO + bind-now → "Full";
  GNU_RELRO without bind-now → "Partial". Evidence shown: the segment's
  presence plus the exact flag found (`DF_BIND_NOW` / `DF_1_NOW` / none).
- Bonus (checksec parity, extra): `DT_RPATH = 15` / `DT_RUNPATH = 29` —
  report RPATH/RUNPATH as a finding (a hard-coded library path is abusable);
  the value is an offset into the dynamic string table (DT_STRTAB = 5) —
  resolve it and print the path. Also report `DT_NEEDED` count in verbose.

## 4. Section headers + symbol tables — canary and fortified

- Walk `e_shnum` section headers at `e_shoff` (64-bit `"<IIQQQQIIQQ"`,
  32-bit `"<IIIIIIIIII"`). Get each section's name from the section-header
  string table (`e_shstrndx` → that section's sh_offset, names are NUL-
  terminated strings at sh_name offsets).
- Find `.symtab` (SHT_SYMTAB = 2) with its linked string table
  (sh_link → `.strtab`); find `.dynsym` (SHT_DYNSYM = 11) with `.dynstr`.
- Symbol entry: 64-bit `"<IBBHQQ"` (st_name, st_info, st_other, st_shndx,
  st_value, st_size); 32-bit `"<IIIBBH"` (st_name, st_value, st_size,
  st_info, st_other, st_shndx). Resolve names via the linked strtab.
- **Stripped-binary fallback (extra, checksec behaviour):** if `.symtab`
  is absent (stripped), use `.dynsym` — the canary check only needs the
  imported `__stack_chk_fail` symbol, which lives in `.dynsym` even in
  stripped binaries. Report which table the evidence came from.
- Canary: any symbol named `__stack_chk_fail` (also accept
  `__stack_chk_fail_local`) → "Present"; otherwise "Missing". Evidence:
  the symbol name + table.
- Fortified functions: any symbol whose name ends in `_chk`
  (`__memcpy_chk`, `__printf_chk`, `__strcpy_chk`, `__read_chk`, …) →
  count them and list them (cap the printed list, keep the full list in
  JSON). FORTIFY verdict: count > 0 → "Present (N fortified)"; 0 → "Missing".
- Fortify score (extra, checksec.py parity): count the *fortifiable*
  functions present in their plain form (memcpy, printf, strcpy, … — a
  curated list) that are NOT fortified; score = fortified / (fortified +
  fortifiable) as a percentage, or "n/a" when no fortifiable functions are
  used at all. Say in the report that the score is an extra, not a PDF
  verdict.

## 5. PIE

- `e_type == ET_DYN (3)` → "PIE enabled" for an executable; for a shared
  library (also ET_DYN, detected by a `.so` name or by `DT_SONAME`) →
  "DSO" (not applicable — a library is position-independent by nature).
  `ET_EXEC (2)` → "No PIE". `ET_REL (1)` → "n/a (relocatable object)".
  `ET_CORE (4)` → "n/a (core dump)". Evidence: the e_type value + name.
- Note the checksec rule: a static PIE binary is ET_DYN with no dynamic
  section — still PIE enabled.

## 6. Verdict model + score (extra)

- Per mitigation, the PDF's verdicts: **Present / Partial / Missing** (plus
  **n/a** where a check does not apply — DSO, static, relocatable), each
  with the evidence string shown in the table.
- Five ELF checks: RELRO (Full/Partial/Missing), Stack canary, NX, PIE,
  FORTIFY. A missing mitigation is a finding with a severity: NX missing =
  High, canary missing = High, RELRO missing = High, PIE missing = Medium,
  FORTIFY missing = Low. Partial RELRO = Medium.
- Hardening score (EXTRA, clearly marked as beyond the PDF): start at 100;
  −25 per High, −10 per Medium, −5 per Low; clamp 0–100; grade A ≥ 90,
  B ≥ 80, C ≥ 70, D ≥ 60, F < 60. The score ranks binaries in batch mode;
  the verdicts stay the PDF's present/partial/missing.
- Exit codes: 0 = all mitigations present; 1 = any mitigation missing or
  partial; 2 = usage/file error (not an ELF/PE, unreadable file, bad args).
  `--fail-on {high,medium,low,none}` overrides the exit-1 threshold.

## 7. PE support (stretch — Winchecksec parity, struct only)

- DOS header: `MZ` magic, `e_lfanew` u32 at offset 0x3c → PE signature
  `PE\0\0`. COFF header (20 bytes): Machine u16, NumberOfSections u16,
  TimeDateStamp, PointerToSymbolTable, NumberOfSymbols, SizeOfOptionalHeader
  u16, Characteristics u16. Optional header magic: `0x10b` = PE32,
  `0x20b` = PE32+.
- `DllCharacteristics` u16 (PE32 offset 70 from the optional-header start,
  PE32+ offset 70 as well — verify in code against the spec layout):
  `DYNAMIC_BASE = 0x0040`, `HIGH_ENTROPY_VA = 0x0020`, `NX_COMPAT = 0x0100`,
  `NO_SEH = 0x0400`, `GUARD_CF = 0x4000`, `TERMINAL_SERVER_AWARE = 0x8000`.
- Checks: ASLR = DYNAMIC_BASE set (edge case: DYNAMIC_BASE set BUT the
  `.reloc` section is missing/stripped → report "Present (no relocations —
  ASLR ineffective)", Winchecksec's edge case); High Entropy VA = 64-bit
  (PE32+) AND HIGH_ENTROPY_VA set; DEP/NX = NX_COMPAT set; SEH = NO_SEH
  clear; SafeSEH = 32-bit PE only, SEH present, and the load-config
  directory holds a valid SEH handler table (SEHandlerTable != 0 and
  SEHandlerCount > 0) → Present, else Missing; on 64-bit → n/a; CFG =
  GUARD_CF set AND the load-config GuardCFCheckFunctionPointer != 0;
  GS stack cookie = load-config SecurityCookie != 0. Force Integrity =
  `IMAGE_FILE_RELOCS_STRIPPED`? No — Force Integrity is
  `DllCharacteristics & 0x0080` (FORCE_INTEGRITY). Isolation = the manifest:
  check for an `RT_MANIFEST` resource (resource directory entry id 24) —
  report Present/Missing honestly; if the resource directory cannot be
  walked, say "unknown", never guess.
- Load config directory: from the optional header's data directories
  (index 10, `IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG`): VirtualAddress + Size →
  file offset via section table (RVA → file offset mapping through the
  section headers). PE32 load config: SecurityCookie at offset 0x40,
  SEHandlerTable 0x40/0x48, SEHandlerCount, GuardCFCheckFunctionPointer
  0x70/0x80 — the offsets differ between PE32 and PE32+; read them from
  the spec table in code, with the size field as the guard (if the load
  config is smaller than the field's offset, the field is absent).
- PE test fixtures: a Python PE writer (`build_test_pe.py`) that emits a
  minimal PE32 and PE32+ with chosen DllCharacteristics + a load config
  with chosen fields — the same trick as the AXML writer for APKSeeker.
  Live PE testing on the user's Windows 11 host is the follow-up; say so
  in the report if mingw is not available here (check for
  `x86_64-w64-mingw32-gcc` first).

## 8. Test binaries — compiled, not committed

- `build_test_bins.py`: compiles a small C program (one that calls
  memcpy/printf/strcpy so fortification has something to bite on, plus a
  function with a local buffer so the canary appears) with gcc under every
  combination the matrix needs:
  - canary: `-fstack-protector-all` vs `-fno-stack-protector`
  - PIE: `-pie -fPIE` vs `-no-pie`
  - RELRO: `-Wl,-z,relro,-z,now` (full) vs `-Wl,-z,relro` (partial) vs
    `-Wl,-z,norelro` (none)
  - NX: `-Wl,-z,noexecstack` (default) vs `-Wl,-z,execstack`
  - FORTIFY: `-O2 -D_FORTIFY_SOURCE=2` vs `-O0 -U_FORTIFY_SOURCE`
  - static: `-static` (and `-static-pie` if the toolchain supports it)
  - stripped: `strip` the binary afterwards (tests the .dynsym fallback)
  - 32-bit: `-m32` (only if `gcc-multilib` is installed — check first;
    if not, document it as untested, do not fake it)
- The generator writes the binaries into `test_bins/` and a manifest of
  the flags used per binary. Binary files are NEVER committed to GitHub
  (push-files is text-only — the APKSeeker lesson); they regenerate with
  `python run.py build-bins`. The C source and the generator ARE committed.
- Oracle: every verdict is compared against `readelf -h/-l/-s/-d` on the
  same binary (and `checksec` / pwntools if installable). Any mismatch is
  a test failure, not a note.

## 9. Interface (same family as SSTIProbe / RBACLens / PipeSentry / MemSeeker / APKSeeker)

- TraceRecon colour class + clear/sep/header/ok/warn/err/info helpers,
  LEGAL DISCLAIMER + box in the banner, Gobuster-style SCAN config block,
  numbered menu with `[?] Select option:` prompt, `--batch`, `-q`, `--version`,
  `--no-color`, `-i/--interactive/--menu`.
- CLI: `canaryseeker.py <binary|directory> [-o/--output report] [--json]
  [--batch] [--recursive] [--min-severity {high,medium,low}]
  [--fail-on {high,medium,low,none}] [--list-checks] [--check] [--skip-check]
  [-q/--quiet] [--batch] [-i/--interactive/--menu] [--version] [--no-color]`.
  A directory path implies batch mode. Exit codes per §6.
- Menu: [1] Check a binary [2] Batch check test binaries [3] Quick check
  fully-hardened binary [4] Quick check unhardened binary [5] List all
  checks [6] Run step tests [7] Check setup (doctor — gcc/readelf/checksec
  presence) [0] Exit.
- `run.py` launcher (venv auto-create + install; commands: setup, check,
  test, doctor, build-bins, build-pe, menu) + `run.bat` (Windows — must
  actually run the tool) + `run.sh`. requirements.txt: stdlib only.
  Cross-platform: pure Python, Windows/macOS/Linux.
- Author "CyberBoy50" ONLY everywhere in the tool and docs — no real names
  anywhere (student Muhammad Zohaib and instructor Abdul Mannan go only in
  the REPORT document).
- Finding codes (family pattern): CC-001 RELRO, CC-002 stack canary,
  CC-003 NX, CC-004 PIE, CC-005 FORTIFY, CC-006 RPATH/RUNPATH (extra),
  CC-007 PE ASLR, CC-008 PE DEP/NX, CC-009 PE CFG, CC-010 PE SafeSEH,
  CC-011 PE GS cookie.
