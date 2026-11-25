# CanarySeeker — Step-by-Step Guide

Build the tool one step at a time, exactly as the PDF's build plan
says. Test each step before moving on — a step you have not tested
is a step you have not finished. Every step below has the command
and the expected result.

Prerequisites: Python 3.10+ and gcc (for compiling the test
binaries). Nothing else — the tool is standard library only.

```bash
git clone https://github.com/CyberBoy50/CanarySeeker.git
cd CanarySeeker
python run.py setup        # first time only
python run.py build-bins   # compile the ELF test binaries
python run.py build-pe     # write the PE test fixtures
```

## Step 1 — Read the ELF header

**Write:** open a binary, check the magic bytes (`\x7fELF`), print
the class (32/64-bit), the endianness and the file type.

```bash
python3 canaryseeker.py test_bins/hardened --segments
python3 -c "
import canaryseeker as cs
kind, elf = cs.load_binary('test_bins/hardened')
print(kind, elf['class'], elf['endian'], elf['type_name'])
"
```

Expected: `ELF 64 little ET_DYN`. Run it on a text file and the
tool refuses cleanly:

```bash
echo "hello" > /tmp/not_a_binary.txt
python3 canaryseeker.py /tmp/not_a_binary.txt; echo "exit=$?"
```

Expected: a clean error ("Not a binary I can check … is neither
ELF nor PE"), exit 2, no traceback.

**Test:** `python run.py test` — Step 1 checks the header fields
on the hardened binary, the 32-bit little-endian fixture and the
32-bit big-endian fixture, and the clean rejection of a text file
and a truncated ELF.

## Step 2 — Walk the program headers

**Write:** parse the program-header table and print every segment
type with its flags.

```bash
python3 canaryseeker.py test_bins/hardened --segments
```

Expected: 13 segments (PHDR, INTERP, 4× LOAD, DYNAMIC, 2× NOTE,
GNU_PROPERTY, GNU_EH_FRAME, GNU_STACK, GNU_RELRO) with the flags
readelf shows. Compare them directly:

```bash
readelf -W -l test_bins/hardened
```

**Test:** the suite compares the tool's segment list with
`readelf -W -l` on five binaries (hardened, unhardened, static,
elf32_le, elf32_be) — type and flags must match, segment for
segment. One detail worth knowing: readelf prints the execute flag
as **E**, not X, so the tool prints it as E too.

## Step 3 — NX and RELRO verdicts

**Write:** derive NX from GNU_STACK and RELRO from GNU_RELRO plus
the bind-now flag.

```bash
python3 canaryseeker.py test_bins/hardened --no-color
python3 canaryseeker.py test_bins/partial_relro --no-color
python3 canaryseeker.py test_bins/unhardened --no-color
```

Expected: hardened is Full RELRO + NX Present; partial_relro is
Partial RELRO (it was linked `-Wl,-z,relro,-z,lazy` — Ubuntu's gcc
adds `-z now` by default, so lazy has to be explicit); unhardened
is No RELRO + NX Missing (GNU_STACK is RWE). Verify against
readelf:

```bash
readelf -W -d test_bins/partial_relro | grep FLAGS
readelf -W -l test_bins/unhardened | grep GNU_STACK
```

**Test:** the suite checks all five verdict combinations and
cross-checks bind-now and the stack flags against readelf.

## Step 4 — Symbol table walk

**Write:** find the symbol table through the section headers and
list every symbol name.

```bash
python3 canaryseeker.py test_bins/hardened --symbols
python3 canaryseeker.py test_bins/stripped --symbols
```

Expected: hardened lists `__stack_chk_fail` from `.symtab`;
stripped lists it from `.dynsym` — the tool falls back to the
dynamic symbol table when the binary is stripped, and says which
table the evidence came from. Compare:

```bash
readelf -W -s test_bins/hardened | grep stack_chk
readelf -W -s test_bins/stripped | grep stack_chk
```

**Test:** the suite checks the canary is Present in the protected
build, Missing in the unprotected build, and still found via
`.dynsym` in the stripped build.

## Step 5 — Fortified functions

**Write:** flag symbols whose names end in `_chk` and count them.

```bash
python3 canaryseeker.py test_bins/hardened --no-color | grep -A1 FORTIFY
python3 canaryseeker.py test_bins/no_fortify --no-color | grep -A1 FORTIFY
```

Expected: hardened reports 1 fortified function (`__strcpy_chk`,
Fortify score 100%); no_fortify reports none (score 0%). Why only
one? The compiler decides which calls survive: `printf("%s\n", x)`
becomes `puts(x)` even at -O0, and a 5-byte `memcpy` is inlined at
-O2 — so those calls never appear as symbols. The tool reports
what is actually in the binary.

**Test:** the suite compares the fortified list with
`readelf -W -s` and checks the count changes between the two
builds.

## Step 6 — CLI, verdict table and report

**Write:** argparse for the binary path and output file, the
verdict table, and the saved report.

```bash
python3 canaryseeker.py test_bins/hardened -o report.txt
python3 canaryseeker.py test_bins/unhardened -o report.txt
python3 canaryseeker.py test_pe/pe64_hardened.exe -o report.txt
cat report.txt
```

Expected: a complete report for each — header info, the verdict
table with evidence, the findings with fixes, the hardening score.
Exit codes: hardened 0, unhardened 1.

**Test:** the suite runs the CLI on three binaries and reads the
saved reports start to finish.

## Step 7 — Full test matrix

**Write:** a set of test binaries with every combination of
mitigation flags, and run the tool on all of them.

```bash
python run.py build-bins
python run.py check test_bins/
```

Expected: the batch summary — hardened 100/100, unhardened
10/100, every other binary exactly the score its flags predict
(`test_bins/manifest.json` lists them all). The two non-binary
files in the folder (the manifest and the C source) are reported
as skipped, not crashed on.

**Test:** the suite runs every binary in the manifest and asserts
each verdict, score, grade and exit code — 16 binaries, no
exceptions.

## Step 8 — Stretch items and the beyond-PDF extras

**PE support** — the fixtures are written by `build_test_pe.py`
(no mingw here):

```bash
python run.py build-pe
python run.py check test_pe/pe64_hardened.exe
python run.py check test_pe/pe64_unhardened.exe
python run.py check test_pe/pe64_no_reloc.exe
python run.py check test_pe/pe32_partial_cfg.exe
```

Expected: the 64-bit hardened PE is 100/100, the unhardened one
5/100; the no-reloc PE shows ASLR Present with the note that it is
ineffective (DYNAMIC_BASE without a `.reloc` section); the
partial-CFG PE shows CFG Partial.

**Batch mode and JSON:**

```bash
python run.py check test_bins/ --json -o batch.json
python3 -c "import json; d = json.load(open('batch.json')); print(len(d['results']), 'results')"
```

**Beyond the PDF** — the extras are all in the same tool: 32-bit
and big-endian ELF (`elf32_le`, `elf32_be`), the `.dynsym`
fallback (`stripped`), static binaries (`static`, `static_pie`),
RPATH/RUNPATH (`rpath`, `runpath`), the Fortify score, and the
hardening score + grade on every report.

**Test:** the suite checks all six PE fixtures against their
manifest, the batch summary, and that the JSON report parses and
matches the text verdicts — plus the readelf and pwntools oracles
for the ELF verdicts.

## Running all the tests

```bash
python run.py test
```

Expected:

```
PASSED: 344   FAILED: 0   SKIPPED: 0
ALL CHECKS PASSED
```

If pwntools is not importable the oracle checks are skipped with
a clear note (readelf is the oracle instead) — nothing is faked.
