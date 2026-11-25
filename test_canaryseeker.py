#!/usr/bin/env python3
"""Step tests for CanarySeeker — one function per PDF build step,
plus Step 8 (stretch) and the independent oracles.

Oracles (independent readers, never the tool itself):
  * readelf -h/-l/-s/-d — always present here; every verdict is
    compared against it.
  * pwntools 4.15.1 (ELF.checksec()) — in /tmp/pwntools-venv when
    available; RELRO / canary / PIE / FORTIFY are compared against
    it. When pwntools is not importable the oracle checks are
    SKIPPED with a clear note (the round-trip + readelf checks are
    the oracle instead) — nothing is faked.
  * checksec (the Go tool) is not installed here and apt has no
    package for it, so it is not used.

Run:  python3 test_canaryseeker.py
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import canaryseeker as cs  # noqa: E402

BINS = os.path.join(HERE, "test_bins")
PE = os.path.join(HERE, "test_pe")
PASSED = 0
FAILED = 0
SKIPPED = 0
FAILURES = []


def check(cond, label):
    global PASSED, FAILED
    if cond:
        PASSED += 1
    else:
        FAILED += 1
        FAILURES.append(label)
        print("  [FAIL] %s" % label)


def skip(label):
    global SKIPPED
    SKIPPED += 1
    print("  [SKIP] %s" % label)


def run(cmd, timeout=60):
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout)


# --- readelf oracle ----------------------------------------------------------
def readelf(*args):
    # -W (wide): readelf truncates long symbol names and wraps
    # program-header lines without it.
    rc = run(["readelf", "-W"] + list(args))
    return rc.stdout


def readelf_header_type(path):
    for line in readelf("-h", path).splitlines():
        if "Type:" in line:
            return line.split("Type:")[1].strip().split()[0]
    return None


def readelf_segments(path):
    """[(type_name, flags_str)] in file order, from readelf -l.

    With -W each program header is ONE line: Type Offset VirtAddr
    PhysAddr FileSiz MemSiz Flags Align — and the flags come
    space-separated ("R E"). Without -W readelf wraps them onto
    two lines, which is why the oracle always uses -W."""
    out = []
    for line in readelf("-l", path).splitlines():
        m = re.match(
            r"\s+([A-Z_][A-Z0-9_]*)\s+0x[0-9a-f]+\s+0x[0-9a-f]+"
            r"\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x[0-9a-f]+"
            r"\s+([RWE ]*?)\s+0x[0-9a-f]+\s*$", line)
        if m:
            out.append((m.group(1), m.group(2).replace(" ", "")))
    return out


def readelf_dynamic(path):
    """{tag_name: value_text} from readelf -d."""
    out = {}
    for line in readelf("-d", path).splitlines():
        m = re.match(r"\s+0x[0-9a-f]+ \((\w+)\)\s+(.*)", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def readelf_symbols(path):
    """Symbol names (version suffixes stripped) from readelf -s."""
    names = set()
    for line in readelf("-s", path).splitlines():
        m = re.match(
            r"\s+\d+:\s+[0-9a-f]+\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)",
            line)
        if m:
            names.add(m.group(1).split("@")[0])
    return names


def readelf_has_gnu_stack_exec(path):
    for _t, flags in readelf_segments(path):
        if _t == "GNU_STACK":
            return "E" in flags  # readelf's letter for execute
    return None


# --- pwntools oracle ---------------------------------------------------------
_PWN = None
_PWN_TRIED = False


def pwntools_checksec(path):
    """{'RELRO': ..., 'Stack': ..., 'NX': ..., 'PIE': ...,
    'FORTIFY': ...} from pwntools, or None when unavailable."""
    global _PWN, _PWN_TRIED
    if not _PWN_TRIED:
        _PWN_TRIED = True
        try:
            from pwn import ELF  # noqa: F401
            _PWN = True
        except ImportError:
            venv = "/tmp/pwntools-venv/lib/python3.12/site-packages"
            if os.path.isdir(venv):
                sys.path.insert(0, venv)
                try:
                    from pwn import ELF  # noqa: F401
                    _PWN = True
                except ImportError:
                    _PWN = False
            else:
                _PWN = False
    if not _PWN:
        return None
    from pwn import ELF
    import io
    import contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        out = ELF(path).checksec()
    text = out if isinstance(out, str) else buf.getvalue()
    found = {}
    for line in text.splitlines():
        m = re.match(r"\s*(\w+):\s+(.*)", line)
        # Keep the FIRST occurrence: pwntools prints "Stack:" twice
        # for an executable stack ("No canary found", then
        # "Executable") and the second would overwrite the first.
        if m and m.group(1) not in found:
            found[m.group(1)] = m.group(2).strip()
    return found


def pwn_verdicts(found):
    """Map pwntools' words to our verdicts (RELRO/canary/PIE/
    FORTIFY only — NX uses a different model there)."""
    out = {}
    if "RELRO" in found:
        relro = found["RELRO"]
        out["RELRO"] = ("Present" if relro.startswith("Full")
                        else "Partial" if relro.startswith("Partial")
                        else "Missing")
    if "Stack" in found:
        out["canary"] = ("Present" if "Canary found" in found["Stack"]
                         else "Missing")
    if "PIE" in found:
        pie = found["PIE"]
        out["PIE"] = ("Present" if pie.startswith("PIE enabled")
                      else "n/a" if pie.startswith("DSO")
                      else "Missing")
    # FORTIFY line is absent when nothing is fortified.
    out["FORTIFY"] = ("Present" if found.get("FORTIFY") == "Enabled"
                      else "Missing")
    return out


# --- Steps -------------------------------------------------------------------
def step_1():
    print("Step 1 — read the ELF header")
    kind, elf = cs.load_binary(os.path.join(BINS, "hardened"))
    check(kind == "ELF", "hardened is detected as ELF")
    check(elf["class"] == 64, "hardened is 64-bit")
    check(elf["endian"] == "little", "hardened is little-endian")
    check(elf["type_name"] == "ET_DYN", "hardened type is ET_DYN")
    check(elf["machine_name"] == "x86-64",
          "hardened machine is x86-64")
    kind, elf = cs.load_binary(os.path.join(BINS, "elf32_le"))
    check(kind == "ELF", "elf32_le is detected as ELF")
    check(elf["class"] == 32, "elf32_le is 32-bit")
    check(elf["endian"] == "little", "elf32_le is little-endian")
    check(elf["type_name"] == "ET_EXEC", "elf32_le type is ET_EXEC")
    kind, elf = cs.load_binary(os.path.join(BINS, "elf32_be"))
    check(elf["class"] == 32, "elf32_be is 32-bit")
    check(elf["endian"] == "big", "elf32_be is big-endian")
    check(elf["machine_name"] == "PowerPC",
          "elf32_be machine is PowerPC")
    # A text file is rejected cleanly (PDF Step 1 test).
    txt = os.path.join(BINS, "not_a_binary.txt")
    with open(txt, "w") as fh:
        fh.write("hello, this is a text file\n")
    try:
        cs.load_binary(txt)
        check(False, "text file is rejected cleanly")
    except cs.CanarySeekerError as exc:
        check("neither ELF nor PE" in str(exc),
              "text file is rejected cleanly")
    os.remove(txt)
    # A truncated ELF is a clean error, not a traceback.
    with open(os.path.join(BINS, "hardened"), "rb") as fh:
        data = fh.read(20)
    with open(os.path.join(BINS, "truncated"), "wb") as fh:
        fh.write(data)
    try:
        cs.load_binary(os.path.join(BINS, "truncated"))
        check(False, "truncated ELF is a clean error")
    except cs.CanarySeekerError:
        check(True, "truncated ELF is a clean error")
    os.remove(os.path.join(BINS, "truncated"))


def step_2():
    print("Step 2 — walk the program headers (vs readelf -l)")
    for name in ("hardened", "unhardened", "static", "elf32_le",
                 "elf32_be"):
        path = os.path.join(BINS, name)
        _kind, elf = cs.load_binary(path)
        mine = [(s["type_name"], s["flags_str"])
                for s in elf["segments"]]
        theirs = readelf_segments(path)
        check(mine == theirs,
              "%s segments match readelf -l (%d segments)"
              % (name, len(mine)))
    # A relocatable object has no program headers at all.
    _kind, elf = cs.load_binary(os.path.join(BINS, "test.o"))
    check(elf["segments"] == [], "test.o has no program headers")
    check(readelf_segments(os.path.join(BINS, "test.o")) == [],
          "readelf agrees test.o has no program headers")


def step_3():
    print("Step 3 — NX and RELRO verdicts (vs readelf -d/-l)")
    cases = {
        "hardened": ("Present", "Present"),
        "partial_relro": ("Partial", "Present"),
        "unhardened": ("Missing", "Missing"),
        "no_nx": ("Present", "Missing"),
        "static": ("Present", "Present"),
    }
    for name, (want_relro, want_nx) in cases.items():
        path = os.path.join(BINS, name)
        result = cs.analyze_path(path)
        got = {v["code"]: v["verdict"] for v in result["verdicts"]}
        check(got["CC-001"] == want_relro,
              "%s RELRO is %s" % (name, want_relro))
        check(got["CC-003"] == want_nx,
              "%s NX is %s" % (name, want_nx))
        # readelf agrees on bind-now and on the stack flags.
        # (A static binary has no dynamic section at all, so no
        # bind-now flag — its RELRO is "Present" via the static
        # rule, not via a flag.)
        dyn = readelf_dynamic(path)
        bind = ("BIND_NOW" in dyn.get("FLAGS", "")
                or "NOW" in dyn.get("FLAGS_1", ""))
        want_bind = (want_relro == "Present") and name != "static"
        check(bind == want_bind,
              "%s readelf bind-now agrees (%s)" % (name, bind))
        stack_exec = readelf_has_gnu_stack_exec(path)
        check((stack_exec is True) == (want_nx == "Missing"),
              "%s readelf GNU_STACK flags agree" % name)


def step_4():
    print("Step 4 — symbol table walk (vs readelf -s)")
    hardened = readelf_symbols(os.path.join(BINS, "hardened"))
    check("__stack_chk_fail" in hardened,
          "readelf: hardened has __stack_chk_fail")
    result = cs.analyze_path(os.path.join(BINS, "hardened"))
    got = {v["code"]: v["verdict"] for v in result["verdicts"]}
    check(got["CC-002"] == "Present", "hardened canary is Present")
    check("symtab" in result["header"]["symbol_table"],
          "hardened canary evidence comes from .symtab")
    unhardened = readelf_symbols(os.path.join(BINS, "unhardened"))
    check("__stack_chk_fail" not in unhardened,
          "readelf: unhardened has no __stack_chk_fail")
    result = cs.analyze_path(os.path.join(BINS, "unhardened"))
    got = {v["code"]: v["verdict"] for v in result["verdicts"]}
    check(got["CC-002"] == "Missing", "unhardened canary is Missing")
    # Stripped: no .symtab, but .dynsym still carries the canary.
    _kind, elf = cs.load_binary(os.path.join(BINS, "stripped"))
    check(elf["stripped"] is True, "stripped has no .symtab")
    check(elf["symbols"]["table"] == "dynsym",
          "stripped falls back to .dynsym")
    result = cs.analyze_path(os.path.join(BINS, "stripped"))
    got = {v["code"]: v["verdict"] for v in result["verdicts"]}
    check(got["CC-002"] == "Present",
          "stripped canary is still found via .dynsym")
    check("dynsym" in result["header"]["symbol_table"],
          "stripped report says the evidence came from .dynsym")


def step_5():
    print("Step 5 — fortified functions (vs readelf -s)")
    hardened = readelf_symbols(os.path.join(BINS, "hardened"))
    fort_h = sorted(n for n in hardened if n.endswith("_chk"))
    check(len(fort_h) > 0,
          "readelf: hardened has %d fortified symbol(s)" % len(fort_h))
    result = cs.analyze_path(os.path.join(BINS, "hardened"))
    got = {v["code"]: v["verdict"] for v in result["verdicts"]}
    check(got["CC-005"] == "Present", "hardened FORTIFY is Present")
    check(result["fortify"]["fortified"] == fort_h,
          "hardened fortified list matches readelf -s")
    check(result["fortify"]["score"] == 100,
          "hardened Fortify score is 100%%")
    unhardened = readelf_symbols(os.path.join(BINS, "unhardened"))
    fort_u = [n for n in unhardened if n.endswith("_chk")]
    check(fort_u == [], "readelf: unhardened has no _chk symbols")
    result = cs.analyze_path(os.path.join(BINS, "unhardened"))
    got = {v["code"]: v["verdict"] for v in result["verdicts"]}
    check(got["CC-005"] == "Missing", "unhardened FORTIFY is Missing")
    check(result["fortify"]["score"] == 0,
          "unhardened Fortify score is 0%%")
    check(len(result["fortify"]["fortifiable"]) >= 2,
          "unhardened still uses plain fortifiable functions")


def step_6():
    print("Step 6 — CLI, verdict table and report")
    for name in ("hardened", "unhardened", "pe64_hardened.exe"):
        sub = BINS if name.endswith(
            ("ened", "o")) and not name.endswith(".exe") else PE
        path = os.path.join(sub, name)
        out = os.path.join(HERE, ".step6_%s.txt" % name)
        rc = run([sys.executable,
                  os.path.join(HERE, "canaryseeker.py"),
                  path, "--no-color", "-o", out])
        check(rc.returncode in (0, 1),
              "CLI exits 0/1 on %s (got %d)"
              % (name, rc.returncode))
        with open(out) as fh:
            text = fh.read()
        check("CanarySeeker" in text, "%s report has the header" % name)
        check("Verdict table" in text,
              "%s report has the verdict table" % name)
        check("Hardening score" in text,
              "%s report has the score" % name)
        check("Findings" in text, "%s report has findings" % name)
        check("DISCLAIMER" in text and "AUTHORIZED USE ONLY" in text,
              "%s report carries the disclaimer" % name)
        os.remove(out)
    # Exit codes: hardened 0, unhardened 1.
    rc = run([sys.executable, os.path.join(HERE, "canaryseeker.py"),
              os.path.join(BINS, "hardened"), "-q", "-o",
              os.path.join(HERE, ".step6_h.txt")])
    check(rc.returncode == 0, "hardened exits 0")
    rc = run([sys.executable, os.path.join(HERE, "canaryseeker.py"),
              os.path.join(BINS, "unhardened"), "-q", "-o",
              os.path.join(HERE, ".step6_u.txt")])
    check(rc.returncode == 1, "unhardened exits 1")
    for f in (".step6_h.txt", ".step6_u.txt"):
        if os.path.exists(os.path.join(HERE, f)):
            os.remove(os.path.join(HERE, f))


def step_7():
    print("Step 7 — full test matrix (vs manifest.json)")
    with open(os.path.join(BINS, "manifest.json")) as fh:
        manifest = json.load(fh)
    check(len(manifest) >= 20, "manifest covers 20 binaries")
    for name, want in sorted(manifest.items()):
        path = os.path.join(BINS, name)
        if name == "shared":
            path = os.path.join(BINS, "libtest.so")
        elif name == "reloc":
            path = os.path.join(BINS, "test.o")
        result = cs.analyze_path(path)
        got = {v["code"]: v["verdict"] for v in result["verdicts"]}
        by_name = {"RELRO": got["CC-001"], "canary": got["CC-002"],
                   "NX": got["CC-003"], "PIE": got["CC-004"],
                   "FORTIFY": got["CC-005"], "RPATH": got["CC-006"],
                   "CET": got["CC-014"]}
        for key in ("RELRO", "canary", "NX", "PIE", "FORTIFY",
                    "RPATH", "CET"):
            check(by_name[key] == want[key],
                  "%s %s is %s (got %s)"
                  % (name, key, want[key], by_name[key]))
        check(result["score"] == want["score"],
              "%s score is %d (got %d)"
              % (name, want["score"], result["score"]))
        check(result["grade"] == want["grade"],
              "%s grade is %s (got %s)"
              % (name, want["grade"], result["grade"]))
        # The exit code the CLI would return.
        rc = run([sys.executable,
                  os.path.join(HERE, "canaryseeker.py"), path,
                  "-q", "-o", os.path.join(HERE, ".step7.txt")])
        check(rc.returncode == want["exit"],
              "%s exits %d (got %d)"
              % (name, want["exit"], rc.returncode))
    if os.path.exists(os.path.join(HERE, ".step7.txt")):
        os.remove(os.path.join(HERE, ".step7.txt"))


def step_8():
    print("Step 8 — stretch: PE, batch mode, JSON")
    with open(os.path.join(PE, "manifest.json")) as fh:
        manifest = json.load(fh)
    check(len(manifest) == 7, "PE manifest covers 7 fixtures")
    for name, want in sorted(manifest.items()):
        result = cs.analyze_path(os.path.join(PE, name))
        got = {v["code"]: v["verdict"] for v in result["verdicts"]}
        by_name = {"ASLR": got["CC-007"], "DEP": got["CC-008"],
                   "CFG": got["CC-009"], "SafeSEH": got["CC-010"],
                   "GS": got["CC-011"], "FI": got["CC-012"],
                   "Isolation": got["CC-013"]}
        for key in ("ASLR", "DEP", "CFG", "SafeSEH", "GS", "FI",
                    "Isolation"):
            check(by_name[key] == want[key],
                  "%s %s is %s (got %s)"
                  % (name, key, want[key], by_name[key]))
        check(result["score"] == want["score"],
              "%s PE score is %d (got %d)"
              % (name, want["score"], result["score"]))
        rc = run([sys.executable,
                  os.path.join(HERE, "canaryseeker.py"),
                  os.path.join(PE, name), "-q", "-o",
                  os.path.join(HERE, ".step8.txt")])
        check(rc.returncode == want["exit"],
              "%s PE exits %d (got %d)"
              % (name, want["exit"], rc.returncode))
    if os.path.exists(os.path.join(HERE, ".step8.txt")):
        os.remove(os.path.join(HERE, ".step8.txt"))
    # Batch mode on test_bins/: every binary in one report.
    out = os.path.join(HERE, ".step8_batch.txt")
    rc = run([sys.executable, os.path.join(HERE, "canaryseeker.py"),
              BINS, "--no-color", "-o", out])
    check(rc.returncode == 1, "batch exits 1 (some binaries unhardened)")
    with open(out) as fh:
        text = fh.read()
    check("Batch summary" in text or "Binary:" in text,
          "batch report lists the binaries")
    check(text.count("Binary:") >= 20,
          "batch report covers all 20 test binaries")
    os.remove(out)
    # JSON output parses and matches the text verdicts.
    out = os.path.join(HERE, ".step8.json")
    rc = run([sys.executable, os.path.join(HERE, "canaryseeker.py"),
              os.path.join(BINS, "hardened"), "--json", "-o", out])
    check(rc.returncode == 0, "JSON run exits 0")
    with open(out) as fh:
        doc = json.load(fh)
    check(doc["tool"] == "CanarySeeker", "JSON has the tool name")
    check(len(doc["results"]) == 1, "JSON has one result")
    got = {v["code"]: v["verdict"]
           for v in doc["results"][0]["verdicts"]}
    check(got["CC-001"] == "Present", "JSON RELRO matches the text")
    check(doc["results"][0]["score"] == 100,
          "JSON score matches the text")
    os.remove(out)


def readelf_notes_cet(path):
    """(ibt, shstk) from readelf -n — the CET oracle.

    Returns (True/False, True/False), or (False, False) when
    readelf shows no .note.gnu.property section at all (then CET
    is off, and the tool must say Missing, not guess)."""
    out = readelf("-n", path)
    if ".note.gnu.property" not in out:
        return (False, False)
    for line in out.splitlines():
        if "x86 feature:" in line:
            feats = line.split("x86 feature:")[1]
            return ("IBT" in feats, "SHSTK" in feats)
    return (False, False)


def step_9():
    print("Step 9 — CET (CC-014), real 32-bit, real PE")
    # The three -fcf-protection fixtures, cross-checked against
    # readelf -n (the oracle reads the same note independently).
    cases = {
        "cet_none": ("Missing", (False, False)),
        "cet_ibt": ("Partial", (True, False)),
        "cet_shstk": ("Partial", (False, True)),
        "hardened": ("Present", (True, True)),
    }
    for name, (want, want_bits) in cases.items():
        path = os.path.join(BINS, name)
        result = cs.analyze_path(path)
        got = {v["code"]: v["verdict"] for v in result["verdicts"]}
        check(got["CC-014"] == want,
              "%s CET is %s" % (name, want))
        check(readelf_notes_cet(path) == want_bits,
              "readelf agrees %s CET bits are %s" % (name, want_bits))
        _kind, elf = cs.load_binary(path)
        check((elf["cet"]["ibt"], elf["cet"]["shstk"]) == want_bits,
              "%s parsed CET bits are %s" % (name, want_bits))
    # Scores: CET is Low, so a lone CET finding costs 5 points.
    for name, want_score in (("cet_none", 95), ("cet_ibt", 95),
                             ("cet_shstk", 95)):
        result = cs.analyze_path(os.path.join(BINS, name))
        check(result["score"] == want_score,
              "%s score is %d with only CET missing/partial"
              % (name, want_score))
    # CET does not apply to a non-x86 machine or a relocatable
    # object — and the hand-built 32-bit LE fixture carries a real
    # CET note, so its CET is Present, not Missing.
    for name, want in (("elf32_be", "n/a"), ("reloc", "n/a"),
                       ("elf32_le", "Present")):
        path = os.path.join(BINS, "test.o" if name == "reloc"
                            else name)
        result = cs.analyze_path(path)
        got = {v["code"]: v["verdict"] for v in result["verdicts"]}
        check(got["CC-014"] == want, "%s CET is %s" % (name, want))
    check(readelf_notes_cet(os.path.join(BINS, "elf32_le"))
          == (True, True),
          "readelf agrees elf32_le CET note has IBT + SHSTK")
    # The real -m32 compile: 32-bit, x86, ET_DYN — and its CET is
    # genuinely Missing, because Ubuntu's gcc enables CET by
    # default for 64-bit only (no .note.gnu.property at all).
    real32 = os.path.join(BINS, "elf32_real")
    if os.path.isfile(real32):
        _kind, elf = cs.load_binary(real32)
        check(elf["class"] == 32, "elf32_real is 32-bit")
        check(elf["machine_name"] == "x86", "elf32_real is x86")
        check(elf["type_name"] == "ET_DYN", "elf32_real is ET_DYN")
        check(readelf_header_type(real32) == "DYN",
              "readelf agrees elf32_real is ET_DYN")
        check(".note.gnu.property" not in readelf("-n", real32),
              "readelf: elf32_real has no CET note (gcc default)")
        result = cs.analyze_path(real32)
        got = {v["code"]: v["verdict"] for v in result["verdicts"]}
        check(got["CC-014"] == "Missing",
              "elf32_real CET is Missing (matches the toolchain)")
        check(result["score"] == 95, "elf32_real score is 95")
        # Its segments still match readelf -l exactly.
        mine = [(s["type_name"], s["flags_str"])
                for s in elf["segments"]]
        check(mine == readelf_segments(real32),
              "elf32_real segments match readelf -l")
    else:
        skip("elf32_real not built — gcc-multilib not installed")
    # The small-directory load-config regression (v1.2 fix): the
    # fixture's directory says 64 but the struct is 0xA0, like
    # Process Explorer — CFG and SafeSEH must still be Present.
    result = cs.analyze_path(os.path.join(
        PE, "pe32_small_lc_dir.exe"))
    got = {v["code"]: v["verdict"] for v in result["verdicts"]}
    check(got["CC-009"] == "Present",
          "small load-config dir: CFG is still Present")
    check(got["CC-010"] == "Present",
          "small load-config dir: SafeSEH is still Present")
    check(result["score"] == 100,
          "small load-config dir: score is 100")
    # The real Windows binary (local only, never pushed):
    # Microsoft Sysinternals Process Explorer, downloaded from
    # live.sysinternals.com. Read-only scan; the verdicts below
    # are the ones recorded in DEMO.md / the project report.
    real_pe = os.path.join(HERE, "real_world", "ProcExp.exe")
    if os.path.isfile(real_pe):
        result = cs.analyze_path(real_pe)
        got = {v["code"]: v["verdict"] for v in result["verdicts"]}
        want = {"CC-007": "Present", "CC-008": "Present",
                "CC-009": "Present", "CC-010": "Present",
                "CC-011": "Present", "CC-012": "Missing",
                "CC-013": "Present"}
        for code, want_v in sorted(want.items()):
            check(got[code] == want_v,
                  "ProcExp.exe %s is %s (got %s)"
                  % (code, want_v, got[code]))
        check(result["score"] == 95, "ProcExp.exe score is 95")
        check(result["grade"] == "A", "ProcExp.exe grade is A")
        check(result["header"]["bits"] == 32,
              "ProcExp.exe is a 32-bit PE")
    else:
        skip("real_world/ProcExp.exe not present — real-PE scan "
             "not run")


def cli_bits():
    print("CLI bits and malformed input")
    here = os.path.join(HERE, "canaryseeker.py")
    # --segments matches readelf -l (already covered in Step 2, but
    # the flag itself must work).
    rc = run([sys.executable, here,
              os.path.join(BINS, "hardened"), "--segments"])
    check(rc.returncode == 0, "--segments exits 0")
    check("GNU_STACK" in rc.stdout, "--segments lists GNU_STACK")
    rc = run([sys.executable, here,
              os.path.join(BINS, "hardened"), "--symbols"])
    check(rc.returncode == 0, "--symbols exits 0")
    check("__stack_chk_fail" in rc.stdout,
          "--symbols lists __stack_chk_fail")
    rc = run([sys.executable, here, "--list-checks"])
    check(rc.returncode == 0, "--list-checks exits 0")
    check("CC-001" in rc.stdout and "CC-014" in rc.stdout,
          "--list-checks lists CC-001..CC-014")
    rc = run([sys.executable, here, "--version"])
    check("CanarySeeker v1.2" in rc.stdout, "--version prints 1.2")
    # Disclaimer: on screen (banner, shown by --list-checks / menu —
    # direct scans print the SCAN block instead), in the text report
    # and in JSON.
    rc = run([sys.executable, here, "--list-checks"])
    check("DISCLAIMER" in rc.stdout,
          "banner prints the disclaimer")
    check("PECA 2016" in rc.stdout,
          "banner disclaimer names PECA 2016")
    rc = run([sys.executable, here,
              os.path.join(BINS, "hardened"), "--json", "--no-color",
              "-o", os.path.join(HERE, ".cli_disc.json")])
    with open(os.path.join(HERE, ".cli_disc.json")) as fh:
        doc = json.load(fh)
    check(doc.get("version") == "1.2", "JSON report says version 1.2")
    check("DISCLAIMER" in doc.get("disclaimer", ""),
          "JSON report carries the disclaimer field")
    for f in (".cli_disc.txt", ".cli_disc.json"):
        if os.path.exists(os.path.join(HERE, f)):
            os.remove(f)
    # --fail-on: a High finding on the unhardened binary exits 2.
    rc = run([sys.executable, here,
              os.path.join(BINS, "unhardened"), "-q",
              "--fail-on", "high", "-o",
              os.path.join(HERE, ".cli.txt")])
    check(rc.returncode == 2, "--fail-on high exits 2")
    rc = run([sys.executable, here,
              os.path.join(BINS, "unhardened"), "-q",
              "--fail-on", "none", "-o",
              os.path.join(HERE, ".cli.txt")])
    check(rc.returncode == 1, "--fail-on none exits 1")
    # --min-severity hides the Low FORTIFY finding from the screen.
    rc = run([sys.executable, here,
              os.path.join(BINS, "no_fortify"), "--no-color",
              "--min-severity", "medium", "-o",
              os.path.join(HERE, ".cli.txt")])
    check("FORTIFY" not in rc.stdout.split("Findings")[1]
          if "Findings" in rc.stdout else True,
          "--min-severity medium hides the Low finding")
    if os.path.exists(os.path.join(HERE, ".cli.txt")):
        os.remove(os.path.join(HERE, ".cli.txt"))
    # Malformed input: all clean errors (exit 2, no traceback).
    for label, path in (
            ("text file", os.path.join(BINS, "hardened")),
            ("missing file", os.path.join(BINS, "does_not_exist"))):
        if label == "text file":
            with open(os.path.join(HERE, ".bad.txt"), "w") as fh:
                fh.write("not a binary\n")
            path = os.path.join(HERE, ".bad.txt")
        rc = run([sys.executable, here, path, "-q"])
        check(rc.returncode == 2, "%s exits 2" % label)
        check("Traceback" not in rc.stderr,
              "%s has no traceback" % label)
        if os.path.exists(os.path.join(HERE, ".bad.txt")):
            os.remove(os.path.join(HERE, ".bad.txt"))
    # A PE file with a bad e_lfanew is a clean error too.
    bad = os.path.join(HERE, ".bad.exe")
    with open(bad, "wb") as fh:
        fh.write(b"MZ" + b"\x00" * 62)
    rc = run([sys.executable, here, bad, "-q"])
    check(rc.returncode == 2, "MZ with a bad e_lfanew exits 2")
    check("Traceback" not in rc.stderr,
          "MZ with a bad e_lfanew has no traceback")
    os.remove(bad)
    # Doctor runs.
    rc = run([sys.executable, here, "--check"])
    check(rc.returncode in (0, 1), "doctor runs (exit 0 or 1)")


def oracle_pwntools():
    print("Oracle — pwntools checksec() (test-only)")
    found = pwntools_checksec(os.path.join(BINS, "hardened"))
    if found is None:
        skip("pwntools not importable — readelf is the oracle")
        return
    check("RELRO" in found, "pwntools returns a RELRO line")
    dynamic = ("hardened", "unhardened", "partial_relro", "no_pie",
               "no_canary", "no_nx", "no_fortify", "rpath",
               "runpath", "stripped")
    for name in dynamic:
        found = pwntools_checksec(os.path.join(BINS, name))
        want = pwn_verdicts(found)
        result = cs.analyze_path(os.path.join(BINS, name))
        got = {v["code"]: v["verdict"] for v in result["verdicts"]}
        by_name = {"RELRO": got["CC-001"], "canary": got["CC-002"],
                   "PIE": got["CC-004"], "FORTIFY": got["CC-005"]}
        for key in ("RELRO", "canary", "PIE", "FORTIFY"):
            check(by_name[key] == want[key],
                  "pwntools: %s %s is %s (got %s)"
                  % (name, key, want[key], by_name[key]))
    # pwntools agrees the stripped binary still has its canary.
    # (pwntools' own "Stripped:" line is quirky — it is absent for
    # the stripped binary — so strippedness is checked against
    # readelf -S instead: .symtab must be gone.)
    found = pwntools_checksec(os.path.join(BINS, "stripped"))
    check("Canary found" in found.get("Stack", ""),
          "pwntools agrees the stripped binary has a canary")
    sections = readelf("-S", os.path.join(BINS, "stripped"))
    check(".symtab" not in sections,
          "readelf: stripped has no .symtab section")
    sections = readelf("-S", os.path.join(BINS, "hardened"))
    check(".symtab" in sections,
          "readelf: hardened still has a .symtab section")


def main():
    print("CanarySeeker step tests")
    print("=" * 58)
    step_1()
    step_2()
    step_3()
    step_4()
    step_5()
    step_6()
    step_7()
    step_8()
    step_9()
    cli_bits()
    oracle_pwntools()
    print("=" * 58)
    print("PASSED: %d   FAILED: %d   SKIPPED: %d"
          % (PASSED, FAILED, SKIPPED))
    if FAILED:
        print("Failures:")
        for label in FAILURES:
            print("  - %s" % label)
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
