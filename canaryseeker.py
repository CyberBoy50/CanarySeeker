#!/usr/bin/env python3
"""
CanarySeeker — Binary Exploit-Mitigation Checker
PNY Trainings, Binary Security — Final Project

WHAT IT DOES
  You give it a path to a binary. It reads the file's own headers with
  the struct module — no external parser, no readelf, no LIEF, no
  pe-parse — and reports which exploit mitigations are switched on:
  for ELF binaries NX (GNU_STACK), PIE (file type), stack canary
  (__stack_chk_fail symbol), RELRO (GNU_RELRO plus the bind-now flag)
  and fortified functions (*_chk symbols); for PE binaries NX
  (NX_COMPAT), ASLR (DYNAMIC_BASE + HIGH_ENTROPY_VA), CFG (GUARD_CF),
  SafeSEH (load-config SEH handler table), the GS stack cookie, Force
  Integrity and isolation. Every verdict is marked Present, Partial,
  Missing or n/a, with the evidence shown, and the result is saved to
  a report file (text or JSON). A non-zero exit code is returned when
  any mitigation is missing.

  Before anyone analyses a binary, they ask what protections it has.
  This tool answers that question from the bytes themselves.

THE 6 MUST-HAVE FEATURES (PDF) — all in this file:
  1. Parse the ELF header with struct: magic bytes, 32/64-bit class,
     endianness and file type
     -> parse_elf() + Reader
  2. Walk the program headers and report the GNU_STACK segment (NX)
     and the GNU_RELRO segment (RELRO)
     -> parse_program_headers() + analyze_elf()
  3. Read the dynamic section and report the bind-now flag that makes
     RELRO full instead of partial
     -> parse_dynamic() + DT_FLAGS / DT_FLAGS_1
  4. Read the symbol table and report the stack canary symbol and the
     fortified function symbols
     -> parse_symbols() + analyze_canary() + analyze_fortify()
  5. A per-binary verdict table: each mitigation marked present,
     partial or missing, with the evidence shown
     -> print_verdict_table() + write_text_report()
  6. A report saved to a file, plus a non-zero exit code when any
     mitigation is missing
     -> write_text_report() / write_json_report() + exit codes

STRETCH ITEMS (PDF — "if you finish early") — all in this file:
  * PE support — Windows header flags for NX, ASLR, CFG and SafeSEH
    -> parse_pe() + analyze_pe()
  * Batch mode — check every binary in a directory, print a summary
    table
    -> do_batch()
  * JSON report output for use in a pipeline
    -> write_json_report()

BEYOND THE PDF (extra effort — the student this tool is for also
uses AI and is at the user's level, so this build goes further):
  * 32-bit AND 64-bit ELF, both little- and big-endian
    -> the same parser, class + endianness from e_ident
  * Stripped-binary fallback — .dynsym when .symtab is gone
    -> parse_symbols() tries .symtab, then .dynsym, and says which
  * Static-binary handling — no dynamic section is a clean verdict,
    never a crash ("Full (static — no lazy binding)")
  * RPATH/RUNPATH check (checksec parity) — CC-006
  * Fortified count + fortifiable list + Fortify score
    (checksec.py parity)
  * Per-binary hardening score + grade A-F (an EXTRA on top of the
    PDF's present/partial/missing verdicts — the verdicts stay the
    PDF's)
  * --segments and --symbols inspection modes (Step 2's readelf
    comparison, in the tool itself)

INSTALL — the checker needs NOTHING installed:
  plain Python 3 is enough (standard library only). No pip, no venv,
  no binutils, no LIEF. It runs on Windows, macOS and Linux:
    python3 canaryseeker.py test_bins/hardened

USAGE — three ways, same tool:
  Menu (SSTIProbe / TraceRecon style — default when run with no args):
    python run.py menu
    python3 canaryseeker.py --menu
      [ 1] Check a binary (enter path)
      [ 2] Batch check test binaries
      [ 3] Quick check: fully-hardened binary
      [ 4] Quick check: unhardened binary
      [ 5] List all checks
      [ 6] Run the step tests
      [ 7] Check setup (doctor)
      [ 0] Exit
      [ ? ] Select option :

  Interactive prompts (option 1 in the menu asks the same questions):
    python3 canaryseeker.py -i
      [?] ENTER BINARY PATH: test_bins/hardened

  With arguments (for scripts / demo):
    python3 canaryseeker.py test_bins/hardened
    python3 canaryseeker.py test_bins/hardened --json -o report.json
    python3 canaryseeker.py test_bins/ --batch
    python3 canaryseeker.py test_bins/hardened --segments
    python3 canaryseeker.py test_bins/hardened --symbols
"""
import argparse
import json
import os
import struct
import sys
import textwrap

VERSION = "1.1"
AUTHOR = "CyberBoy50"
DISCLAIMER = ("DISCLAIMER — AUTHORIZED USE ONLY. This tool was built for "
              "ethical, authorized security testing only. You are using it "
              "on your own responsibility. The authors are not responsible "
              "for how you use it, or for anything that happens because of "
              "your use. Only test systems, code, and data you own or have "
              "explicit written permission to test — testing anything else "
              "may be illegal (for example, PECA 2016 in Pakistan).")
DEFAULT_OUTPUT = "canaryseeker_report.txt"
QUIET = False


class CanarySeekerError(Exception):
    """A clean, user-facing error — never a traceback."""


# --- Terminal colours (TraceRecon style, green theme) ------------------------
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[1;31m"
    GRN = "\033[1;32m"
    YEL = "\033[1;33m"
    BLU = "\033[1;34m"
    MAG = "\033[1;35m"
    CYN = "\033[1;36m"
    WHT = "\033[1;37m"


RED = C.RED
GREEN = C.GRN
YELLOW = C.YEL
CYAN = C.CYN
BOLD = C.BLD
RESET = C.RST


def clear():
    """Clear the screen — GhostTrack / TraceRecon pattern."""
    os.system("cls" if os.name == "nt" else "clear")


def sep(color=C.GRN, char="─", width=58):
    """A rule line, TraceRecon style."""
    print(f"{color}{char * width}{C.RST}")


def header(title, color=C.GRN):
    """A titled section header with rule lines above and below."""
    sep(color)
    print(f"{color} {title}{C.RST}")
    sep(color)


def ok(msg):
    """[+] success line: ' [+] message' — white brackets, green plus."""
    print(f" {C.WHT}[{C.GRN}+{C.WHT}]{C.RST} {msg}")


def warn(msg):
    """[!] warning line, yellow."""
    print(f" {C.WHT}[{C.YEL}!{C.WHT}]{C.RST} {C.YEL}{msg}{C.RST}")


def err(msg):
    """[x] error line, red."""
    print(f" {C.WHT}[{C.RED}x{C.WHT}]{C.RST} {C.RED}{msg}{C.RST}")


def info(label, value, label_color=C.WHT, val_color=C.GRN):
    """One aligned field — TraceRecon style (label 22 chars)."""
    print(f" {label_color}{label:<22}{C.RST}: {val_color}{value}{C.RST}")


BANNER = r"""
   ____  ___  _   _    _    ______   __ ____  _____ _____ _  _______ ____
  / ___|/ _ \| \ | |  / \  |  _ \ \ / // ___|| ____| ____| |/ / ____|  _ \
 | |   | | | |  \| | / _ \ | |_) \ V / \___ \|  _| |  _| | ' /|  _| | |_) |
 | |___| |_| | |\  |/ ___ \|  _ < | |   ___) | |___| |___| . \| |___|  _ <
  \____|\___/|_| \_/_/   \_\_| \_\|_|  |____/|_____|_____|_|\_\_____|_| \_\

"""


def print_banner():
    if not QUIET:
        print(f"{C.GRN}{BANNER}{C.RST}")
        print(f"{C.WHT}  CanarySeeker v{VERSION} — Binary exploit-mitigation "
              f"checker (ELF + PE){C.RST}")
        print(f"{C.YEL}  AUTHORIZED USE ONLY — only check binaries you built "
              f"or have written permission to test.{C.RST}")
        print(f"{C.DIM}  Checking someone else's software without permission "
              f"is unauthorized access (PECA 2016).{C.RST}")
        for line in textwrap.wrap(DISCLAIMER, width=56):
            print(f"{C.YEL}  {line}{C.RST}")
        print()


# --- Bounds-checked reading --------------------------------------------------
class Reader:
    """A bounds-checked view over a file's bytes.

    Every read is checked against the file length first, so a
    truncated or corrupt binary is a clean CanarySeekerError, never
    a struct.error traceback.
    """

    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def check(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.size:
            raise CanarySeekerError(
                "Truncated file: tried to read %d bytes at offset %d, "
                "file is only %d bytes" % (length, offset, self.size))

    def unpack(self, fmt, offset):
        size = struct.calcsize(fmt)
        self.check(offset, size)
        return struct.unpack_from(fmt, self.data, offset)

    def u8(self, offset):
        return self.unpack("B", offset)[0]

    def u16(self, offset, endian="<"):
        return self.unpack(endian + "H", offset)[0]

    def u32(self, offset, endian="<"):
        return self.unpack(endian + "I", offset)[0]

    def bytes(self, offset, length):
        self.check(offset, length)
        return self.data[offset:offset + length]

    def cstr(self, data, offset):
        """A NUL-terminated string inside a blob (strtab / shstrtab)."""
        if offset < 0 or offset >= len(data):
            return ""
        end = data.find(b"\x00", offset)
        if end < 0:
            end = len(data)
        try:
            return data[offset:end].decode("utf-8", "replace")
        except Exception:
            return ""


# --- Check catalogue ---------------------------------------------------------
# (code, title, description) — CC-001..CC-011 are the PDF's checks plus
# the stretch PE checks; CC-012/CC-013 are beyond-PDF extras.
CHECKS = [
    ("CC-001", "RELRO",
     "GNU_RELRO segment + bind-now flag (Full / Partial / Missing)"),
    ("CC-002", "Stack canary",
     "__stack_chk_fail symbol in .symtab or .dynsym"),
    ("CC-003", "NX (no-execute stack)",
     "GNU_STACK segment without the execute flag"),
    ("CC-004", "PIE",
     "File type ET_DYN (shared libraries report DSO)"),
    ("CC-005", "FORTIFY",
     "Fortified function symbols (*_chk) and the Fortify score"),
    ("CC-006", "RPATH / RUNPATH",
     "Hard-coded library search path in the dynamic section (extra)"),
    ("CC-007", "PE ASLR",
     "DYNAMIC_BASE + HIGH_ENTROPY_VA (with the stripped-relocations "
     "edge case)"),
    ("CC-008", "PE DEP / NX",
     "NX_COMPAT flag in DllCharacteristics"),
    ("CC-009", "PE CFG",
     "GUARD_CF + load-config GuardCFCheckFunctionPointer"),
    ("CC-010", "PE SafeSEH",
     "32-bit only: load-config SEH handler table"),
    ("CC-011", "PE GS stack cookie",
     "Load-config SecurityCookie is non-zero"),
    ("CC-012", "PE Force Integrity",
     "FORCE_INTEGRITY flag in DllCharacteristics (extra)"),
    ("CC-013", "PE isolation",
     "RT_MANIFEST resource present (extra)"),
]

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_LABEL = {"critical": "CRIT", "high": "HIGH",
                  "medium": "MED", "low": "LOW"}

# Fortifiable libc functions (the plain names _FORTIFY_SOURCE replaces
# with a *_chk variant when it can prove the buffer size). Used for the
# Fortify score: fortified / (fortified + fortifiable).
FORTIFIABLE = {
    "memcpy", "memmove", "memset", "mempcpy", "memccpy",
    "strcpy", "strncpy", "strcat", "strncat", "stpcpy", "stpncpy",
    "sprintf", "vsprintf", "snprintf", "vsnprintf",
    "printf", "fprintf", "gets", "fgets", "fgetws",
    "read", "pread", "pread64", "recv", "recvfrom",
    "poll", "ppoll", "getcwd", "realpath", "readlink",
    "gethostname", "getdomainname", "confstr", "getgroups",
    "getlogin", "getwd", "ptsname", "ttyname",
    "wctomb", "mbsrtowcs", "wcrtomb", "mbsnrtowcs", "wcsnrtombs",
    "mbstowcs", "wcstombs", "strtok", "strerror",
}


def sev_color(severity):
    if severity == "high":
        return C.RED
    if severity == "medium":
        return C.YEL
    if severity == "low":
        return C.CYN
    return C.RED


def grade_for(score):
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings):
    """Hardening score (EXTRA, beyond the PDF): 100 minus the
    findings, clamped 0-100. High -25, Medium -10, Low -5."""
    score = 100
    for finding in findings:
        if finding["severity"] == "high":
            score -= 25
        elif finding["severity"] == "medium":
            score -= 10
        elif finding["severity"] == "low":
            score -= 5
    return max(0, min(100, score))


# --- ELF constants -----------------------------------------------------------
ET_NAMES = {0: "ET_NONE", 1: "ET_REL", 2: "ET_EXEC", 3: "ET_DYN",
            4: "ET_CORE"}
EM_NAMES = {3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
            40: "ARM", 43: "SPARC32+", 62: "x86-64", 183: "AArch64",
            243: "RISC-V"}
PT_NAMES = {0: "NULL", 1: "LOAD", 2: "DYNAMIC", 3: "INTERP", 4: "NOTE",
            5: "SHLIB", 6: "PHDR", 7: "TLS",
            0x6474e550: "GNU_EH_FRAME", 0x6474e551: "GNU_STACK",
            0x6474e552: "GNU_RELRO", 0x6474e553: "GNU_PROPERTY"}
PT_NULL, PT_LOAD, PT_DYNAMIC, PT_INTERP = 0, 1, 2, 3
PT_GNU_STACK, PT_GNU_RELRO = 0x6474e551, 0x6474e552
PF_X, PF_W, PF_R = 1, 2, 4
SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB = 2, 11, 3
DT_NULL, DT_NEEDED, DT_STRTAB, DT_STRSZ = 0, 1, 5, 10
DT_SONAME, DT_RPATH, DT_RUNPATH = 14, 15, 29
DT_FLAGS, DT_FLAGS_1 = 30, 0x6ffffffb
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1


def flags_str(flags):
    """Segment flags the way readelf prints them: R, W, E (E for
    execute — readelf's letter, so --segments matches readelf -l
    exactly). The bit itself is still PF_X in the spec."""
    out = ""
    if flags & PF_R:
        out += "R"
    if flags & PF_W:
        out += "W"
    if flags & PF_X:
        out += "E"
    return out or "-"


def parse_elf(data, path):
    """Parse an ELF file with struct only. Returns a dict of facts.

    Raises CanarySeekerError on anything that is not a well-formed
    ELF file (wrong magic, truncated header, bad offsets).
    """
    r = Reader(data)
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise CanarySeekerError(
            "Not an ELF binary: %s does not start with the ELF magic "
            "bytes (\\x7fELF)" % path)
    ei_class = data[4]
    ei_data = data[5]
    if ei_class not in (1, 2):
        raise CanarySeekerError(
            "Unknown ELF class %d in %s (want 1=32-bit or 2=64-bit)"
            % (ei_class, path))
    if ei_data not in (1, 2):
        raise CanarySeekerError(
            "Unknown ELF data encoding %d in %s (want 1=little-endian "
            "or 2=big-endian)" % (ei_data, path))
    is64 = ei_class == 2
    endian = "<" if ei_data == 1 else ">"
    elf = {
        "format": "ELF",
        "is64": is64,
        "endian": "little" if ei_data == 1 else "big",
        "class": 64 if is64 else 32,
        "_data": data,
    }
    if is64:
        (_ident, e_type, e_machine, _ver, _entry, e_phoff, e_shoff,
         _flags, _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = r.unpack(endian + "16sHHIQQQIHHHHHH", 0)
    else:
        (_ident, e_type, e_machine, _ver, _entry, e_phoff, e_shoff,
         _flags, _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = r.unpack(endian + "16sHHIIIIIHHHHHH", 0)
    elf["type"] = e_type
    elf["type_name"] = ET_NAMES.get(e_type, "ET_%d" % e_type)
    elf["machine"] = e_machine
    elf["machine_name"] = EM_NAMES.get(e_machine, "EM_%d" % e_machine)
    elf["phoff"] = e_phoff
    elf["shoff"] = e_shoff

    # --- Extended numbering (rare, but real): e_phnum/e_shnum of 0
    # means the true count lives in section header 0.
    sh0 = None
    if (e_phnum == 0 or e_shnum == 0 or e_shstrndx == 0xffff) and e_shoff:
        sh0 = _read_shdr(r, e_shoff, 0, is64, endian)
    if e_phnum == 0 and sh0 is not None:
        e_phnum = sh0["info"]
    if e_shnum == 0 and sh0 is not None:
        e_shnum = sh0["size"]
    if e_shstrndx == 0xffff and sh0 is not None:
        e_shstrndx = sh0["link"]
    elf["phnum"] = e_phnum
    elf["shnum"] = e_shnum

    elf["segments"] = _parse_program_headers(r, e_phoff, e_phnum,
                                             e_phentsize, is64, endian)
    elf["sections"] = _parse_section_headers(r, e_shoff, e_shnum,
                                             e_shentsize, e_shstrndx,
                                             is64, endian)
    elf["dynamic"] = _parse_dynamic(r, elf["segments"], is64, endian)
    elf["symbols"] = _parse_symbols(r, elf["sections"], is64, endian)
    elf["is_static"] = not any(
        s["type"] == PT_DYNAMIC for s in elf["segments"])
    elf["stripped"] = not any(
        s["name"] == ".symtab" for s in elf["sections"])
    elf["soname"] = _dynamic_string(elf, DT_SONAME)
    elf["is_shared"] = bool(elf["soname"]) or path.endswith(".so")
    elf["needed"] = _dynamic_strings(elf, DT_NEEDED)
    return elf


def _read_shdr(r, shoff, index, is64, endian):
    """Read one section header by index (used for section 0 too)."""
    off = shoff + index * (64 if is64 else 40)
    if is64:
        (name, shtype, _flags, _addr, offset, size, link, info,
         _align, entsize) = r.unpack(endian + "IIQQQQIIQQ", off)
    else:
        (name, shtype, _flags, _addr, offset, size, link, info,
         _align, entsize) = r.unpack(endian + "IIIIIIIIII", off)
    return {"name_off": name, "type": shtype, "offset": offset,
            "size": size, "link": link, "info": info,
            "entsize": entsize}


def _parse_program_headers(r, phoff, phnum, phentsize, is64, endian):
    segments = []
    if phoff == 0 or phnum == 0:
        return segments
    if phentsize < (56 if is64 else 32):
        raise CanarySeekerError(
            "Bad program-header entry size %d" % phentsize)
    for i in range(phnum):
        off = phoff + i * phentsize
        if is64:
            (ptype, flags, offset, vaddr, _paddr, filesz, memsz,
             _align) = r.unpack(endian + "IIQQQQQQ", off)
        else:
            (ptype, offset, vaddr, _paddr, filesz, memsz, flags,
             _align) = r.unpack(endian + "IIIIIIII", off)
        segments.append({
            "type": ptype,
            "type_name": PT_NAMES.get(ptype, "PT_0x%x" % ptype),
            "flags": flags,
            "flags_str": flags_str(flags),
            "offset": offset,
            "vaddr": vaddr,
            "filesz": filesz,
            "memsz": memsz,
        })
    return segments


def _parse_section_headers(r, shoff, shnum, shentsize, shstrndx,
                           is64, endian):
    sections = []
    if shoff == 0 or shnum == 0:
        return sections
    if shentsize < (64 if is64 else 40):
        raise CanarySeekerError(
            "Bad section-header entry size %d" % shentsize)
    raw = []
    for i in range(shnum):
        raw.append(_read_shdr(r, shoff, i, is64, endian))
    shstr = b""
    if 0 <= shstrndx < len(raw):
        s = raw[shstrndx]
        if s["size"]:
            shstr = r.bytes(s["offset"], s["size"])
    for i, s in enumerate(raw):
        sections.append({
            "index": i,
            "name": r.cstr(shstr, s["name_off"]),
            "type": s["type"],
            "offset": s["offset"],
            "size": s["size"],
            "link": s["link"],
            "info": s["info"],
            "entsize": s["entsize"],
        })
    return sections


def _parse_dynamic(r, segments, is64, endian):
    """The dynamic section entries (from the PT_DYNAMIC segment)."""
    entries = []
    dyn = next((s for s in segments if s["type"] == PT_DYNAMIC), None)
    if dyn is None:
        return entries
    fmt = endian + ("qQ" if is64 else "iI")
    size = struct.calcsize(fmt)
    count = dyn["filesz"] // size if size else 0
    for i in range(count):
        tag, val = r.unpack(fmt, dyn["offset"] + i * size)
        if tag == DT_NULL:
            break
        entries.append({"tag": tag, "value": val})
    return entries


def _vaddr_to_offset(segments, vaddr):
    """Map a virtual address to a file offset via PT_LOAD segments."""
    for s in segments:
        if s["type"] != PT_LOAD:
            continue
        if s["vaddr"] <= vaddr < s["vaddr"] + s["memsz"]:
            return s["offset"] + (vaddr - s["vaddr"])
    return None


def _dynamic_string(elf, tag):
    """Resolve one dynamic string tag (RPATH/RUNPATH/SONAME) via
    DT_STRTAB. Returns the string or None."""
    entries = {e["tag"]: e["value"] for e in elf["dynamic"]}
    if tag not in entries or DT_STRTAB not in entries:
        return None
    off = _vaddr_to_offset(elf["segments"], entries[DT_STRTAB])
    if off is None:
        return None
    # The strtab lives in the file; resolve through the raw bytes.
    return _cstr_at_offset(elf, off + entries[tag])


def _cstr_at_offset(elf, offset):
    data = elf.get("_data", b"")
    if offset < 0 or offset >= len(data):
        return None
    end = data.find(b"\x00", offset)
    if end < 0:
        end = len(data)
    try:
        return data[offset:end].decode("utf-8", "replace")
    except Exception:
        return None


def _dynamic_strings(elf, tag):
    entries = [e["value"] for e in elf["dynamic"] if e["tag"] == tag]
    out = []
    for val in entries:
        s = _dynamic_string_value(elf, val)
        if s is not None:
            out.append(s)
    return out


def _dynamic_string_value(elf, stroff):
    entries = {e["tag"]: e["value"] for e in elf["dynamic"]}
    if DT_STRTAB not in entries:
        return None
    off = _vaddr_to_offset(elf["segments"], entries[DT_STRTAB])
    if off is None:
        return None
    return _cstr_at_offset(elf, off + stroff)


def _parse_symbols(r, sections, is64, endian):
    """Symbol names from .symtab (preferred) and .dynsym.

    Returns {"names": [...], "table": "symtab"/"dynsym"/"none",
    "fortified": [...], "from_symtab": bool, "from_dynsym": bool}.
    """
    names = []
    table = "none"
    from_symtab = False
    from_dynsym = False
    for want_type, want_name in ((SHT_SYMTAB, "symtab"),
                                 (SHT_DYNSYM, "dynsym")):
        for sec in sections:
            if sec["type"] != want_type:
                continue
            link = sec["link"]
            if link < 0 or link >= len(sections):
                continue
            strsec = sections[link]
            if strsec["size"] == 0:
                continue
            strtab = r.bytes(strsec["offset"], strsec["size"])
            fmt = endian + ("IBBHQQ" if is64 else "IIIBBH")
            size = struct.calcsize(fmt)
            entsize = sec["entsize"] or size
            if entsize < size or sec["size"] == 0:
                continue
            count = sec["size"] // entsize
            for i in range(count):
                off = sec["offset"] + i * entsize
                if is64:
                    (st_name, _info, _other, _shndx, _val,
                     _sz) = r.unpack(fmt, off)
                else:
                    (st_name, _val, _sz, _info, _other,
                     _shndx) = r.unpack(fmt, off)
                name = r.cstr(strtab, st_name)
                if name:
                    names.append(name)
            if want_name == "symtab":
                from_symtab = True
            else:
                from_dynsym = True
            if table == "none":
                table = want_name
    # De-duplicate, keep order.
    seen = set()
    uniq = []
    for n in names:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    fortified = sorted({n for n in uniq if n.endswith("_chk")})
    return {"names": uniq, "table": table,
            "from_symtab": from_symtab, "from_dynsym": from_dynsym,
            "fortified": fortified}


# --- PE constants ------------------------------------------------------------
PE_MACHINE_NAMES = {0x14c: "i386", 0x8664: "x86-64", 0x1c0: "ARM",
                    0xaa64: "ARM64", 0x200: "IA64"}
IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020
IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080
IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10

# Load-config field offsets (from the PE/COFF spec). The Size field
# guards every read: a field is absent when Size is not past it.
LC32 = {"SecurityCookie": 60, "SEHandlerTable": 64,
        "SEHandlerCount": 68, "GuardCFCheckFunctionPointer": 72,
        "GuardFlags": 88}
LC64 = {"SecurityCookie": 84, "SEHandlerTable": 92,
        "SEHandlerCount": 100, "GuardCFCheckFunctionPointer": 108,
        "GuardFlags": 140}


def parse_pe(data, path):
    """Parse a PE file with struct only. Returns a dict of facts.

    Raises CanarySeekerError on anything that is not a well-formed
    PE file (wrong MZ magic, bad e_lfanew, no PE signature).
    """
    r = Reader(data)
    if len(data) < 64 or data[:2] != b"MZ":
        raise CanarySeekerError(
            "Not a PE binary: %s does not start with the MZ magic "
            "bytes" % path)
    e_lfanew = r.u32(0x3c)
    if e_lfanew < 0 or e_lfanew + 24 > len(data):
        raise CanarySeekerError(
            "Bad PE header offset (e_lfanew=%d) in %s"
            % (e_lfanew, path))
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise CanarySeekerError(
            "Not a PE binary: %s has no PE signature at e_lfanew"
            % path)
    coff = e_lfanew + 4
    (machine, nsec, _tstamp, _psym, _nsym, opt_size,
     _chars) = r.unpack("<HHIIIHH", coff)
    opt = coff + 20
    if opt_size < 2 or opt + opt_size > len(data):
        raise CanarySeekerError(
            "Bad optional-header size %d in %s" % (opt_size, path))
    magic = r.u16(opt)
    if magic == 0x10b:
        is64 = False
    elif magic == 0x20b:
        is64 = True
    else:
        raise CanarySeekerError(
            "Unknown PE optional-header magic 0x%x in %s"
            % (magic, path))
    pe = {"format": "PE", "is64": is64,
          "machine": machine,
          "machine_name": PE_MACHINE_NAMES.get(
              machine, "0x%x" % machine),
          "opt_size": opt_size}
    pe["dll_characteristics"] = r.u16(opt + 70)
    dc = pe["dll_characteristics"]
    # Data directories: PE32 at opt+96, PE32+ at opt+112.
    dd_base = opt + (112 if is64 else 96)
    pe["data_directories"] = []
    for i in range(16):
        off = dd_base + i * 8
        if off + 8 > opt + opt_size:
            break
        rva, size = r.unpack("<II", off)
        pe["data_directories"].append({"rva": rva, "size": size})
    # Section table (40 bytes each, right after the optional header).
    sec_off = opt + opt_size
    pe["sections"] = []
    for i in range(nsec):
        off = sec_off + i * 40
        (raw_name, vsize, vaddr, rawsize,
         rawptr) = r.unpack("<8sIIII", off)
        name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "replace")
        pe["sections"].append({
            "name": name, "vsize": vsize, "vaddr": vaddr,
            "rawsize": rawsize, "rawptr": rawptr})
    pe["has_reloc_section"] = any(
        s["name"] == ".reloc" for s in pe["sections"])
    pe["load_config"] = _parse_load_config(r, pe)
    pe["has_manifest"] = _pe_has_manifest(r, pe)
    return pe


def _rva_to_offset(pe, rva):
    """Map a PE relative virtual address to a file offset."""
    for s in pe["sections"]:
        span = max(s["vsize"], s["rawsize"])
        if s["vaddr"] <= rva < s["vaddr"] + span:
            return s["rawptr"] + (rva - s["vaddr"])
    return None


def _parse_load_config(r, pe):
    """The load-config directory (index 10). Returns a dict of the
    fields we need, or {} when there is no load-config directory."""
    dirs = pe["data_directories"]
    if len(dirs) <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
        return {}
    entry = dirs[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]
    if entry["rva"] == 0 or entry["size"] == 0:
        return {}
    off = _rva_to_offset(pe, entry["rva"])
    if off is None:
        return {}
    try:
        size = r.u32(off)
    except CanarySeekerError:
        return {}
    if size < 4 or size > entry["size"]:
        size = entry["size"]
    lc = {"size": size, "offset": off}
    table = LC64 if pe["is64"] else LC32
    for field, foff in table.items():
        # A field exists only when the directory is big enough.
        width = 8 if (pe["is64"] and field != "GuardFlags") else 4
        if field == "GuardFlags":
            width = 4
        if foff + width > size:
            lc[field] = None
            continue
        try:
            if width == 8:
                lc[field] = r.unpack("<Q", off + foff)[0]
            else:
                lc[field] = r.unpack("<I", off + foff)[0]
        except CanarySeekerError:
            lc[field] = None
    return lc


def _pe_has_manifest(r, pe):
    """True when the resource directory holds an RT_MANIFEST entry
    (type 24). Returns None when the resource directory cannot be
    walked — never guess."""
    dirs = pe["data_directories"]
    if len(dirs) <= IMAGE_DIRECTORY_ENTRY_RESOURCE:
        return False
    entry = dirs[IMAGE_DIRECTORY_ENTRY_RESOURCE]
    if entry["rva"] == 0 or entry["size"] == 0:
        return False
    off = _rva_to_offset(pe, entry["rva"])
    if off is None:
        return None
    try:
        (_chars, _tstamp, _maj, _min, nnamed,
         nid) = r.unpack("<IIHHHH", off)
    except CanarySeekerError:
        return None
    for i in range(nnamed + nid):
        try:
            name, _dataoff = r.unpack("<II", off + 16 + i * 8)
        except CanarySeekerError:
            return None
        # High bit set = the name is a string offset, not an ID.
        if not (name & 0x80000000) and (name & 0xffff) == 24:
            return True
    return False


# --- Format detection --------------------------------------------------------
def load_binary(path):
    """Read a file and return (kind, parsed) where kind is "ELF" or
    "PE". Raises CanarySeekerError on anything else."""
    if not os.path.isfile(path):
        raise CanarySeekerError("No such file: %s" % path)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise CanarySeekerError("Cannot read %s: %s" % (path, exc))
    if len(data) >= 4 and data[:4] == b"\x7fELF":
        return "ELF", parse_elf(data, path)
    if len(data) >= 2 and data[:2] == b"MZ":
        return "PE", parse_pe(data, path)
    raise CanarySeekerError(
        "Not a binary I can check: %s is neither ELF nor PE "
        "(checked the first bytes — this is not a binary file)"
        % path)


# --- Analysis ----------------------------------------------------------------
def _verdict(code, name, verdict, evidence, severity=None, fix=None):
    """One row of the verdict table. severity is the severity of the
    finding when the verdict is Missing/Partial (None otherwise)."""
    return {"code": code, "name": name, "verdict": verdict,
            "evidence": evidence, "severity": severity, "fix": fix}


def _findings_from_verdicts(verdicts):
    """Findings are the Missing/Partial rows that carry a severity."""
    findings = []
    for v in verdicts:
        if v["verdict"] in ("Missing", "Partial") and v["severity"]:
            findings.append({
                "code": v["code"], "title": "%s: %s" % (v["name"],
                                                        v["verdict"]),
                "severity": v["severity"], "evidence": v["evidence"],
                "location": v["name"],
                "fix": v["fix"] or "Rebuild with the mitigation enabled.",
            })
    return findings


def analyze_elf(elf, path):
    """The five ELF mitigations + the RPATH/RUNPATH extra."""
    verdicts = []
    segments = elf["segments"]
    gnu_stack = next((s for s in segments if s["type"] == PT_GNU_STACK),
                     None)
    gnu_relro = next((s for s in segments if s["type"] == PT_GNU_RELRO),
                     None)
    dynamic = {e["tag"]: e["value"] for e in elf["dynamic"]}
    bind_now = bool(dynamic.get(DT_FLAGS, 0) & DF_BIND_NOW) or \
        bool(dynamic.get(DT_FLAGS_1, 0) & DF_1_NOW)
    bind_evidence = None
    if dynamic.get(DT_FLAGS, 0) & DF_BIND_NOW:
        bind_evidence = "DF_BIND_NOW in DT_FLAGS"
    elif dynamic.get(DT_FLAGS_1, 0) & DF_1_NOW:
        bind_evidence = "DF_1_NOW in DT_FLAGS_1"

    # --- CC-001 RELRO ---
    if elf["type"] == 1:  # ET_REL — a relocatable object
        verdicts.append(_verdict(
            "CC-001", "RELRO", "n/a",
            "Relocatable object (ET_REL) — no segments yet."))
    elif elf["type"] == 4:  # ET_CORE — a core dump
        verdicts.append(_verdict(
            "CC-001", "RELRO", "n/a",
            "Core dump (ET_CORE) — RELRO does not apply."))
    elif gnu_relro is None:
        verdicts.append(_verdict(
            "CC-001", "RELRO", "Missing",
            "No GNU_RELRO segment — the GOT is fully writable.",
            "high",
            "Link with -Wl,-z,relro,-z,now for Full RELRO."))
    elif elf["is_static"]:
        verdicts.append(_verdict(
            "CC-001", "RELRO", "Present",
            "GNU_RELRO present; static binary — no lazy binding "
            "exists, so the GOT is read-only at load."))
    elif bind_now:
        verdicts.append(_verdict(
            "CC-001", "RELRO", "Present",
            "GNU_RELRO present + bind-now (%s) — Full RELRO."
            % bind_evidence))
    else:
        verdicts.append(_verdict(
            "CC-001", "RELRO", "Partial",
            "GNU_RELRO present but no bind-now flag — the GOT is "
            "read-only after relocation except .got.plt, which stays "
            "writable for lazy binding.",
            "medium",
            "Link with -Wl,-z,relro,-z,now to make RELRO full."))

    # --- CC-002 Stack canary ---
    syms = elf["symbols"]
    names = set(syms["names"])
    canary = None
    for cand in ("__stack_chk_fail", "__stack_chk_fail_local"):
        if cand in names:
            canary = cand
            break
    if canary:
        verdicts.append(_verdict(
            "CC-002", "Stack canary", "Present",
            "Symbol %s found in .%s."
            % (canary, syms["table"])))
    else:
        verdicts.append(_verdict(
            "CC-002", "Stack canary", "Missing",
            "No __stack_chk_fail symbol in .%s — the binary was not "
            "compiled with stack protection." % syms["table"],
            "high",
            "Compile with -fstack-protector-strong (or -all)."))

    # --- CC-003 NX ---
    if elf["type"] == 1:  # ET_REL — a relocatable object
        verdicts.append(_verdict(
            "CC-003", "NX", "n/a",
            "Relocatable object (ET_REL) — no stack segment yet."))
    elif gnu_stack is None:
        verdicts.append(_verdict(
            "CC-003", "NX", "Missing",
            "No GNU_STACK segment — old linkers default to an "
            "executable stack.",
            "high",
            "Link with -Wl,-z,noexecstack."))
    elif gnu_stack["flags"] & PF_X:
        verdicts.append(_verdict(
            "CC-003", "NX", "Missing",
            "GNU_STACK segment has the execute flag (%s) — the stack "
            "is executable." % gnu_stack["flags_str"],
            "high",
            "Link with -Wl,-z,noexecstack."))
    else:
        verdicts.append(_verdict(
            "CC-003", "NX", "Present",
            "GNU_STACK segment present without the execute flag "
            "(%s) — the stack is not executable."
            % gnu_stack["flags_str"]))

    # --- CC-004 PIE ---
    if elf["type"] == 3:  # ET_DYN
        if elf["is_shared"]:
            verdicts.append(_verdict(
                "CC-004", "PIE", "n/a",
                "Shared library (ET_DYN, SONAME %s) — DSO, "
                "position-independent by nature."
                % (elf["soname"] or "set")))
        else:
            verdicts.append(_verdict(
                "CC-004", "PIE", "Present",
                "File type ET_DYN — position-independent executable."))
    elif elf["type"] == 2:  # ET_EXEC
        verdicts.append(_verdict(
            "CC-004", "PIE", "Missing",
            "File type ET_EXEC — the binary loads at a fixed address.",
            "medium",
            "Compile and link with -pie -fPIE."))
    elif elf["type"] == 1:  # ET_REL
        verdicts.append(_verdict(
            "CC-004", "PIE", "n/a",
            "Relocatable object (ET_REL) — not linked yet."))
    else:
        verdicts.append(_verdict(
            "CC-004", "PIE", "n/a",
            "File type %s — PIE does not apply."
            % elf["type_name"]))

    # --- CC-005 FORTIFY ---
    fortified = syms["fortified"]
    plain = sorted({n for n in names
                    if n in FORTIFIABLE})
    fortifiable = [n for n in plain
                   if "__%s_chk" % n not in names
                   and "%s_chk" % n not in names]
    denom = len(fortified) + len(fortifiable)
    if denom:
        fortify_score = round(100.0 * len(fortified) / denom)
    else:
        fortify_score = None
    if fortified:
        shown = ", ".join(fortified[:6])
        if len(fortified) > 6:
            shown += ", ... (%d total)" % len(fortified)
        verdicts.append(_verdict(
            "CC-005", "FORTIFY", "Present",
            "%d fortified function(s): %s. Fortify score %s%% "
            "(%d fortified, %d still plain)."
            % (len(fortified), shown,
               fortify_score if fortify_score is not None else "n/a",
               len(fortified), len(fortifiable))))
    else:
        verdicts.append(_verdict(
            "CC-005", "FORTIFY", "Missing",
            "No *_chk symbols — no fortified functions. %d "
            "fortifiable function(s) used plainly%s."
            % (len(fortifiable),
               (": " + ", ".join(fortifiable[:6])) if fortifiable
               else ""),
            "low",
            "Compile with -O2 -D_FORTIFY_SOURCE=2."))
    fortify_info = {"fortified": fortified,
                    "fortifiable": fortifiable,
                    "score": fortify_score}

    # --- CC-006 RPATH / RUNPATH (extra) ---
    rpath = _dynamic_string(elf, DT_RPATH)
    runpath = _dynamic_string(elf, DT_RUNPATH)
    if rpath is not None or runpath is not None:
        parts = []
        if rpath is not None:
            parts.append("RPATH=%s" % rpath)
        if runpath is not None:
            parts.append("RUNPATH=%s" % runpath)
        verdicts.append(_verdict(
            "CC-006", "RPATH / RUNPATH", "Missing",
            "Hard-coded library search path: %s — an attacker who "
            "can write there gets their library loaded."
            % "; ".join(parts),
            "medium",
            "Remove RPATH/RUNPATH; use the system library path or "
            "$ORIGIN with care."))
    else:
        verdicts.append(_verdict(
            "CC-006", "RPATH / RUNPATH", "Present",
            "No DT_RPATH or DT_RUNPATH in the dynamic section."))

    findings = _findings_from_verdicts(verdicts)
    score = score_findings(findings)
    return {
        "path": path, "format": "ELF",
        "header": {
            "class": elf["class"], "endian": elf["endian"],
            "type": elf["type_name"], "machine": elf["machine_name"],
            "static": elf["is_static"], "stripped": elf["stripped"],
            "shared": elf["is_shared"],
            "soname": elf["soname"],
            "needed": elf["needed"],
            "symbol_table": elf["symbols"]["table"],
        },
        "segments": elf["segments"],
        "symbols": elf["symbols"],
        "fortify": fortify_info,
        "verdicts": verdicts,
        "findings": findings,
        "score": score, "grade": grade_for(score),
    }


def analyze_pe(pe, path):
    """The PE mitigations (Winchecksec parity)."""
    verdicts = []
    dc = pe["dll_characteristics"]
    lc = pe["load_config"]

    def has(flag):
        return bool(dc & flag)

    # --- CC-007 PE ASLR (incl. High Entropy VA + reloc edge case) ---
    if has(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE):
        if pe["is64"] and not has(
                IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA):
            verdicts.append(_verdict(
                "CC-007", "PE ASLR", "Partial",
                "DYNAMIC_BASE set but HIGH_ENTROPY_VA missing on a "
                "64-bit binary — ASLR works, but with only 8 bits of "
                "entropy in the high half.",
                "medium",
                "Link with /HIGHENTROPYVA (and /DYNAMICBASE)."))
        elif not pe["has_reloc_section"]:
            verdicts.append(_verdict(
                "CC-007", "PE ASLR", "Present",
                "DYNAMIC_BASE set, but no .reloc section — ASLR is "
                "enabled yet ineffective: the image cannot actually "
                "be rebased."))
        else:
            extra = ""
            if pe["is64"]:
                extra = " + HIGH_ENTROPY_VA"
            verdicts.append(_verdict(
                "CC-007", "PE ASLR", "Present",
                "DYNAMIC_BASE set%s; .reloc section present."
                % extra))
    else:
        verdicts.append(_verdict(
            "CC-007", "PE ASLR", "Missing",
            "DYNAMIC_BASE not set — the image loads at a fixed "
            "address.",
            "high",
            "Link with /DYNAMICBASE (and /HIGHENTROPYVA on 64-bit)."))

    # --- CC-008 PE DEP / NX ---
    if has(IMAGE_DLLCHARACTERISTICS_NX_COMPAT):
        verdicts.append(_verdict(
            "CC-008", "PE DEP / NX", "Present",
            "NX_COMPAT set — data execution prevention is on."))
    else:
        verdicts.append(_verdict(
            "CC-008", "PE DEP / NX", "Missing",
            "NX_COMPAT not set — DEP is off.",
            "high",
            "Link with /NXCOMPAT."))

    # SEH status is a precondition for SafeSEH, not a row of its
    # own — it is folded into the SafeSEH evidence below.
    seh_present = not has(IMAGE_DLLCHARACTERISTICS_NO_SEH)

    # --- CC-009 PE CFG ---
    guard_cf = has(IMAGE_DLLCHARACTERISTICS_GUARD_CF)
    check_fn = lc.get("GuardCFCheckFunctionPointer")
    if guard_cf and check_fn:
        verdicts.append(_verdict(
            "CC-009", "PE CFG", "Present",
            "GUARD_CF set and load-config GuardCFCheckFunctionPointer "
            "is 0x%x." % check_fn))
    elif guard_cf:
        verdicts.append(_verdict(
            "CC-009", "PE CFG", "Partial",
            "GUARD_CF set but the load config has no "
            "GuardCFCheckFunctionPointer — CFG is declared, not "
            "enforced.",
            "medium",
            "Link with /GUARD:CF and a load config that carries the "
            "check function."))
    else:
        verdicts.append(_verdict(
            "CC-009", "PE CFG", "Missing",
            "GUARD_CF not set — no control-flow guard.",
            "medium",
            "Link with /GUARD:CF."))

    # --- CC-010 PE SafeSEH (32-bit only) ---
    if pe["is64"]:
        verdicts.append(_verdict(
            "CC-010", "PE SafeSEH", "n/a",
            "64-bit PE — SafeSEH is a 32-bit concept (x64 uses "
            "table-based exception handling)."))
    elif not seh_present:
        verdicts.append(_verdict(
            "CC-010", "PE SafeSEH", "n/a",
            "SEH is disabled (NO_SEH) — SafeSEH does not apply."))
    else:
        table = lc.get("SEHandlerTable")
        count = lc.get("SEHandlerCount")
        if table and count:
            verdicts.append(_verdict(
                "CC-010", "PE SafeSEH", "Present",
                "Load-config SEH handler table present: %d handler(s) "
                "at 0x%x." % (count, table)))
        else:
            verdicts.append(_verdict(
                "CC-010", "PE SafeSEH", "Missing",
                "SEH is on but the load config carries no SEH handler "
                "table — handlers are not registered.",
                "medium",
                "Link with /SAFESEH."))

    # --- CC-011 PE GS stack cookie ---
    cookie = lc.get("SecurityCookie")
    if cookie:
        verdicts.append(_verdict(
            "CC-011", "PE GS cookie", "Present",
            "Load-config SecurityCookie is 0x%x — stack cookies are "
            "in use." % cookie))
    elif not lc:
        verdicts.append(_verdict(
            "CC-011", "PE GS cookie", "Missing",
            "No load-config directory — no SecurityCookie, so no GS "
            "stack cookie.",
            "high",
            "Compile with /GS (the default) and keep the load "
            "config."))
    else:
        verdicts.append(_verdict(
            "CC-011", "PE GS cookie", "Missing",
            "Load-config SecurityCookie is 0 — no GS stack cookie.",
            "high",
            "Compile with /GS."))

    # --- CC-012 PE Force Integrity (extra) ---
    if has(IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY):
        verdicts.append(_verdict(
            "CC-012", "PE Force Integrity", "Present",
            "FORCE_INTEGRITY set — the image must be signed to load."))
    else:
        verdicts.append(_verdict(
            "CC-012", "PE Force Integrity", "Missing",
            "FORCE_INTEGRITY not set — the image loads unsigned.",
            "low",
            "Link with /INTEGRITYCHECK."))

    # --- CC-013 PE isolation (extra) ---
    manifest = pe["has_manifest"]
    if manifest is True:
        verdicts.append(_verdict(
            "CC-013", "PE isolation", "Present",
            "RT_MANIFEST resource present — the binary carries its "
            "own activation manifest."))
    elif manifest is False:
        verdicts.append(_verdict(
            "CC-013", "PE isolation", "Missing",
            "No RT_MANIFEST resource — the binary has no activation "
            "manifest.",
            "low",
            "Embed an application manifest (/MANIFEST)."))
    else:
        verdicts.append(_verdict(
            "CC-013", "PE isolation", "n/a",
            "The resource directory could not be walked — manifest "
            "status unknown (not guessed)."))

    findings = _findings_from_verdicts(verdicts)
    score = score_findings(findings)
    return {
        "path": path, "format": "PE",
        "header": {
            "machine": pe["machine_name"],
            "bits": 64 if pe["is64"] else 32,
            "dll_characteristics": "0x%04x" % dc,
            "has_reloc_section": pe["has_reloc_section"],
            "has_load_config": bool(lc),
        },
        "sections": pe["sections"],
        "load_config": {k: (("0x%x" % v) if isinstance(v, int) else v)
                        for k, v in lc.items()},
        "verdicts": verdicts,
        "findings": findings,
        "score": score, "grade": grade_for(score),
    }


def analyze_path(path):
    """Detect the format, parse, and analyze one file."""
    kind, parsed = load_binary(path)
    if kind == "ELF":
        return analyze_elf(parsed, path)
    return analyze_pe(parsed, path)


def analyze_paths(paths):
    """Analyze many files; non-binaries are reported as skipped,
    never as errors that stop the batch."""
    results = []
    skipped = []
    for path in paths:
        try:
            results.append(analyze_path(path))
        except CanarySeekerError as exc:
            skipped.append({"path": path, "reason": str(exc)})
    return results, skipped


# --- Reports -----------------------------------------------------------------
def result_to_json(result):
    """One result as a JSON-ready dict (verdicts + findings + info)."""
    out = {
        "file": result["path"],
        "format": result["format"],
        "header": result["header"],
        "score": result["score"],
        "grade": result["grade"],
        "verdicts": [
            {"code": v["code"], "check": v["name"],
             "verdict": v["verdict"], "evidence": v["evidence"],
             "severity": v["severity"], "fix": v["fix"]}
            for v in result["verdicts"]
        ],
        "findings": [
            {"code": f["code"], "title": f["title"],
             "severity": f["severity"], "evidence": f["evidence"],
             "location": f["location"], "fix": f["fix"]}
            for f in result["findings"]
        ],
    }
    if "fortify" in result:
        out["fortify"] = result["fortify"]
    return out


def build_report_text(results, skipped):
    """The text report for one or many results."""
    import datetime
    lines = []
    lines.append("CanarySeeker v%s — Binary Exploit-Mitigation Checker"
                 % VERSION)
    lines.append("by %s — AUTHORIZED USE ONLY" % AUTHOR)
    lines.append(DISCLAIMER)
    lines.append("=" * 58)
    lines.append("Scanned: %s"
                 % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    lines.append("Binaries: %d (%d skipped)"
                 % (len(results), len(skipped)))
    lines.append("")
    for result in results:
        lines.append("Binary: %s" % result["path"])
        lines.append("Format: %s" % result["format"])
        hdr = result["header"]
        if result["format"] == "ELF":
            lines.append(
                "Header: %d-bit %s, %s, %s%s%s" % (
                    hdr["class"], hdr["endian"], hdr["type"],
                    hdr["machine"],
                    ", static" if hdr["static"] else "",
                    ", stripped" if hdr["stripped"] else ""))
            lines.append("Symbol table: .%s" % hdr["symbol_table"])
            if hdr["needed"]:
                lines.append("Needed libraries: %s"
                             % ", ".join(hdr["needed"]))
            if "fortify" in result:
                f = result["fortify"]
                lines.append(
                    "Fortify: %d fortified, %d fortifiable, score %s"
                    % (len(f["fortified"]), len(f["fortifiable"]),
                       ("%d%%" % f["score"]) if f["score"] is not None
                       else "n/a"))
        else:
            lines.append(
                "Header: PE %d-bit, %s, DllCharacteristics %s%s" % (
                    hdr["bits"], hdr["machine"],
                    hdr["dll_characteristics"],
                    ", .reloc present" if hdr["has_reloc_section"]
                    else ", no .reloc section"))
        lines.append("")
        lines.append("Verdict table")
        lines.append("-" * 58)
        for v in result["verdicts"]:
            lines.append("  [%s] %-18s %-8s %s" % (
                v["code"], v["name"], v["verdict"], v["evidence"]))
        lines.append("")
        lines.append("Findings (%d)" % len(result["findings"]))
        lines.append("-" * 58)
        if not result["findings"]:
            lines.append("  No findings — every applicable mitigation "
                         "is present.")
        for f in result["findings"]:
            lines.append("  [%s] [%s] %s" % (
                SEVERITY_LABEL[f["severity"]], f["code"], f["title"]))
            lines.append("      Evidence: %s" % f["evidence"])
            lines.append("      Fix: %s" % f["fix"])
        lines.append("")
        lines.append("Hardening score: %d/100 (grade %s) — extra, "
                     "beyond the PDF" % (result["score"],
                                         result["grade"]))
        lines.append("")
        lines.append("=" * 58)
        lines.append("")
    if skipped:
        lines.append("Skipped (%d)" % len(skipped))
        lines.append("-" * 58)
        for s in skipped:
            lines.append("  %s — %s" % (s["path"], s["reason"]))
        lines.append("")
    lines.append("End of report — CanarySeeker v%s by %s"
                 % (VERSION, AUTHOR))
    return "\n".join(lines) + "\n"


def build_report_json(results, skipped):
    doc = {
        "tool": "CanarySeeker",
        "version": VERSION,
        "author": AUTHOR,
        "disclaimer": DISCLAIMER,
        "results": [result_to_json(r) for r in results],
        "skipped": skipped,
    }
    return json.dumps(doc, indent=2) + "\n"


def write_report(results, skipped, output, as_json):
    """Write the report file; returns the path written."""
    text = build_report_json(results, skipped) if as_json else \
        build_report_text(results, skipped)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(text)
    return output


# --- Terminal output ---------------------------------------------------------
def print_config(path, output, as_json, min_severity, recursive=False):
    """Gobuster-style SCAN config block before each check."""
    if QUIET:
        return
    sep()
    print(f" {C.WHT}[ {C.GRN}SCAN {C.WHT}] {C.GRN}CanarySeeker v{VERSION}"
          f"{C.RST}")
    sep()
    info("Target", path)
    info("Output", "%s (%s)" % (output, "JSON" if as_json else "text"))
    info("Min severity", min_severity)
    if recursive:
        info("Recursive", "yes")
    sep()


def verdict_color(verdict):
    if verdict == "Present":
        return C.GRN
    if verdict == "Partial":
        return C.YEL
    if verdict == "Missing":
        return C.RED
    return C.CYN


def print_verdict_table(result):
    """The per-binary verdict table, checksec style."""
    if QUIET:
        return
    header("Verdict table — %s" % os.path.basename(result["path"]))
    for v in result["verdicts"]:
        color = verdict_color(v["verdict"])
        print(f" {C.WHT}[{color}{v['verdict']:<8}{C.WHT}]{C.RST} "
              f"{C.GRN}[{v['code']}] {v['name']:<18}{C.RST}")
        print(f"      {C.DIM}{v['evidence']}{C.RST}")
    sep()
    info("Hardening score",
         "%d/100 (grade %s)" % (result["score"], result["grade"]))
    info("Findings", "%d (%s)" % (
        len(result["findings"]),
        ", ".join("%d %s" % (
            sum(1 for f in result["findings"]
                if f["severity"] == sev), sev)
            for sev in ("high", "medium", "low")
            if any(f["severity"] == sev for f in result["findings"]))
        or "none"))


def print_findings(result, min_severity):
    """Print the findings section to the terminal."""
    if QUIET:
        return
    shown = [f for f in result["findings"]
             if SEVERITY_ORDER[f["severity"]] >=
             SEVERITY_ORDER[min_severity]]
    header("Findings (%d: %d high, %d medium, %d low)" % (
        len(result["findings"]),
        sum(1 for f in result["findings"] if f["severity"] == "high"),
        sum(1 for f in result["findings"]
            if f["severity"] == "medium"),
        sum(1 for f in result["findings"] if f["severity"] == "low")))
    if not shown:
        ok("No findings at this severity — every applicable "
           "mitigation is present.")
        return
    for finding in shown:
        color = sev_color(finding["severity"])
        print(f" {C.WHT}[{color}{SEVERITY_LABEL[finding['severity']]}"
              f"{C.WHT}] {C.GRN}[{finding['code']}]{C.RST} "
              f"{finding['title']}")
        print(f"      {C.DIM}Evidence: {finding['evidence']}{C.RST}")
        print(f"      {C.DIM}Fix: {finding['fix']}{C.RST}")
    if len(shown) != len(result["findings"]):
        warn("%d finding(s) hidden by --min-severity."
             % (len(result["findings"]) - len(shown)))


def print_batch_summary(results, skipped):
    """The batch summary table: one line per binary."""
    if QUIET:
        return
    header("Batch summary (%d binaries, %d skipped)"
           % (len(results), len(skipped)))
    print(f"  {'File':<28} {'Fmt':<4} {'Score':<7} {'Grade':<6} "
          f"{'Missing':<8}")
    sep(C.DIM)
    for r in results:
        name = os.path.basename(r["path"])
        if len(name) > 28:
            name = name[:25] + "..."
        missing = sum(1 for v in r["verdicts"]
                      if v["verdict"] in ("Missing", "Partial"))
        print(f"  {name:<28} {r['format']:<4} {r['score']:<7} "
              f"{r['grade']:<6} {missing:<8}")
    sep(C.DIM)
    if skipped:
        for s in skipped:
            warn("Skipped %s — %s" % (s["path"], s["reason"]))
    if results:
        worst = min(results, key=lambda r: r["score"])
        best = max(results, key=lambda r: r["score"])
        info("Worst", "%s (%d/100, grade %s)"
             % (os.path.basename(worst["path"]), worst["score"],
                worst["grade"]))
        info("Best", "%s (%d/100, grade %s)"
             % (os.path.basename(best["path"]), best["score"],
                best["grade"]))


def print_checks():
    """--list-checks: the check catalogue."""
    header("CanarySeeker checks (%d)" % len(CHECKS))
    for code, title, desc in CHECKS:
        print(f" {C.WHT}[{C.GRN}{code}{C.WHT}]{C.RST} {title}")
        print(f"      {C.DIM}{desc}{C.RST}")


def print_segments(path):
    """--segments: every program header (ELF) or section (PE)."""
    kind, parsed = load_binary(path)
    header("Segments — %s" % os.path.basename(path))
    if kind == "ELF":
        for s in parsed["segments"]:
            print(f"  {s['type_name']:<12} flags {s['flags_str']:<4} "
                  f"offset 0x{s['offset']:x} filesz {s['filesz']}")
    else:
        for s in parsed["sections"]:
            print(f"  {s['name']:<10} vaddr 0x{s['vaddr']:x} "
                  f"rawsize {s['rawsize']}")
    sep()
    return 0


def print_symbols(path):
    """--symbols: every symbol name in the binary."""
    kind, parsed = load_binary(path)
    header("Symbols — %s" % os.path.basename(path))
    if kind == "ELF":
        syms = parsed["symbols"]
        info("Symbol table", ".%s" % syms["table"])
        for name in syms["names"]:
            print("  %s" % name)
        info("Total", "%d symbols (%d fortified)"
             % (len(syms["names"]), len(syms["fortified"])))
    else:
        warn("PE binaries have no symbol table in this tool — the "
             "load-config checks are the PE equivalent.")
    sep()
    return 0


# --- Doctor ------------------------------------------------------------------
def doctor():
    """Check the setup: Python, gcc, readelf, strip, oracles, fixtures."""
    print_banner()
    header("Doctor — check setup")
    problems = 0
    import shutil
    info("Platform", "%s (%s)" % (sys.platform, os.name))
    ok("Python %s" % sys.version.split()[0])
    for tool in ("gcc", "readelf", "strip"):
        path = shutil.which(tool)
        if path:
            ok("%s: %s" % (tool, path))
        else:
            warn("%s not found — test-binary generation needs it."
                 % tool)
            problems += 1
    if shutil.which("checksec"):
        ok("checksec: %s" % shutil.which("checksec"))
    else:
        warn("checksec not found (optional — readelf is the oracle).")
    if shutil.which("x86_64-w64-mingw32-gcc"):
        ok("x86_64-w64-mingw32-gcc: %s"
           % shutil.which("x86_64-w64-mingw32-gcc"))
    else:
        warn("x86_64-w64-mingw32-gcc not found (optional — PE "
             "fixtures are built by the Python writer).")
    try:
        import pwn  # noqa: F401 - availability check
        ok("pwntools available (second oracle).")
    except ImportError:
        warn("pwntools not importable from this Python "
             "(optional — readelf is the oracle).")
    here = os.path.dirname(os.path.abspath(__file__))
    for label, rel in (
            ("test-binary generator", "build_test_bins.py"),
            ("PE fixture writer", "build_test_pe.py"),
            ("step tests", "test_canaryseeker.py"),
            ("hardened test binary", "test_bins/hardened"),
            ("unhardened test binary", "test_bins/unhardened")):
        full = os.path.join(here, rel)
        if os.path.isfile(full):
            ok("%s: %s" % (label, rel))
        else:
            warn("%s missing: %s (run: python run.py build-bins)"
                 % (label, rel))
            problems += 1
    try:
        probe = os.path.join(here, ".doctor_write_test")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.remove(probe)
        ok("Can write report files here.")
    except OSError as exc:
        err("Cannot write here: %s" % exc)
        problems += 1
    sep()
    if problems:
        warn("Doctor: %d problem(s) — see above." % problems)
        return 1
    ok("Doctor: all good.")
    return 0


# --- Scan drivers ------------------------------------------------------------
def exit_code_for(results, fail_on):
    """0 = all mitigations present; 1 = any missing/partial;
    2 = a --fail-on hit (overrides the 1)."""
    worst = 0
    for r in results:
        if r["findings"]:
            worst = max(worst, 1)
    if fail_on and fail_on != "none":
        for r in results:
            for f in r["findings"]:
                if SEVERITY_ORDER[f["severity"]] >= \
                        SEVERITY_ORDER[fail_on]:
                    return 2
    return worst


def do_single(args, path):
    """Check one binary: config block, verdict table, findings,
    report file. Returns the exit code."""
    print_config(path, args.output, args.json, args.min_severity)
    try:
        result = analyze_path(path)
    except CanarySeekerError as exc:
        err(str(exc))
        return 2
    print_verdict_table(result)
    print_findings(result, args.min_severity)
    write_report([result], [], args.output, args.json)
    ok("Report saved: %s" % args.output)
    return exit_code_for([result], args.fail_on)


def do_batch(args, paths):
    """Check many files: per-binary tables, then the summary table
    and one report file. Returns the exit code."""
    print_config("%d file(s)" % len(paths), args.output, args.json,
                 args.min_severity, recursive=args.recursive)
    results, skipped = analyze_paths(paths)
    for result in results:
        print_verdict_table(result)
        print_findings(result, args.min_severity)
    print_batch_summary(results, skipped)
    write_report(results, skipped, args.output, args.json)
    ok("Report saved: %s" % args.output)
    return exit_code_for(results, args.fail_on)


def collect_paths(target, recursive):
    """Every file under a directory (or the single file itself)."""
    if os.path.isfile(target):
        return [target]
    if not os.path.isdir(target):
        raise CanarySeekerError("No such file or directory: %s"
                                % target)
    paths = []
    if recursive:
        for root, _dirs, files in os.walk(target):
            for name in sorted(files):
                paths.append(os.path.join(root, name))
    else:
        for name in sorted(os.listdir(target)):
            full = os.path.join(target, name)
            if os.path.isfile(full):
                paths.append(full)
    return paths


def fixture_path(name):
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "test_bins", name)


def ensure_fixtures():
    """Build the test binaries if they are missing."""
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    need = not (os.path.isfile(fixture_path("hardened"))
                and os.path.isfile(fixture_path("unhardened")))
    if not need:
        return True
    warn("Test binaries missing — building them now "
         "(python run.py build-bins) ...")
    rc = subprocess.run(
        [sys.executable, os.path.join(here, "build_test_bins.py")]
    ).returncode
    if rc != 0:
        err("Could not build the test binaries.")
        return False
    rc = subprocess.run(
        [sys.executable, os.path.join(here, "build_test_pe.py")]
    ).returncode
    if rc != 0:
        warn("PE fixtures could not be built — ELF fixtures are "
             "ready; PE checks will be skipped.")
    return True


def quick_check(args, name, label):
    """Menu quick-check: one named test binary."""
    if not ensure_fixtures():
        return 2
    args.output = args.output or DEFAULT_OUTPUT
    print_banner()
    return do_single(args, fixture_path(name))


# --- Menu ----------------------------------------------------------------------
def show_menu():
    clear()
    print_banner()
    print(f" {C.WHT}[ {C.GRN}1 {C.WHT}] {C.GRN}Check a binary "
          f"(enter path){C.RST}")
    print(f" {C.WHT}[ {C.GRN}2 {C.WHT}] {C.GRN}Batch check test "
          f"binaries{C.RST}")
    print(f" {C.WHT}[ {C.GRN}3 {C.WHT}] {C.GRN}Quick check: "
          f"fully-hardened binary{C.RST}")
    print(f" {C.WHT}[ {C.GRN}4 {C.WHT}] {C.GRN}Quick check: "
          f"unhardened binary{C.RST}")
    print(f" {C.WHT}[ {C.GRN}5 {C.WHT}] {C.GRN}List all checks"
          f"{C.RST}")
    print(f" {C.WHT}[ {C.GRN}6 {C.WHT}] {C.GRN}Run the step tests"
          f"{C.RST}")
    print(f" {C.WHT}[ {C.GRN}7 {C.WHT}] {C.GRN}Check setup (doctor)"
          f"{C.RST}")
    print(f" {C.WHT}[ {C.RED}0 {C.WHT}] {C.RED}Exit{C.RST}")
    print()


def ask_interactive(label, default):
    """One [?] prompt with a default (Enter keeps the default)."""
    try:
        value = input(f"{C.WHT}\n [ ? ] {C.GRN}{label}{C.WHT} "
                      f"[{default}]: {C.GRN}").strip()
    except KeyboardInterrupt:
        print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
        raise
    print(C.RST, end="")
    return value or default


def menu_loop(args):
    """Numbered menu loop. Returns 0 on clean exit."""
    import time as _time
    while True:
        show_menu()
        try:
            choice = input(
                f"{C.WHT}\n [ ? ] {C.GRN}Select option{C.WHT} : "
                f"{C.GRN}").strip()
            print(C.RST, end="")
            if choice == "0":
                print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
                return 0
            if choice == "1":
                args.target = ask_interactive(
                    "ENTER BINARY PATH", fixture_path("hardened"))
                args.output = args.output or DEFAULT_OUTPUT
                return do_single(args, args.target)
            if choice == "2":
                if not ensure_fixtures():
                    return 2
                args.output = args.output or DEFAULT_OUTPUT
                here = os.path.dirname(os.path.abspath(__file__))
                paths = collect_paths(
                    os.path.join(here, "test_bins"), False)
                paths += collect_paths(
                    os.path.join(here, "test_pe"), False) \
                    if os.path.isdir(os.path.join(here, "test_pe")) \
                    else []
                return do_batch(args, paths)
            if choice == "3":
                return quick_check(args, "hardened",
                                   "fully-hardened binary")
            if choice == "4":
                return quick_check(args, "unhardened",
                                   "unhardened binary")
            if choice == "5":
                print_banner()
                print_checks()
            elif choice == "6":
                return run_step_tests()
            elif choice == "7":
                return doctor()
            else:
                err("Please input a number from the menu (0-7).")
                _time.sleep(1)
                continue
        except ValueError:
            err("Please input a number from the menu (0-7).")
            _time.sleep(1)
            continue
        except KeyboardInterrupt:
            print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
            return 0
        input(f"\n{C.WHT}[ {C.GRN}+ {C.WHT}] {C.GRN}Press enter to "
              f"continue{C.RST}")
    return 0


def run_step_tests():
    """Menu option 6: run the step-test suite in a subprocess."""
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(here, "test_canaryseeker.py")
    if not os.path.isfile(test_file):
        err("Step tests missing: %s" % test_file)
        return 2
    return subprocess.run(
        [sys.executable, test_file]).returncode


# --- CLI -----------------------------------------------------------------------
def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="canaryseeker",
        description="CanarySeeker v%s — binary exploit-mitigation "
                    "checker (hand-written ELF + PE parsers, zero "
                    "dependencies)." % VERSION)
    parser.add_argument("target", nargs="?", default=None,
                        help="binary file (or directory, for batch mode)")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT,
                        help="report file (default: %(default)s)")
    parser.add_argument("--json", action="store_true",
                        help="write the report as JSON instead of text")
    parser.add_argument("--batch", action="store_true",
                        help="batch mode: check every binary in a "
                             "directory (a directory target implies it)")
    parser.add_argument("--recursive", action="store_true",
                        help="recurse into subdirectories in batch mode")
    parser.add_argument("--segments", action="store_true",
                        help="list program headers (ELF) or sections "
                             "(PE) and exit")
    parser.add_argument("--symbols", action="store_true",
                        help="list all symbol names and exit")
    parser.add_argument("--min-severity",
                        choices=["high", "medium", "low"],
                        default="low",
                        help="only display findings at or above this "
                             "severity (default: low)")
    parser.add_argument("--fail-on",
                        choices=["high", "medium", "low", "none"],
                        default="none",
                        help="exit 2 when a finding at or above this "
                             "severity exists (default: none — findings "
                             "exit 1)")
    parser.add_argument("--check", action="store_true",
                        help="doctor: check the setup and exit")
    parser.add_argument("--skip-check", action="store_true",
                        help="(accepted for family parity; no-op)")
    parser.add_argument("--list-checks", action="store_true",
                        help="list all checks and exit")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="quiet: no banner, no progress, report only")
    parser.add_argument("-i", "--interactive", "--menu",
                        action="store_true", dest="menu",
                        help="open the numbered menu")
    parser.add_argument("--version", action="store_true",
                        help="print the version and exit")
    parser.add_argument("--no-color", action="store_true",
                        help="disable coloured output")
    return parser.parse_args(argv)


def main(argv=None):
    global QUIET
    args = parse_args(argv)
    if args.no_color:
        for name in ("RST", "BLD", "DIM", "RED", "GRN", "YEL", "BLU",
                     "MAG", "CYN", "WHT"):
            setattr(C, name, "")
    if args.version:
        print("CanarySeeker v%s by %s" % (VERSION, AUTHOR))
        return 0
    if args.quiet:
        QUIET = True
    try:
        if args.check:
            return doctor()
        if args.list_checks:
            print_banner()
            print_checks()
            return 0
        if args.menu or (args.target is None and not args.batch):
            print_banner()
            return menu_loop(args)
        if args.target is None:
            err("No binary or directory given. "
                "Run with --menu, or give a path.")
            return 2
        if args.segments:
            return print_segments(args.target)
        if args.symbols:
            return print_symbols(args.target)
        is_dir = os.path.isdir(args.target)
        if args.batch or is_dir:
            paths = collect_paths(args.target, args.recursive)
            if not paths:
                err("Nothing to check in %s" % args.target)
                return 2
            return do_batch(args, paths)
        return do_single(args, args.target)
    except CanarySeekerError as exc:
        err(str(exc))
        return 2
    except KeyboardInterrupt:
        print(f"\n{C.WHT}[ {C.RED}! {C.WHT}] {C.RED}Exit{C.RST}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
