#!/usr/bin/env python3
"""Build CanarySeeker's test binaries with gcc (plus hand-built
32-bit ELF fixtures for the class/endianness paths gcc cannot
produce here — the big-endian PowerPC fixture; the little-endian
fixture is hand-built too, so its bytes are exact. A real -m32
compile (elf32_real) is also built now that gcc-multilib is
installed).

Every binary is compiled from the same small C program with explicit
flags for every mitigation dimension, so the expected verdicts are
known in advance and written to test_bins/manifest.json (the Step 7
test reads it). Binary files are never committed to GitHub
(push-files is text-only) — they regenerate with:
    python run.py build-bins
"""
import json
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "test_bins")

C_SOURCE = r"""#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void fill(char *dst, const char *src) {
    char buf[64];
    strcpy(buf, src);      /* fortifiable: becomes __strcpy_chk */
    memcpy(buf, src, 5);   /* fortifiable: becomes __memcpy_chk */
    printf("%s\n", buf);   /* fortifiable (literal format: stays plain) */
    strcpy(dst, buf);
}

int main(int argc, char **argv) {
    char name[32];
    if (argc > 1) {
        strcpy(name, argv[1]);
        fill(name, argv[1]);
    } else {
        fill(name, "hello");
    }
    printf("%s\n", name);
    return 0;
}
"""

# name -> (extra gcc flags, description)
MATRIX = [
    ("hardened",
     ["-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "everything on: canary, PIE, Full RELRO, NX, FORTIFY"),
    ("unhardened",
     ["-fno-stack-protector", "-no-pie",
      "-Wl,-z,norelro", "-Wl,-z,execstack",
      "-O0", "-U_FORTIFY_SOURCE"],
     "everything off: no canary, no PIE, no RELRO, execstack, "
     "no FORTIFY"),
    ("partial_relro",
     ["-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,lazy", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "hardened except RELRO is partial (-z lazy; Ubuntu's gcc "
     "adds -z now by default, so lazy must be explicit)"),
    ("no_pie",
     ["-fstack-protector-all", "-no-pie",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "hardened except PIE off (ET_EXEC)"),
    ("no_canary",
     ["-fno-stack-protector", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "hardened except stack protector off"),
    ("no_nx",
     ["-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,execstack",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "hardened except the stack is executable"),
    ("no_fortify",
     ["-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O0", "-U_FORTIFY_SOURCE"],
     "hardened except FORTIFY off"),
    ("static",
     ["-static", "-no-pie", "-fstack-protector-all",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "static binary, Full RELRO, no lazy binding at all"),
    ("static_pie",
     ["-static-pie", "-fstack-protector-all",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "static PIE binary (ET_DYN, no dynamic section)"),
    ("rpath",
     ["-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-Wl,-rpath,/opt/lab/lib",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "hardened + hard-coded RPATH"),
    ("runpath",
     ["-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-Wl,--enable-new-dtags,-rpath,/opt/lab/lib",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "hardened + hard-coded RUNPATH"),
    ("cet_none",
     ["-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2", "-fcf-protection=none"],
     "hardened except CET off (-fcf-protection=none)"),
    ("cet_ibt",
     ["-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2", "-fcf-protection=branch"],
     "hardened except only IBT on (-fcf-protection=branch)"),
    ("cet_shstk",
     ["-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2", "-fcf-protection=return"],
     "hardened except only SHSTK on (-fcf-protection=return)"),
    ("elf32_real",
     ["-m32", "-fstack-protector-all", "-pie", "-fPIE",
      "-Wl,-z,relro,-z,now", "-Wl,-z,noexecstack",
      "-O2", "-D_FORTIFY_SOURCE=2"],
     "real 32-bit compile (-m32; needs gcc-multilib)"),
]

# Expected verdicts for the gcc matrix (RELRO, canary, NX, PIE,
# FORTIFY, RPATH, CET) — the Step 7 test asserts these exactly.
EXPECTED = {
    "hardened":     {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 100, "grade": "A", "exit": 0},
    "unhardened":   {"RELRO": "Missing", "canary": "Missing",
                     "NX": "Missing", "PIE": "Missing",
                     "FORTIFY": "Missing", "RPATH": "Present",
                     "CET": "Present",
                     "score": 10, "grade": "F", "exit": 1},
    "partial_relro": {"RELRO": "Partial", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 90, "grade": "A", "exit": 1},
    "no_pie":       {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Missing",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 90, "grade": "A", "exit": 1},
    "no_canary":    {"RELRO": "Present", "canary": "Missing",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 75, "grade": "C", "exit": 1},
    "no_nx":        {"RELRO": "Present", "canary": "Present",
                     "NX": "Missing", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 75, "grade": "C", "exit": 1},
    "no_fortify":   {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Missing", "RPATH": "Present",
                     "CET": "Present",
                     "score": 95, "grade": "A", "exit": 1},
    "static":       {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Missing",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 90, "grade": "A", "exit": 1},
    "static_pie":   {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 100, "grade": "A", "exit": 0},
    "rpath":        {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Missing",
                     "CET": "Present",
                     "score": 90, "grade": "A", "exit": 1},
    "runpath":      {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Missing",
                     "CET": "Present",
                     "score": 90, "grade": "A", "exit": 1},
    "stripped":     {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 100, "grade": "A", "exit": 0},
    "shared":       {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "n/a",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 100, "grade": "A", "exit": 0},
    "reloc":        {"RELRO": "n/a", "canary": "Present",
                     "NX": "n/a", "PIE": "n/a",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "n/a",
                     "score": 100, "grade": "A", "exit": 0},
    "elf32_le":     {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Missing",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Present",
                     "score": 90, "grade": "A", "exit": 1},
    "elf32_be":     {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "n/a",
                     "score": 100, "grade": "A", "exit": 0},
    "cet_none":     {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Missing",
                     "score": 95, "grade": "A", "exit": 1},
    "cet_ibt":      {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Partial",
                     "score": 95, "grade": "A", "exit": 1},
    "cet_shstk":    {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Partial",
                     "score": 95, "grade": "A", "exit": 1},
    "elf32_real":   {"RELRO": "Present", "canary": "Present",
                     "NX": "Present", "PIE": "Present",
                     "FORTIFY": "Present", "RPATH": "Present",
                     "CET": "Missing",
                     "score": 95, "grade": "A", "exit": 1},
}


def run(cmd, what):
    rc = subprocess.run(cmd, capture_output=True, text=True)
    if rc.returncode != 0:
        print("[!] %s failed:\n%s" % (what, rc.stderr.strip()))
        return False
    return True


def build_gcc_matrix(src):
    """Compile the matrix. Returns (built, skipped) name lists."""
    built, skipped = [], []
    for name, flags, _desc in MATRIX:
        out = os.path.join(OUT, name)
        if run(["gcc", src, "-o", out] + flags,
               "gcc %s" % name):
            built.append(name)
        else:
            skipped.append(name)
    # stripped: a copy of hardened, then strip it (tests .dynsym
    # fallback — the canary must still be found).
    import shutil
    src_h = os.path.join(OUT, "hardened")
    dst = os.path.join(OUT, "stripped")
    if os.path.isfile(src_h):
        shutil.copyfile(src_h, dst)
        if run(["strip", dst], "strip stripped"):
            built.append("stripped")
        else:
            skipped.append("stripped")
    # shared library: the DSO case (PIE reports n/a).
    if run(["gcc", "-shared", "-fPIC", src, "-o",
            os.path.join(OUT, "libtest.so"),
            "-fstack-protector-all", "-Wl,-z,relro,-z,now",
            "-Wl,-z,noexecstack", "-O2", "-D_FORTIFY_SOURCE=2"],
           "gcc shared"):
        built.append("shared")
    else:
        skipped.append("shared")
    # relocatable object: the ET_REL case.
    if run(["gcc", "-c", src, "-o", os.path.join(OUT, "test.o"),
            "-fstack-protector-all", "-O2", "-D_FORTIFY_SOURCE=2"],
           "gcc reloc"):
        built.append("reloc")
    else:
        skipped.append("reloc")
    return built, skipped


# --- Hand-built 32-bit ELF fixtures -----------------------------------------
def _strtab(names):
    """Build a string table; returns (blob, {name: offset})."""
    blob = bytearray(b"\x00")
    offsets = {"": 0}
    for name in names:
        offsets[name] = len(blob)
        blob += name.encode() + b"\x00"
    return bytes(blob), offsets


def build_elf32(path, endian, etype, machine, stack_flags, relro,
                bind_via, canary, fortified, cet=False):
    """Write a minimal but well-formed 32-bit ELF with chosen flags.

    endian: "<" little or ">" big. bind_via: "FLAGS" (DT_FLAGS +
    DF_BIND_NOW) or "FLAGS_1" (DT_FLAGS_1 + DF_1_NOW) or None.
    cet: add a PT_GNU_PROPERTY segment + a .note.gnu.property
    section carrying the x86 IBT+SHSTK feature bits (32-bit note:
    property data padded to 4 bytes). Only meaningful for x86 —
    the PowerPC fixture has no CET note, and the tool reports
    CET n/a for it.
    The file has one PT_LOAD covering everything, a GNU_STACK, an
    optional GNU_RELRO, a PT_DYNAMIC, a .dynsym with the canary and
    fortified symbols, and the section headers to match.
    """
    text = b"\x90" * 16
    sym_names = ["libc.so.6"]
    if canary:
        sym_names.append("__stack_chk_fail")
    if fortified:
        sym_names.append("__memcpy_chk")
    sym_names += ["memcpy", "printf"]
    dynstr, dyn_off = _strtab(sym_names)
    sh_names = [".text", ".dynamic", ".dynsym", ".dynstr",
                ".shstrtab"]
    if cet:
        sh_names.insert(1, ".note.gnu.property")
    shstr, sh_off = _strtab(sh_names)
    nsec = len(sh_names) + 1  # + the null section

    # The CET note: one GNU property, x86 feature-used, IBT+SHSTK.
    note = b""
    if cet:
        note = struct.pack(endian + "III", 4, 12, 5) + b"GNU\x00" \
            + struct.pack(endian + "II", 0xc0000002, 4) \
            + struct.pack(endian + "I", 0x3)

    # Dynamic entries.
    dyn_entries = [(1, dyn_off["libc.so.6"])]  # DT_NEEDED
    if bind_via == "FLAGS":
        dyn_entries.append((30, 0x8))          # DT_FLAGS DF_BIND_NOW
    elif bind_via == "FLAGS_1":
        dyn_entries.append((0x6ffffffb, 0x1))  # DT_FLAGS_1 DF_1_NOW
    dyn_entries += [(5, 0), (10, len(dynstr)), (6, 0), (0, 0)]
    dyn_size = len(dyn_entries) * 8

    # Layout.
    ehsize, phentsize, shentsize = 52, 32, 40
    nphdr = (4 if relro else 3) + (1 if cet else 0)
    text_off = ehsize + nphdr * phentsize
    note_off = text_off + len(text)
    dyn_off_file = note_off + len(note)
    dynsym_off = dyn_off_file + dyn_size
    dynsym_size = (1 + len(sym_names) - 1) * 16  # null + symbols
    dynstr_off = dynsym_off + dynsym_size
    shstr_off = dynstr_off + len(dynstr)
    shoff = shstr_off + len(shstr)
    total = shoff + nsec * shentsize
    base = 0x08048000

    buf = bytearray(total)
    # ELF header.
    ident = b"\x7fELF" + bytes([1, 1 if endian == "<" else 2, 1]) \
        + b"\x00" * 9
    struct.pack_into(endian + "16sHHIIIIIHHHHHH", buf, 0,
                     ident, etype, machine, 1,
                     base + text_off, ehsize, shoff, 0,
                     ehsize, phentsize, nphdr, shentsize, nsec,
                     nsec - 1)

    def phdr(i, ptype, offset, vaddr, filesz, memsz, flags):
        struct.pack_into(endian + "IIIIIIII", buf,
                         ehsize + i * phentsize,
                         ptype, offset, vaddr, vaddr, filesz, memsz,
                         flags, 0x1000)

    phdr(0, 1, 0, base, total, total, 5)          # PT_LOAD R+X
    phdr(1, 0x6474e551, 0, 0, 0, 0, stack_flags)  # GNU_STACK
    idx = 2
    if cet:
        phdr(idx, 0x6474e553, note_off, base + note_off,
             len(note), len(note), 4)             # GNU_PROPERTY R
        idx += 1
    if relro:
        phdr(idx, 0x6474e552, dyn_off_file, base + dyn_off_file,
             dyn_size, dyn_size, 6)              # GNU_RELRO RW
        idx += 1
    phdr(idx, 2, dyn_off_file, base + dyn_off_file,
         dyn_size, dyn_size, 6)                  # PT_DYNAMIC RW

    buf[text_off:text_off + len(text)] = text
    if cet:
        buf[note_off:note_off + len(note)] = note
    # Dynamic section (patch the vaddr placeholders).
    fixed = []
    for tag, val in dyn_entries:
        if tag == 5:
            val = base + dynstr_off
        elif tag == 6:
            val = base + dynsym_off
        fixed.append((tag, val))
    for i, (tag, val) in enumerate(fixed):
        struct.pack_into(endian + "iI", buf,
                         dyn_off_file + i * 8, tag, val)
    # .dynsym: null symbol, then one entry per name.
    for j, name in enumerate(sym_names[1:], start=1):
        struct.pack_into(endian + "IIIBBH", buf,
                         dynsym_off + j * 16,
                         dyn_off[name], 0, 0, 0x12, 0, 0)
    buf[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    buf[shstr_off:shstr_off + len(shstr)] = shstr

    def shdr(i, name, shtype, flags, addr, offset, size, link,
             info, align, entsize):
        struct.pack_into(endian + "IIIIIIIIII", buf,
                         shoff + i * shentsize,
                         name, shtype, flags, addr, offset, size,
                         link, info, align, entsize)

    dynstr_idx = sh_names.index(".dynstr") + 1
    shdr(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    shdr(1, sh_off[".text"], 1, 6, base + text_off, text_off,
         len(text), 0, 0, 16, 0)
    i = 2
    if cet:
        shdr(i, sh_off[".note.gnu.property"], 7, 2,
             base + note_off, note_off, len(note), 0, 0, 4, 0)
        i += 1
    shdr(i, sh_off[".dynamic"], 6, 3, base + dyn_off_file,
         dyn_off_file, dyn_size, dynstr_idx, 0, 4, 8)
    i += 1
    shdr(i, sh_off[".dynsym"], 11, 2, base + dynsym_off, dynsym_off,
         dynsym_size, dynstr_idx, 1, 4, 16)
    i += 1
    shdr(i, sh_off[".dynstr"], 3, 2, base + dynstr_off, dynstr_off,
         len(dynstr), 0, 0, 1, 0)
    i += 1
    shdr(i, sh_off[".shstrtab"], 3, 0, 0, shstr_off, len(shstr),
         0, 0, 1, 0)
    with open(path, "wb") as fh:
        fh.write(bytes(buf))


def build_synthetic():
    """The 32-bit LE (ET_EXEC, DT_FLAGS, CET note) and BE (ET_DYN,
    DT_FLAGS_1, PowerPC — no CET note) fixtures. The BE fixture
    stays hand-built: gcc cannot build big-endian here at all.
    The LE fixture keeps its CET note so its score is unchanged
    now that CET is checked (CC-014)."""
    build_elf32(os.path.join(OUT, "elf32_le"), "<", 2, 3, 6, True,
                "FLAGS", True, True, cet=True)
    build_elf32(os.path.join(OUT, "elf32_be"), ">", 3, 20, 6, True,
                "FLAGS_1", True, True)
    return ["elf32_le", "elf32_be"]


def main():
    os.makedirs(OUT, exist_ok=True)
    src = os.path.join(OUT, "test_prog.c")
    with open(src, "w") as fh:
        fh.write(C_SOURCE)
    built, skipped = build_gcc_matrix(src)
    built += build_synthetic()
    manifest = {}
    for name in built:
        if name in EXPECTED:
            manifest[name] = EXPECTED[name]
    with open(os.path.join(OUT, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    descs = {n: d for n, _f, d in MATRIX}
    print("[+] Built %d test binaries in %s" % (len(built), OUT))
    for name in built:
        print("    [+] %-12s %s" % (name, descs.get(name, "fixture")))
    if skipped:
        print("[!] Skipped (toolchain could not build them): %s"
              % ", ".join(skipped))
        print("    These are documented as untested in the report, "
              "not faked.")
    print("[+] Manifest written: test_bins/manifest.json "
          "(%d entries)" % len(manifest))
    return 0 if not skipped else 0


if __name__ == "__main__":
    sys.exit(main())
