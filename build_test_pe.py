#!/usr/bin/env python3
"""Build CanarySeeker's PE test fixtures with a Python PE writer.

No mingw cross-compiler is installed here, so the fixtures are
written by hand: a minimal PE32 / PE32+ with chosen
DllCharacteristics, an optional .reloc section, an optional
RT_MANIFEST resource, and a load config with chosen fields. The
writer is the inverse of the parser in canaryseeker.py — the test
suite reads each fixture back with the tool and checks every verdict
against the flags the writer set (plus a manifest.json of expected
verdicts).

Regenerate with:  python run.py build-pe
"""
import json
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "test_pe")

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

DC_DYNAMIC_BASE = 0x0040
DC_FORCE_INTEGRITY = 0x0080
DC_NX_COMPAT = 0x0100
DC_NO_SEH = 0x0400
DC_HIGH_ENTROPY_VA = 0x0020
DC_GUARD_CF = 0x4000

# Expected verdicts per fixture (ASLR, DEP, CFG, SafeSEH, GS,
# Force Integrity, isolation) — the Step 8 test asserts these.
EXPECTED = {
    "pe64_hardened.exe":   {"ASLR": "Present", "DEP": "Present",
                            "CFG": "Present", "SafeSEH": "n/a",
                            "GS": "Present", "FI": "Present",
                            "Isolation": "Present",
                            "score": 100, "grade": "A", "exit": 0},
    "pe64_unhardened.exe": {"ASLR": "Missing", "DEP": "Missing",
                            "CFG": "Missing", "SafeSEH": "n/a",
                            "GS": "Missing", "FI": "Missing",
                            "Isolation": "Missing",
                            "score": 5, "grade": "F", "exit": 1},
    "pe32_hardened.exe":   {"ASLR": "Present", "DEP": "Present",
                            "CFG": "Present", "SafeSEH": "Present",
                            "GS": "Present", "FI": "Present",
                            "Isolation": "Present",
                            "score": 100, "grade": "A", "exit": 0},
    "pe32_unhardened.exe": {"ASLR": "Missing", "DEP": "Missing",
                            "CFG": "Missing", "SafeSEH": "n/a",
                            "GS": "Missing", "FI": "Missing",
                            "Isolation": "Missing",
                            "score": 5, "grade": "F", "exit": 1},
    "pe64_no_reloc.exe":   {"ASLR": "Present", "DEP": "Present",
                            "CFG": "Present", "SafeSEH": "n/a",
                            "GS": "Present", "FI": "Missing",
                            "Isolation": "Missing",
                            "score": 90, "grade": "A", "exit": 1},
    "pe32_partial_cfg.exe": {"ASLR": "Present", "DEP": "Present",
                            "CFG": "Partial", "SafeSEH": "Present",
                            "GS": "Present", "FI": "Present",
                            "Isolation": "Present",
                            "score": 90, "grade": "A", "exit": 1},
}


def _align(n, a):
    return (n + a - 1) // a * a


def _load_config(is64, cookie, seh_table, seh_count, guard_fn):
    """Load-config bytes with the fields at the spec offsets.

    PE32:  SecurityCookie 60, SEHandlerTable 64, SEHandlerCount 68,
           GuardCFCheckFunctionPointer 72, GuardFlags 88.
    PE32+: SecurityCookie 84, SEHandlerTable 92, SEHandlerCount 100,
           GuardCFCheckFunctionPointer 108, GuardFlags 140.
    """
    if is64:
        size = 0x100
        buf = bytearray(size)
        struct.pack_into("<I", buf, 0, size)
        if cookie is not None:
            struct.pack_into("<Q", buf, 84, cookie)
        if seh_table is not None:
            struct.pack_into("<Q", buf, 92, seh_table)
        if seh_count is not None:
            struct.pack_into("<Q", buf, 100, seh_count)
        if guard_fn is not None:
            struct.pack_into("<Q", buf, 108, guard_fn)
        struct.pack_into("<I", buf, 140, 0x100)
    else:
        size = 0xA0
        buf = bytearray(size)
        struct.pack_into("<I", buf, 0, size)
        if cookie is not None:
            struct.pack_into("<I", buf, 60, cookie)
        if seh_table is not None:
            struct.pack_into("<I", buf, 64, seh_table)
        if seh_count is not None:
            struct.pack_into("<I", buf, 68, seh_count)
        if guard_fn is not None:
            struct.pack_into("<I", buf, 72, guard_fn)
        struct.pack_into("<I", buf, 88, 0x100)
    return bytes(buf)


def _rsrc():
    """A minimal .rsrc section holding one RT_MANIFEST entry.

    Root directory (16 bytes) + one entry (Name=24, OffsetToData
    points at a sub-directory) + a sub-directory (16 bytes) + one
    entry (Name=1, OffsetToData points at a data entry) + a data
    entry (16 bytes: DataRVA, Size, CodePage, Reserved)."""
    root = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
    entry = struct.pack("<II", 24, 0x80000000 | 24)
    sub = struct.pack("<IIHHHH", 0, 0, 0, 0, 0, 1)
    sub_entry = struct.pack("<II", 1, 48)
    data_entry = struct.pack("<IIII", 0x3000, 4, 0, 0)
    return root + entry + sub + sub_entry + data_entry + b"<?xml"


def build_pe(path, is64, dll_chars, has_reloc, has_rsrc, lc):
    """Write one minimal PE file.

    lc: None (no load-config directory) or a dict with cookie,
    seh_table, seh_count, guard_fn (None = field zero).
    """
    sections = []  # (name, vaddr, data)
    vaddr = 0x1000
    text = b"\x90\x90\x90\x90\xcc\xcc\xcc\xcc"
    sections.append((".text", vaddr, text))
    vaddr += SECT_ALIGN
    reloc_rva = 0
    if has_reloc:
        reloc = struct.pack("<II", 0x2000, 10) + b"\x00\x00"
        sections.append((".reloc", vaddr, reloc))
        reloc_rva = vaddr
        vaddr += SECT_ALIGN
    rsrc_rva, rsrc_size = 0, 0
    if has_rsrc:
        rsrc = _rsrc()
        sections.append((".rsrc", vaddr, rsrc))
        rsrc_rva, rsrc_size = vaddr, len(rsrc)
        vaddr += SECT_ALIGN
    lc_rva, lc_size = 0, 0
    if lc is not None:
        lc_bytes = _load_config(is64, lc.get("cookie"),
                                lc.get("seh_table"),
                                lc.get("seh_count"),
                                lc.get("guard_fn"))
        sections.append((".lcfg", vaddr, lc_bytes))
        lc_rva, lc_size = vaddr, len(lc_bytes)
        vaddr += SECT_ALIGN
    image_size = _align(vaddr, SECT_ALIGN)

    opt_size = 240 if is64 else 224
    nsec = len(sections)
    headers_size = _align(0x80 + 4 + 20 + opt_size + nsec * 40,
                          FILE_ALIGN)
    total = headers_size
    for _name, _va, data in sections:
        total += _align(len(data), FILE_ALIGN)

    buf = bytearray(total)
    # DOS header.
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3c, 0x80)
    # PE signature + COFF header.
    struct.pack_into("<4s", buf, 0x80, b"PE\x00\x00")
    machine = 0x8664 if is64 else 0x14c
    struct.pack_into("<HHIIIHH", buf, 0x84, machine, nsec, 0, 0, 0,
                     opt_size, 0x0102)
    opt = 0x80 + 4 + 20
    struct.pack_into("<H", buf, opt, 0x20b if is64 else 0x10b)
    struct.pack_into("<BB", buf, opt + 2, 14, 0)
    struct.pack_into("<III", buf, opt + 4, len(text), 0, 0)
    struct.pack_into("<I", buf, opt + 16, 0x1000)  # entry point
    struct.pack_into("<I", buf, opt + 20, 0x1000)  # base of code
    if is64:
        struct.pack_into("<Q", buf, opt + 24, 0x140000000)
        struct.pack_into("<II", buf, opt + 32, SECT_ALIGN, FILE_ALIGN)
        struct.pack_into("<HHHHHH", buf, opt + 40, 6, 0, 0, 0, 6, 0)
        struct.pack_into("<I", buf, opt + 52, 0)
        struct.pack_into("<I", buf, opt + 56, image_size)
        struct.pack_into("<I", buf, opt + 60, headers_size)
        struct.pack_into("<I", buf, opt + 64, 0)
        struct.pack_into("<HH", buf, opt + 68, 3, dll_chars)
        struct.pack_into("<QQQQ", buf, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<II", buf, opt + 104, 0, 16)
        dd_base = opt + 112
    else:
        struct.pack_into("<I", buf, opt + 24, 0x1000)  # base of data
        struct.pack_into("<I", buf, opt + 28, 0x400000)
        struct.pack_into("<II", buf, opt + 32, SECT_ALIGN, FILE_ALIGN)
        struct.pack_into("<HHHHHH", buf, opt + 40, 6, 0, 0, 0, 6, 0)
        struct.pack_into("<I", buf, opt + 52, 0)
        struct.pack_into("<I", buf, opt + 56, image_size)
        struct.pack_into("<I", buf, opt + 60, headers_size)
        struct.pack_into("<I", buf, opt + 64, 0)
        struct.pack_into("<HH", buf, opt + 68, 3, dll_chars)
        struct.pack_into("<IIII", buf, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<II", buf, opt + 88, 0, 16)
        dd_base = opt + 96
    # Data directories: index 2 = resource, index 10 = load config.
    struct.pack_into("<II", buf, dd_base + 2 * 8, rsrc_rva, rsrc_size)
    struct.pack_into("<II", buf, dd_base + 10 * 8, lc_rva, lc_size)
    # Section headers + raw data.
    sec_off = opt + opt_size
    raw = headers_size
    for i, (name, va, data) in enumerate(sections):
        struct.pack_into("<8sIIII", buf, sec_off + i * 40,
                         name.encode().ljust(8, b"\x00"),
                         len(data), va, _align(len(data), FILE_ALIGN),
                         raw)
        buf[raw:raw + len(data)] = data
        raw += _align(len(data), FILE_ALIGN)
    with open(path, "wb") as fh:
        fh.write(bytes(buf))


def main():
    os.makedirs(OUT, exist_ok=True)
    fixtures = [
        ("pe64_hardened.exe", True,
         DC_DYNAMIC_BASE | DC_HIGH_ENTROPY_VA | DC_NX_COMPAT
         | DC_GUARD_CF | DC_FORCE_INTEGRITY,
         True, True,
         {"cookie": 0x12345678, "seh_table": 0x5000, "seh_count": 2,
          "guard_fn": 0x6000}),
        ("pe64_unhardened.exe", True, 0, False, False, None),
        ("pe32_hardened.exe", False,
         DC_DYNAMIC_BASE | DC_NX_COMPAT | DC_GUARD_CF
         | DC_FORCE_INTEGRITY,
         True, True,
         {"cookie": 0x12345678, "seh_table": 0x5000, "seh_count": 2,
          "guard_fn": 0x6000}),
        ("pe32_unhardened.exe", False, DC_NO_SEH, False, False, None),
        ("pe64_no_reloc.exe", True,
         DC_DYNAMIC_BASE | DC_HIGH_ENTROPY_VA | DC_NX_COMPAT
         | DC_GUARD_CF,
         False, False,
         {"cookie": 0x12345678, "seh_table": None, "seh_count": None,
          "guard_fn": 0x6000}),
        ("pe32_partial_cfg.exe", False,
         DC_DYNAMIC_BASE | DC_NX_COMPAT | DC_GUARD_CF
         | DC_FORCE_INTEGRITY,
         True, True,
         {"cookie": 0x12345678, "seh_table": 0x5000, "seh_count": 2,
          "guard_fn": 0}),
    ]
    manifest = {}
    for name, is64, dc, reloc, rsrc, lc in fixtures:
        build_pe(os.path.join(OUT, name), is64, dc, reloc, rsrc, lc)
        manifest[name] = EXPECTED[name]
        print("    [+] %-22s %s-bit" % (name, 64 if is64 else 32))
    with open(os.path.join(OUT, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    print("[+] Built %d PE fixtures in %s" % (len(fixtures), OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
