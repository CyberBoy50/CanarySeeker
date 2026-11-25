#!/usr/bin/env python3
"""CanarySeeker launcher — setup, check, test, doctor, build-bins,
build-pe, menu.

Usage:
    python run.py setup            # create venv (first time only)
    python run.py check <binary>   # check a binary (flags pass through)
    python run.py test             # run the 8 build-plan step tests
    python run.py doctor           # check the setup
    python run.py build-bins       # regenerate the ELF test binaries
    python run.py build-pe         # regenerate the PE test fixtures
    python run.py menu             # open the numbered menu

Cross-platform: pure Python, Windows/macOS/Linux. Plain
`python3 canaryseeker.py` also works (standard library only).
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def venv_python():
    """Path of the venv Python for this OS, or None if no venv yet."""
    if os.name == "nt":
        cand = os.path.join(HERE, "venv", "Scripts", "python.exe")
    else:
        cand = os.path.join(HERE, "venv", "bin", "python")
    return cand if os.path.isfile(cand) else None


def run(cmd, **kw):
    return subprocess.run(cmd, **kw)


def ensure_venv():
    """Create the venv if needed. Returns the Python to use.
    CanarySeeker uses only the standard library, so there is nothing
    to install — the venv just keeps the setup identical to the other
    tools."""
    vp = venv_python()
    if vp is None:
        print("[*] Creating virtual environment (first time only)...")
        rc = run([sys.executable, "-m", "venv",
                  os.path.join(HERE, "venv")]).returncode
        if rc != 0:
            print("[!] Could not create a venv. Using system Python.")
            return sys.executable
        vp = venv_python()
    print("[*] CanarySeeker needs no packages (standard library only).")
    return vp


def cmd_setup(_args):
    vp = ensure_venv()
    print("[+] Setup done. Python: %s" % vp)
    print("    Test it: python run.py check test_bins/hardened")
    return 0


def cmd_check(args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "canaryseeker.py")]
               + args).returncode


def cmd_test(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "test_canaryseeker.py")]).returncode


def cmd_doctor(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "canaryseeker.py"),
                "--check"]).returncode


def cmd_build_bins(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "build_test_bins.py")]).returncode


def cmd_build_pe(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "build_test_pe.py")]).returncode


def cmd_menu(_args):
    vp = venv_python() or sys.executable
    return run([vp, os.path.join(HERE, "canaryseeker.py"),
                "--menu"]).returncode


def usage():
    print(__doc__.strip())
    return 2


COMMANDS = {
    "setup": cmd_setup,
    "check": cmd_check,
    "test": cmd_test,
    "doctor": cmd_doctor,
    "build-bins": cmd_build_bins,
    "build-pe": cmd_build_pe,
    "menu": cmd_menu,
}


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return usage()
    cmd = argv[0]
    if cmd not in COMMANDS:
        print("[!] Unknown command: %s" % cmd)
        return usage()
    return COMMANDS[cmd](argv[1:])


if __name__ == "__main__":
    sys.exit(main())
