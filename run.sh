#!/bin/sh
# CanarySeeker launcher for macOS/Linux — setup, check, test,
# doctor, build-bins, build-pe, menu. Pure Python, standard library
# only.
# Usage:
#   ./run.sh setup
#   ./run.sh check test_bins/hardened
#   ./run.sh test
#   ./run.sh doctor
#   ./run.sh build-bins
#   ./run.sh build-pe
#   ./run.sh menu
cd "$(dirname "$0")" || exit 1
if [ "$#" -eq 0 ]; then
    python3 run.py
    exit $?
fi
python3 run.py "$@"
exit $?
