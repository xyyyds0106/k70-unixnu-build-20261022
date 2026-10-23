#!/usr/bin/env bash
set -euo pipefail
ulimit -c 0
TASK_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
case "$TASK_ROOT" in /mnt/e/k70ios) ;; *) printf '%s\n' 'This local source test runner requires the E-backed workspace.' >&2; exit 2;; esac
export PYTHONDONTWRITEBYTECODE=1
python3 -B "$TASK_ROOT/tools/xnu-usb-stages/source-tests.py"
