#!/usr/bin/env bash
set -euo pipefail

# Runs the built binary, forwarding all arguments (e.g. ./scripts/run.sh list)
if [ -x build/bin/key_wallet ]; then
  exec ./build/bin/key_wallet "$@"
else
  echo "Binary not found. Run ./scripts/build.sh first."
  exit 1
fi
