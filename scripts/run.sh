#!/usr/bin/env bash
set -euo pipefail

# Ejecuta el binario generado
if [ -x build/bin/key_wallet ]; then
  ./build/bin/key_wallet
else
  echo "Binary not found. Run ./scripts/build.sh first."
  exit 1
fi
