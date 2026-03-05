#!/usr/bin/env bash
set -euo pipefail

# Usage: ./scripts/build.sh [Debug|Release]
BUILD_TYPE=${1:-Release}

mkdir -p build
cd build
cmake .. -DCMAKE_BUILD_TYPE=${BUILD_TYPE}
cmake --build . -- -j$(nproc)
