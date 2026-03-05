# key_wallet — Dependencies

## Build Tools

| Tool | Minimum Version | Notes |
|------|----------------|-------|
| CMake | 3.10 | Build system generator |
| GCC or Clang | GCC 13 / Clang 17 | C++23 support required |
| Make | any | Or Ninja (`cmake -G Ninja`) |

## System Libraries

| Library | Minimum Version | Why |
|---------|----------------|-----|
| OpenSSL | **3.2** | Argon2id (`OSSL_KDF_NAME_ARGON2ID`) requires 3.2+; also used for AES-256-GCM and `RAND_bytes` |

### Installing OpenSSL 3.2+

**Ubuntu / Debian (24.04+)**
```bash
sudo apt install libssl-dev
```

**Ubuntu 22.04** (ships OpenSSL 3.0 — too old):
```bash
# Build from source or use the backport PPA
sudo apt install -y build-essential wget
wget https://www.openssl.org/source/openssl-3.2.0.tar.gz
tar xf openssl-3.2.0.tar.gz && cd openssl-3.2.0
./Configure --prefix=/usr/local/openssl-3.2 --openssldir=/usr/local/openssl-3.2
make -j$(nproc) && sudo make install
# Then pass -DOPENSSL_ROOT_DIR=/usr/local/openssl-3.2 to cmake
```

**Fedora / RHEL 9+**
```bash
sudo dnf install openssl-devel
```

**macOS (Homebrew)**
```bash
brew install openssl@3
# Pass to cmake: -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
```

## Test Dependencies (auto-fetched)

| Library | Version | How |
|---------|---------|-----|
| Google Test | v1.15.2 | Fetched automatically by CMake `FetchContent` on first configure — no manual install needed |

## Optional System Utilities (Phase 3)

| Tool | Purpose |
|------|---------|
| `xclip` or `xsel` | Clipboard integration on Linux |
| `pbcopy` / `pbpaste` | Clipboard integration on macOS |

## Building

```bash
# Quick build (uses scripts/build.sh)
./scripts/build.sh

# Manual
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Run tests
cd build && ctest --output-on-failure
```

## Verifying Your OpenSSL Version

```bash
openssl version          # must show 3.2.x or higher
pkg-config --modversion libssl
```
