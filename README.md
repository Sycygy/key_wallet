# key_wallet

A local, CLI-first password manager written in C++23 on top of OpenSSL 3.2+.

Credentials are stored in a fully encrypted binary vault on disk. There is no network access, no cloud sync and no telemetry: the vault file never leaves your machine.

> **Disclaimer:** key_wallet is an educational project built for an Applied Cryptography course. It has not been independently audited. Do not rely on it as your only password manager.

## Features

- **Argon2id master key derivation**: m = 64 MiB, t = 3, p = 4, with a random 16-byte salt per vault.
- **Per-entry keys**: every password is encrypted under its own key, derived with HKDF-SHA256 from the vault key and the entry's UUID.
- **AES-256-GCM everywhere**: the vault header (magic, version, salt, KDF parameters) is authenticated as AAD on every ciphertext, so tampering or a silent KDF downgrade is detected.
- **Passwords stay on disk until needed**: unlocking decrypts only the index (names, websites, usernames). A single password is decrypted on demand, and only after you re-enter the master password.
- **Memory hygiene**: secrets live in OpenSSL's secure heap (mlock'd, excluded from core dumps) and are wiped with `OPENSSL_cleanse()`. The process disables core dumps and ptrace at startup.
- **Crash-safe saves**: the vault is written to a temporary file and atomically `rename()`d into place.
- **Expiry policies**: optional master password rotation (hard block once expired, warning 7 days before) and per-entry expiry dates (warning only).
- **Auto-lock** after a period of inactivity.
- **Password generator** using rejection sampling, so there is no modulo bias.

## Requirements

- Linux (process hardening uses `prctl`)
- A C++23 compiler (GCC 13+ or Clang 17+)
- CMake 3.10+
- OpenSSL **3.2+** (needed for Argon2id)
- `xclip` or `xsel` for clipboard support

Google Test is fetched automatically by CMake. For OpenSSL installation instructions per distro, see [DEPENDENCIES.md](DEPENDENCIES.md).

## Build and test

```bash
./scripts/build.sh            # Release build -> build/bin/key_wallet
cd build && ctest --output-on-failure
```

The build script compiles with `-Wall -Wextra -Wpedantic -fstack-protector-strong` and checks that stack canaries are present in the binary.

## Usage

```bash
key_wallet init                 # create a new vault (prompts for a master password)
key_wallet add                  # add an entry (name, website, username, password)
key_wallet list                 # list entries (no passwords are decrypted)
key_wallet search github        # filter by name or website
key_wallet get github           # re-auth, then copy the password to the clipboard
key_wallet update github        # rotate a password or edit fields
key_wallet delete github        # remove an entry (asks for confirmation)
key_wallet generate 24 --no-symbols
key_wallet change-master        # rotate the master password and re-encrypt all entries
key_wallet config --show        # show master password expiry status
key_wallet config --expiry-days 90
```

By default the vault lives at `~/.key_wallet.vault`. You can choose another location with `--vault <path>` or the `KEY_WALLET_VAULT` environment variable.

## How it works

```
master password + salt
        │  Argon2id
        ▼
    vault_key ──────────► decrypts the index (metadata only)
        │  HKDF-SHA256, info = "vault-entry-key:" + uuid
        ▼
   entry_key_N ─────────► decrypts one password
```

A session moves through four states: `LOCKED → BROWSING ⇄ RETRIEVING`, plus `EXPIRED`. In `BROWSING`, no password is held in memory. `EXPIRED` means the master password has expired and only `change-master` is allowed.

The full threat model, vault file layout and design rationale are in [docs/design_document-v0.2.md](docs/design_document-v0.2.md).

## Project layout

```
src/
  crypto/    Argon2id + HKDF, AES-256-GCM, secure random / UUID
  storage/   entry serialization and the two-layer vault format
  core/      SecureBuffer and the session state machine
  cli/       commands, masked terminal input, clipboard
tests/       Google Test suites for every module
docs/        design document and roadmap
```

## Status

Version 0.2. Phases 1–3 (crypto primitives, vault storage, CLI) and memory hardening are complete. Next on the [roadmap](docs/key_manager_roadmap-v0.2.md): fuzzing the vault parser, enforcing field length limits, checking vault file permissions, and making the clipboard clear survive process exit.

## License

[MIT](LICENSE)
