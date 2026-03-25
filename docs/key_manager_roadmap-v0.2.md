# key_manager — Project Roadmap

**Project:** Secure Password Manager
**Course:** CMPS 297AD/396AI — Applied Cryptography, AUB Fall 2025
**Stack:** C++ · OpenSSL 3.2+ · CMake · CLI → GUI
**Version:** 0.2

---

## Changelog: v0.1 → v0.2

### Roadmap changes introduced by v0.2:

1. **Phase 1.2 — SecureBuffer:** Migrated from `new[]` + manual `mlock` to OpenSSL's secure heap (`OPENSSL_secure_malloc` / `OPENSSL_secure_clear_free`). The `mlocked_` field is removed.

2. **Phase 1.3 — Random:** Added `generate_uuid()` returning a 16-byte UUID v4 via `RAND_bytes()` with proper RFC 4122 version and variant bits.

3. **Phase 1.4 — KDF:** Renamed `derive_key()` → `derive_vault_key()`. Added `derive_entry_key(vault_key, uuid)` using HKDF-SHA256 for per-entry key derivation.

4. **Phase 1.6 (new) — main.cpp hardening:** Added `CRYPTO_secure_malloc_init()`, `prctl(PR_SET_DUMPABLE, 0)`, and `setrlimit(RLIMIT_CORE, {0, 0})` before any secrets are loaded.

5. **Phase 2 — Vault Storage:** Vault format changed from single encrypted blob to two-layer format (encrypted index + per-entry encrypted passwords). FORMAT_VERSION bumped from 1 to 2.

6. **Phase 2.1 — Entry:** `BrowsableEntry` no longer has a password field (was a zeroed `SecureBuffer` in v0.1). Serialization split into `serialize_index()` / `serialize_password()` and matching deserializers.

7. **Phase 2.2 — Vault:** `load_vault` now decrypts index only (passwords stay on disk). New `get_entry(id)` function derives entry key via HKDF and decrypts a single password on demand. Key rotation re-encrypts all entry passwords under new entry keys.

8. **Phase 3.2 — Session:** BROWSING state holds `vector<BrowsableEntry>` with no password data. `retrieve()` performs HKDF derivation and on-demand decryption.

---

## Overview

The project is divided into 5 phases. Each phase produces a working, testable artifact before the next begins. Phases 1–3 are the core deliverable. Phases 4–5 are hardening and polish.

```
Phase 1 → Scaffolding & Crypto Primitives
Phase 2 → Vault Storage
Phase 3 → CLI Interface
Phase 4 → Security Hardening
Phase 5 → GUI (stretch goal)
```

---

## Phase 1 — Scaffolding & Crypto Primitives

**Goal:** A compilable project skeleton with all cryptographic building blocks working and tested in isolation.

### 1.1 Project Scaffold
- [x] Initialize CMake project with `CMakeLists.txt`
- [x] Configure `find_package(OpenSSL 3.2 REQUIRED)`
- [x] Set up directory structure: `src/crypto/`, `src/storage/`, `src/core/`, `src/cli/`
- [x] Add a test runner (Google Test with `ctest`)
- [x] Confirm project compiles cleanly with `-Wall -Wextra -O2`

### 1.2 `core/secure_buffer`
- [x] Implement `SecureBuffer` RAII wrapper
- [x] ~~Allocate with `mlock()` (best-effort, fallback gracefully)~~ **(v0.2)** Allocate via `OPENSSL_secure_malloc()` from OpenSSL's secure heap
- [x] ~~Zero on destruction with `OPENSSL_cleanse()`~~ **(v0.2)** Free via `OPENSSL_secure_clear_free()` which cleanse + frees
- [x] Fallback to `OPENSSL_malloc()` if secure heap is exhausted or uninitialised
- [x] Used by all subsequent crypto code for sensitive data

### 1.3 `crypto/random`
- [x] Wrap `RAND_bytes()` into `random_bytes(size_t n) → SecureBuffer`
- [x] Implement `generate_password(length, charset_flags) → std::string`
- [x] Use rejection sampling to eliminate modulo bias
- [x] Configurable character sets: uppercase, lowercase, digits, symbols
- [x] **(v0.2)** Implement `generate_uuid() → std::array<uint8_t, 16>` (UUID v4 per RFC 4122)
- [x] Unit test: verify output length, charset constraints, no obvious bias
- [x] Unit test: UUID version/variant bits, uniqueness

### 1.4 `crypto/kdf`
- [x] Implement Argon2id via OpenSSL `EVP_KDF` (`OSSL_KDF_NAME_ARGON2ID`)
- [x] Parameters: m=65536 KiB, t=3, p=4, output=32 bytes
- [x] Function: ~~`derive_key(password, salt) → SecureBuffer`~~ **(v0.2)** `derive_vault_key(password, salt) → SecureBuffer`
- [x] **(v0.2)** Function: `derive_entry_key(vault_key, uuid) → SecureBuffer` using HKDF-SHA256
- [x] Unit test: same inputs → same output (deterministic); different salt → different output
- [x] Unit test: entry key determinism, UUID sensitivity, vault key sensitivity, differs from vault key

### 1.5 `crypto/aead`
- [x] Implement AES-256-GCM encrypt: `encrypt(key, plaintext, aad) → {iv, ciphertext, tag}`
- [x] Implement AES-256-GCM decrypt: `decrypt(key, iv, ciphertext, tag, aad) → plaintext`
- [x] Hybrid IV construction per NIST SP 800-38D §8.2.2: `IV = counter(4B, LE) || random(8B)`
  - Counter-based overload for index encryption (counter from encrypted payload)
  - Fully random IV overload for verification token and entry password encryption
- [x] Return explicit error on tag verification failure (do not silently return garbage)
- [x] Unit test: encrypt → decrypt round-trip; tampered ciphertext → error; tampered AAD → error; hybrid IV uses counter prefix correctly

### 1.6 `main.cpp` Process Hardening (New in v0.2)
- [x] `CRYPTO_secure_malloc_init(65536, 32)` — initialize OpenSSL secure heap before any SecureBuffer usage
- [x] `prctl(PR_SET_DUMPABLE, 0)` — disable core dumps and block ptrace
- [x] `setrlimit(RLIMIT_CORE, {0, 0})` — belt-and-suspenders core dump disable

**Phase 1 exit criteria:** `ctest` passes all crypto unit tests (72 tests). No hardcoded keys or test artifacts committed.

---

## Phase 2 — Vault Storage

**Goal:** A fully encrypted binary vault file using the two-layer format that can be created, loaded, and modified on disk.

### 2.1 `storage/entry`
- [ ] Define `PasswordEntry` struct: `{id, name, website, username, password, created_at, updated_at, expires_at}`
- [ ] Define `BrowsableEntry` struct: same but **no password field** (v0.2 — password is never loaded)
- [ ] Implement split binary serialization:
  - `serialize_index(entry) → bytes` — everything except password
  - `serialize_password(entry) → bytes` — password only
  - `deserialize_index(bytes) → BrowsableEntry`
  - `deserialize_password(bytes) → SecureBuffer`
- [ ] Validate all length fields on deserialization (prevent buffer overflows)
- [ ] Unit test: round-trip serialize/deserialize; malformed input → error

### 2.2 `storage/vault`
- [ ] Implement vault binary format v0.2 (see design doc Section 6)
- [ ] `create_vault(path, master_password) → Vault` — generates salt, derives vault key, generates verification token, assigns UUIDs, encrypts index and per-entry passwords separately
- [ ] `load_vault(path, master_password) → Vault` — reads file, verifies AAD, verifies token, **decrypts index only** (passwords remain on disk as ciphertexts)
- [ ] `save_vault(vault, path)` — increments `save_counter`, builds hybrid IV, re-encrypts index and modified entry passwords, writes atomically via `rename()`
- [ ] `get_entry(id) → PasswordEntry` — reads entry's ciphertext from disk, derives `entry_key = HKDF(vault_key, uuid)`, decrypts, returns entry with password. Caller responsible for zeroing via RAII.
- [ ] AAD covers: MAGIC + VERSION + CREATED_AT + SALT + ARGON2_PARAMS (authenticated in index AND every entry ciphertext)
- [ ] `verify_master_password(input) → bool` — re-derives key, attempts token decryption
- [ ] `check_expiry() → ExpiryStatus` — returns EXPIRED, WARNING (≤7 days), or OK
- [ ] Detect FORMAT_VERSION=1 (v0.1 vaults) and reject with migration message
- [ ] Unit test: create → load round-trip; tampered file → error; wrong password → error; per-entry decrypt; version detection

### 2.3 Entry CRUD on Vault
- [x] `vault.add_entry(entry)` — generates UUID, derives entry_key, encrypts password separately
- [x] `vault.get_entry(id) → PasswordEntry` — on-demand HKDF + decrypt
- [x] `vault.find_entries(website) → vector<BrowsableEntry>` (substring match, no passwords)
- [x] `vault.update_entry(id, fields)` — if password changed, re-encrypts with same entry_key (UUID preserved)
- [x] `vault.delete_entry(id)` — removes from index and removes ciphertext block
- [x] Unit test: all CRUD operations; lookup on nonexistent entry → error

**Phase 2 exit criteria:** A test program can create a vault, add entries, save it, reload it, and retrieve entries correctly. The vault file is opaque binary. `load_vault` only decrypts the index — passwords are not in RAM after load.

---

## Phase 3 — CLI Interface

**Goal:** A fully usable command-line password manager.

### 3.1 `cli/input`
- [x] Masked password input using `termios` (disable echo)
- [x] Restore terminal state on SIGINT / unexpected exit
- [x] Clipboard write: `xclip` / `xsel` on Linux, `pbcopy` on macOS
- [x] Clipboard clear: overwrite after configurable timeout (default 30s) in background thread

### 3.2 `core/session`
- [ ] Implement LOCKED / EXPIRED / BROWSING / RETRIEVING state machine
- [ ] `unlock(path, master_password)` — loads vault (index only), derives vault key, calls `check_expiry()`:
  - EXPIRED → transition to EXPIRED state, print hard-block message
  - WARNING → transition to BROWSING, print non-blocking warning with days remaining
  - OK → transition to BROWSING, start inactivity timer
- [ ] `verify_master_password(input) → bool` — re-derives key, checks verification token
- [ ] `retrieve(entry_id, master_password) → PasswordEntry` — calls verify, derives entry_key via HKDF, decrypts single password from disk → RETRIEVING then back to BROWSING
- [ ] `lock()` — zeros vault key and all sensitive fields → LOCKED
- [ ] Auto-lock after configurable inactivity timeout (default 5 min)
- [ ] In EXPIRED state: only `change-master` is permitted
- [ ] `change-master` re-derives all entry keys under new vault key, re-encrypts all passwords, resets `master_password_changed_at = now`

### 3.3 `cli/commands`
Implement the following subcommands:

| Command | State Required | Description |
|---------|---------------|-------------|
| ✅ `init <vault_path>` | — | Create a new vault, prompt for master password |
| ✅ `list` | BROWSING | List all entries (name, website, username, expires_at — no passwords) |
| ✅ `search <query>` | BROWSING | Filter entries by name or website |
| ✅ `get <name>` | BROWSING | Re-prompt master password → derive entry key → copy password to clipboard |
| ✅ `add` | BROWSING | Re-prompt master password → add new entry (UUID auto-generated) |
| ✅ `update <name>` | BROWSING | Re-prompt master password → update entry |
| ✅ `delete <name>` | BROWSING | Re-prompt master password → delete entry (with confirmation) |
| ✅ `generate` | — | Generate and print a password without storing it |
| ✅ `change-master` | BROWSING / EXPIRED | Re-prompt old + new master password → key rotation, re-encrypt all entries |
| ✅ `config --expiry-days <N>` | BROWSING | Re-prompt master password → set expiry interval (0 = disable) |
| ✅ `config --show` | BROWSING | Display current expiry settings and days remaining |

### 3.4 Error Handling
- [x] All errors print a user-facing message without leaking cryptographic details
- [x] Wrong master password → "Authentication failed" (not "Tag mismatch")
- [x] Missing vault file → clear instructions to run `init`
- [x] Expired master password → "Master password expired N days ago. Run change-master to continue."
- [x] Warning period → "Master password expires in N days. Consider running change-master soon."
- [x] No stack traces or internal paths in user-facing output

**Phase 3 exit criteria:** All commands work end-to-end from the terminal. The vault file survives a restart. `list` works without re-authentication and shows no passwords. `get` correctly gates behind master password re-entry and derives entry key on demand.

---

## Phase 4 — Security Hardening

**Goal:** Close the most important residual security gaps identified in the design document.

### 4.1 Memory Hardening
- [x] **(v0.2 — moved from Phase 4 to Phase 1)** SecureBuffer uses OpenSSL secure heap
- [x] **(v0.2 — moved from Phase 4 to Phase 1)** Process hardening: prctl + setrlimit in main()
- [ ] Audit all `std::string` usages for sensitive data — replace with `SecureBuffer` or `secure_string`
- [ ] Ensure no sensitive data ends up in STL containers that don't zero on destruction
- [ ] Review all copy constructors and assignment operators for `SecureBuffer`
- [ ] Compile with `-fstack-protector-strong` and verify no stack canary warnings

### 4.2 Input Validation & Fuzzing
- [ ] Fuzz the vault deserializer with `libFuzzer` or AFL++ on malformed binary inputs
- [ ] Enforce maximum lengths on all string fields in entries
- [ ] Validate Argon2 parameter ranges on vault load (reject suspiciously weak parameters)

### 4.3 Auto-lock & Timeout Polish
- [ ] Confirm auto-lock fires reliably under SIGTERM and SIGHUP
- [ ] Ensure clipboard is cleared even if the app is killed (best-effort via `atexit`)
- [ ] Fix clipboard clear: replace detached `std::thread` in `schedule_clipboard_clear()` with `fork()` so the clear process survives the parent exiting — current CLI design exits immediately after `get`, killing the thread before the 30-second timer fires

### 4.4 Vault Integrity Warnings
- [ ] Detect and warn if vault file permissions are too permissive (e.g., world-readable)
- [ ] Warn if vault is stored in a world-readable directory

**Phase 4 exit criteria:** No sensitive strings visible in a post-mortem core dump. Fuzzer runs 10k iterations without crashes. v0.1 migration tested.

---

## Phase 5 — GUI (Stretch Goal)

**Goal:** A graphical interface that wraps the same core/session and storage logic used by the CLI.

### 5.1 Framework Selection
- Candidate: **Qt6** (cross-platform, good C++ integration, `QLineEdit::setEchoMode(Password)`)
- The `core/` and `storage/` modules are reused without modification
- Only `cli/` is replaced by a `gui/` module

### 5.2 GUI Features
- [ ] Master password dialog on launch
- [ ] Entry list with search/filter
- [ ] Add / Edit / Delete entry forms
- [ ] Password generator dialog with live preview
- [ ] Copy-to-clipboard button with countdown indicator
- [ ] Auto-lock indicator in status bar

**Phase 5 exit criteria:** All CLI functionality is accessible through the GUI. The GUI compiles and runs on Linux and macOS.

---

## Deliverables Checklist (per assignment)

| Deliverable | Produced In |
|-------------|-------------|
| Source code | Phases 1–3 (4–5 optional) |
| Design document & threat model | ✅ `design_document-v0.2.md` |
| Cryptographic mechanisms description | ✅ Design doc Section 3 + `extra_docs/cryptographic_decisions.md` |
| User manual | After Phase 3 |
| Security analysis | After Phase 4 |
| 10-minute presentation | After Phase 4 |
