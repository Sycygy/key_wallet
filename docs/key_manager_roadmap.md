# key_manager — Project Roadmap

**Project:** Secure Password Manager  
**Course:** CMPS 297AD/396AI — Applied Cryptography, AUB Fall 2025  
**Stack:** C++ · OpenSSL 3.2+ · CMake · CLI → GUI  
**Version:** 0.1

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

**Goal:** A compilable project skeleton with all three cryptographic building blocks working and tested in isolation.

### 1.1 Project Scaffold
- [ ] Initialize CMake project with `CMakeLists.txt`
- [ ] Configure `find_package(OpenSSL 3.2 REQUIRED)`
- [ ] Set up directory structure: `src/crypto/`, `src/storage/`, `src/core/`, `src/cli/`
- [ ] Add a test runner (Google Test or a simple `tests/` with `ctest`)
- [ ] Confirm project compiles cleanly with `-Wall -Wextra -O2`

### 1.2 `core/secure_buffer`
- [ ] Implement `SecureBuffer` RAII wrapper
- [ ] Allocate with `mlock()` (best-effort, fallback gracefully)
- [ ] Zero on destruction with `OPENSSL_cleanse()`
- [ ] Used by all subsequent crypto code for sensitive data

### 1.3 `crypto/random`
- [ ] Wrap `RAND_bytes()` into `random_bytes(size_t n) → SecureBuffer`
- [ ] Implement `generate_password(length, charset_flags) → std::string`
- [ ] Use rejection sampling to eliminate modulo bias
- [ ] Configurable character sets: uppercase, lowercase, digits, symbols
- [ ] Unit test: verify output length, charset constraints, no obvious bias

### 1.4 `crypto/kdf`
- [ ] Implement Argon2id via OpenSSL `EVP_KDF` (`OSSL_KDF_NAME_ARGON2ID`)
- [ ] Parameters: m=65536 KiB, t=3, p=4, output=32 bytes
- [ ] Function: `derive_key(password, salt) → SecureBuffer`
- [ ] Unit test: same inputs → same output (deterministic); different salt → different output

### 1.5 `crypto/aead`
- [ ] Implement AES-256-GCM encrypt: `encrypt(key, plaintext, aad) → {iv, ciphertext, tag}`
- [ ] Implement AES-256-GCM decrypt: `decrypt(key, iv, ciphertext, tag, aad) → plaintext`
- [ ] Hybrid IV construction per NIST SP 800-38D §8.2.2: `IV = counter(4B, LE) || random(8B)`
  - Counter-based overload for main vault encryption (counter from encrypted payload)
  - Fully random IV overload for verification token encryption
- [ ] Return explicit error on tag verification failure (do not silently return garbage)
- [ ] Unit test: encrypt → decrypt round-trip; tampered ciphertext → error; tampered AAD → error; hybrid IV uses counter prefix correctly

**Phase 1 exit criteria:** `ctest` passes all crypto unit tests. No hardcoded keys or test artifacts committed.

---

## Phase 2 — Vault Storage

**Goal:** A fully encrypted binary vault file that can be created, loaded, and modified on disk.

### 2.1 `storage/entry`
- [ ] Define `PasswordEntry` struct: `{id, name, website, username, password, created_at, updated_at, expires_at}`
- [ ] Define `BrowsableEntry` struct: same but `password` field is a zeroed `SecureBuffer` (not accessible)
- [ ] Implement binary serialization: `serialize(entry) → bytes`
- [ ] Implement binary deserialization: `deserialize(bytes) → PasswordEntry`
- [ ] Validate all length fields on deserialization (prevent buffer overflows)
- [ ] Unit test: round-trip serialize/deserialize; malformed input → error

### 2.2 `storage/vault`
- [ ] Implement vault binary format (see design doc Section 6)
- [ ] `create_vault(path, master_password) → Vault` — generates salt, derives key, generates verification token, sets `save_counter = 0`, `master_password_changed_at = now`, `expiry_days = 30`, writes empty vault
- [ ] `load_vault(path, master_password) → Vault` — reads file, verifies AAD, verifies token, decrypts, deserializes (reads `save_counter` from payload)
- [ ] `save_vault(vault, path)` — increments `save_counter`, builds hybrid IV (counter ‖ random), encrypts, writes atomically via `rename()`
- [ ] AAD covers: MAGIC + VERSION + CREATED_AT + SALT + ARGON2_PARAMS
- [ ] `verify_master_password(input) → bool` — re-derives key, attempts token decryption, returns result
- [ ] `check_expiry() → ExpiryStatus` — returns EXPIRED, WARNING (≤7 days), or OK based on `changed_at + expiry_days`
- [ ] Unit test: create → load round-trip; tampered file → error; wrong password → error; token verification correct/incorrect; expiry check returns correct status

### 2.3 Entry CRUD on Vault
- [ ] `vault.add_entry(entry)`
- [ ] `vault.get_entry(id) → PasswordEntry`
- [ ] `vault.find_entries(website) → vector<PasswordEntry>` (substring match)
- [ ] `vault.update_entry(id, fields)`
- [ ] `vault.delete_entry(id)`
- [ ] Unit test: all CRUD operations; lookup on nonexistent entry → error

**Phase 2 exit criteria:** A test program can create a vault, add entries, save it, reload it, and retrieve entries correctly. The vault file is opaque binary (no plaintext strings visible with `strings` or a hex editor).

---

## Phase 3 — CLI Interface

**Goal:** A fully usable command-line password manager.

### 3.1 `cli/input`
- [ ] Masked password input using `termios` (disable echo)
- [ ] Restore terminal state on SIGINT / unexpected exit
- [ ] Clipboard write: `xclip` / `xsel` on Linux, `pbcopy` on macOS
- [ ] Clipboard clear: overwrite after configurable timeout (default 30s) in background thread

### 3.2 `core/session`
- [ ] Implement LOCKED / EXPIRED / BROWSING / RETRIEVING state machine
- [ ] `unlock(path, master_password)` — loads vault, derives key, calls `check_expiry()`:
  - EXPIRED → transition to EXPIRED state, print hard-block message
  - WARNING → transition to BROWSING, print non-blocking warning with days remaining
  - OK → transition to BROWSING, start inactivity timer
- [ ] `verify_master_password(input) → bool` — re-derives key, checks verification token
- [ ] `retrieve(entry_id, master_password) → PasswordEntry` — calls verify, reconstructs full entry momentarily → RETRIEVING then back to BROWSING
- [ ] `lock()` — zeros key and all sensitive fields → LOCKED
- [ ] Auto-lock after configurable inactivity timeout (default 5 min)
- [ ] In EXPIRED state: only `change-master` is permitted; all other operations print "Master password expired — please run change-master"
- [ ] `change-master` resets `master_password_changed_at = now` and re-encrypts vault, then transitions to BROWSING

### 3.3 `cli/commands`
Implement the following subcommands:

| Command | State Required | Description |
|---------|---------------|-------------|
| `init <vault_path>` | — | Create a new vault, prompt for master password |
| `list` | BROWSING | List all entries (name, website, username, expires_at — no passwords) |
| `search <query>` | BROWSING | Filter entries by name or website |
| `get <name>` | BROWSING | Re-prompt master password → copy password to clipboard |
| `add` | BROWSING | Re-prompt master password → add new entry |
| `update <name>` | BROWSING | Re-prompt master password → update entry |
| `delete <name>` | BROWSING | Re-prompt master password → delete entry (with confirmation) |
| `generate` | — | Generate and print a password without storing it |
| `change-master` | BROWSING / EXPIRED | Re-prompt old + new master password → key rotation, resets expiry clock |
| `config --expiry-days <N>` | BROWSING | Re-prompt master password → set expiry interval (0 = disable) |
| `config --show` | BROWSING | Display current expiry settings and days remaining |

### 3.4 Error Handling
- [ ] All errors print a user-facing message without leaking cryptographic details
- [ ] Wrong master password → "Authentication failed" (not "Tag mismatch")
- [ ] Missing vault file → clear instructions to run `init`
- [ ] Expired master password → "Master password expired N days ago. Run change-master to continue."
- [ ] Warning period → "Master password expires in N days. Consider running change-master soon."
- [ ] No stack traces or internal paths in user-facing output

**Phase 3 exit criteria:** All commands work end-to-end from the terminal. The vault file survives a restart. `list` works without re-authentication. `get` correctly gates behind master password re-entry. Expiry hard-blocks correctly after deadline and clears after `change-master`. Warning appears correctly in the 7-day window.

---

## Phase 4 — Security Hardening

**Goal:** Close the most important residual security gaps identified in the design document.

### 4.1 Memory Hardening
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

### 4.4 Vault Integrity Warnings
- [ ] Detect and warn if vault file permissions are too permissive (e.g., world-readable)
- [ ] Warn if vault is stored in a world-readable directory

**Phase 4 exit criteria:** No sensitive strings visible in a post-mortem core dump. Fuzzer runs 10k iterations without crashes on the vault parser.

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
| Design document & threat model | ✅ `key_manager_design.md` |
| Cryptographic mechanisms description | ✅ Design doc Section 3 |
| User manual | After Phase 3 |
| Security analysis | After Phase 4 |
| 10-minute presentation | After Phase 4 |


