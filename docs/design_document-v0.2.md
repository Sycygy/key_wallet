# key_manager — Design Document & Threat Model
**Project:** Secure Password Manager
**Language:** C++
**Crypto Library:** OpenSSL 3.2+
**Version:** 0.2

---

## Changelog: v0.1 → v0.2

This section summarises every change from version 0.1 to 0.2. The rest of the document is the authoritative v0.2 specification.

### Two-Layer Key Hierarchy
- **v0.1:** A single `derived_key` (Argon2id output) encrypted the entire vault payload — all entries including all passwords — in one AES-256-GCM blob.
- **v0.2:** The Argon2id output is now called `vault_key` and encrypts only the **index** (metadata, no passwords). Each entry's password is encrypted separately under an **entry key** derived via `HKDF-SHA256(vault_key, "vault-entry-key:" + uuid_hex)`.

### Per-Entry Password Encryption
- **v0.1:** Unlocking decrypted all passwords into RAM simultaneously; they were zeroed immediately but briefly existed in memory.
- **v0.2:** Passwords are never decrypted on unlock. Only the entry index is decrypted. Individual passwords are decrypted on demand (one at a time, only during RETRIEVING), then destroyed by RAII.

### Vault File Format
- **v0.1:** Single encrypted blob after the verification token containing all entries.
- **v0.2:** Two-layer format — an encrypted index section followed by N individually encrypted entry password blocks. FORMAT_VERSION bumped from 1 to 2.

### SecureBuffer Migrated to OpenSSL Secure Heap
- **v0.1:** `new[]` + manual `mlock()` + `OPENSSL_cleanse()` + `delete[]`.
- **v0.2:** `OPENSSL_secure_malloc()` + `OPENSSL_secure_clear_free()`. The secure heap provides page-aligned allocation, `mlock`, guard pages, and `MADV_DONTDUMP` automatically. The `mlocked_` field is removed.

### Process-Level Memory Hardening
- **v0.1:** No process hardening.
- **v0.2:** `main()` initialises three hardening measures before any secrets are loaded:
  1. `CRYPTO_secure_malloc_init(65536, 32)` — OpenSSL secure heap
  2. `prctl(PR_SET_DUMPABLE, 0)` — disables core dumps and blocks same-user ptrace
  3. `setrlimit(RLIMIT_CORE, {0, 0})` — belt-and-suspenders core dump disable

### KDF Module Rename
- `derive_key()` renamed to `derive_vault_key()` for clarity.
- New function `derive_entry_key(vault_key, uuid)` added using HKDF-SHA256.

### Random Module Addition
- New function `generate_uuid()` returns a 16-byte UUID v4 via `RAND_bytes()` with proper version and variant bits per RFC 4122.

### BrowsableEntry Change
- **v0.1:** Password field was a zeroed `SecureBuffer` in BROWSING state.
- **v0.2:** Password field is absent entirely from `BrowsableEntry` — never loaded into RAM.

### Security Properties Improved

| Property | v0.1 | v0.2 |
|---|---|---|
| Passwords in RAM on unlock | All (briefly) | None |
| Passwords in RAM in BROWSING | Zeroed buffers | Not present |
| Core dump leaks passwords | If crash during unlock | Never (prctl + secure heap) |
| Same-user ptrace blocked | No | Yes (prctl) |
| Guard pages around secrets | No | Yes (secure heap) |
| Sensitive pages excluded from swap | Best-effort (mlock) | Yes (secure heap arena) |

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Threat Model](#2-threat-model)
3. [Cryptographic Design](#3-cryptographic-design)
4. [Session Model & Two-Step Authentication](#4-session-model--two-step-authentication)
5. [System Architecture](#5-system-architecture)
6. [Vault File Format](#6-vault-file-format)
7. [Key Rotation](#7-key-rotation)
8. [Security Assumptions & Limitations](#8-security-assumptions--limitations)
9. [Design Decisions & Rationale](#9-design-decisions--rationale)

---

## 1. Project Overview

`key_manager` is a locally-operated, CLI-first password manager written in C++. It uses a master password to derive an encryption key, which protects a fully-encrypted binary vault stored on disk. The system generates cryptographically strong random passwords, supports CRUD operations on entries, and is designed with security as the primary constraint.

The application uses a **two-step authentication model**: the master password is required once to unlock the vault and browse entry names and metadata; it is required a second time to retrieve any individual password. This separates the "browsing" and "retrieving" security contexts without compromising vault privacy on disk.

In v0.2, the application uses a **two-layer key hierarchy**: the vault key decrypts the index (metadata only), while per-entry keys derived via HKDF-SHA256 decrypt individual passwords on demand. This ensures that passwords are never in RAM unless explicitly requested.

The application also enforces **master password expiry**: the vault tracks when the master password was last changed and hard-blocks all operations once the configurable expiry period elapses, forcing the user to rotate before continuing.

The system operates entirely offline. There is no network communication, no cloud sync, and no shared state between users.

---

## 2. Threat Model

### 2.1 Assets to Protect

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| Master password | Critical | Never stored; must not be recoverable from any artifact |
| Vault key (derived) | Critical | Held in memory only during an active session |
| Entry keys (derived) | Critical | Derived on demand via HKDF; exist only during RETRIEVING |
| Vault index plaintext | High | Website, username, and metadata for each entry |
| Entry password plaintext | Critical | Decrypted one at a time, only during RETRIEVING |
| Vault ciphertext | High | Must resist offline brute-force and tampering |
| Session state | Medium | Unlocked vault in memory during use |
| Password expiry metadata | Medium | Last-changed timestamp and expiry interval; stored inside encrypted payload to prevent tampering |

### 2.2 Attacker Profiles

#### Attacker A — Disk/File Access (Primary Threat)
- **Capability:** Read-only or read-write access to the vault file on disk (e.g., stolen laptop, shared filesystem, malware exfiltrating files).
- **Goal:** Recover plaintext credentials without knowing the master password.
- **Mitigation:** AES-256-GCM encryption ensures confidentiality; authentication tag prevents undetected tampering. Argon2id with strong parameters makes offline brute-force computationally infeasible. Per-entry encryption means even if the index key were somehow leaked, individual passwords remain independently encrypted.

#### Attacker B — Memory Inspection (Secondary Threat)
- **Capability:** Can read process memory during an active session (e.g., local malware, ptrace attach, core dump analysis).
- **Goal:** Extract the master password or derived key from memory.
- **Mitigation (v0.2 enhancements):**
  - Master password is zeroed immediately after key derivation using `OPENSSL_cleanse`.
  - Vault key is stored in OpenSSL's secure heap (guard pages, `MADV_DONTDUMP`, `mlock`).
  - `prctl(PR_SET_DUMPABLE, 0)` blocks same-user ptrace and disables core dumps.
  - `setrlimit(RLIMIT_CORE, {0, 0})` as belt-and-suspenders core dump prevention.
  - Passwords never enter RAM during BROWSING — only one password is decrypted at a time during RETRIEVING.

#### Attacker C — Physical Access / Cold Boot (Tertiary Threat)
- **Capability:** Physical access to a running or recently-powered-off machine.
- **Goal:** Extract keys or plaintext from RAM.
- **Mitigation:** Short session timeout, eager memory zeroing, secure heap arena with `mlock`. Full mitigation against cold boot attacks is outside scope (would require OS-level memory encryption).

#### Attacker D — Malicious Vault Modification
- **Capability:** Can modify the vault file on disk between sessions.
- **Goal:** Inject or alter entries without detection, or cause the application to behave unexpectedly.
- **Mitigation:** AES-256-GCM provides authenticated encryption; any modification to the ciphertext or AAD will cause decryption to fail with an explicit integrity error. AAD covers vault header fields, preventing silent KDF parameter downgrade. Each entry password is independently authenticated.

#### Attacker E — Shoulder Surfing / Screen Capture
- **Capability:** Visual observation of the terminal.
- **Goal:** Observe master password or retrieved credentials.
- **Mitigation:** Master password input is masked (no echo). Retrieved passwords are optionally written to clipboard (cleared after timeout) rather than printed to stdout.

#### Attacker F — Unlocked Session Opportunistic Access
- **Capability:** Briefly accesses a logged-in terminal while the user is away (e.g., unlocked workstation).
- **Goal:** Retrieve stored passwords without knowing the master password.
- **Mitigation:** Two-step authentication model. BROWSING state exposes only entry names and metadata. Retrieving any password requires re-entering the master password, verified against the vault's stored verification token. No passwords exist in RAM during BROWSING.

### 2.3 Out-of-Scope Threats

- **Compromised OpenSSL library:** We assume the system's OpenSSL 3.2+ installation is trustworthy.
- **Keyloggers:** A keylogger operating at the OS level can capture the master password before it reaches the application. This is out of scope.
- **Side-channel attacks on AES:** We rely on OpenSSL's AES-NI hardware acceleration, which provides constant-time implementations on supported hardware.
- **Vault file metadata:** File creation time, size, and inode information may leak that a vault exists. Not addressed in this version.

---

## 3. Cryptographic Design

### 3.1 Key Hierarchy (New in v0.2)

```
master_password + salt
        │
     Argon2id (m=64MiB, t=3, p=4)
        │
        ▼
    vault_key (32 bytes)          ← decrypts the index
        │
   HKDF-SHA256 per entry
   info = "vault-entry-key:" + uuid_hex
        │
        ▼
   entry_key_N (32 bytes)         ← decrypts one password field
```

**`vault_key`** is derived directly from Argon2id, exactly as the single key in v0.1. Its role is narrowed: it now decrypts the index section only.

**`entry_key_N`** is derived from `vault_key` using HKDF-SHA256, with each entry's UUID as the `info` parameter. This produces a unique 256-bit key per entry with negligible computational cost.

### 3.2 Key Derivation — Argon2id

**Algorithm:** Argon2id (hybrid variant, resistant to both GPU and side-channel attacks)
**OpenSSL API:** `EVP_KDF` with `OSSL_KDF_NAME_ARGON2ID` (OpenSSL 3.2+)

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Output length | 32 bytes (256 bits) | Matches AES-256 key size |
| Salt | 16 bytes, random per vault | Prevents precomputation / rainbow tables |
| Memory cost (m) | 65536 KiB (64 MiB) | OWASP minimum for Argon2id |
| Iterations (t) | 3 | OWASP recommendation |
| Parallelism (p) | 4 | Matches typical CPU thread count |

**Derivation flow:**

```
master_password + salt  ──►  Argon2id  ──►  vault_key (32 bytes)
                              (64MiB, t=3, p=4)
```

The salt is stored in the vault header in plaintext. It is not secret — its purpose is uniqueness, not confidentiality.

### 3.3 Per-Entry Key Derivation — HKDF-SHA256 (New in v0.2)

**Algorithm:** HKDF (RFC 5869) with SHA-256
**OpenSSL API:** `EVP_KDF` with `OSSL_KDF_NAME_HKDF`

**Parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| PRK input | vault_key (32 bytes) | Already high-entropy from Argon2id |
| Salt | Empty (HKDF zero-fills internally) | vault_key is already uniformly random |
| Info | `"vault-entry-key:" + hex(uuid)` | Domain separation — binds key to specific entry |
| Output | 32 bytes (256 bits) | Matches AES-256 key size |

The computational cost is a few HMAC-SHA256 calls — negligible even for large vaults. Entry keys are derived on demand, never stored.

### 3.4 Authenticated Encryption — AES-256-GCM

**Algorithm:** AES-256-GCM
**OpenSSL API:** `EVP_EncryptInit_ex2` / `EVP_CIPHER_CTX`

| Parameter | Value |
|-----------|-------|
| Key size | 256 bits (32 bytes) |
| IV (nonce) | 96 bits (12 bytes), hybrid construction (see below) |
| Authentication tag | 128 bits (16 bytes) |
| AAD | Vault header (MAGIC through ARGON2_PARAMS) |

**Why GCM over CBC-HMAC?** GCM provides both confidentiality and integrity in a single pass with a clean, standardized API. CBC with a separate HMAC is error-prone to implement correctly (MAC-then-Encrypt vs Encrypt-then-MAC ordering). GCM natively produces an authentication tag, and OpenSSL's EVP interface handles this correctly.

**Nonce handling — hybrid construction (NIST SP 800-38D §8.2.2):**

The index ciphertext uses a **hybrid IV** composed of a deterministic counter and a random field:

```
IV (12 bytes) = [ counter (4 bytes, LE) ] || [ random (8 bytes) ]
```

| Component | Size | Source |
|-----------|------|--------|
| Counter (fixed field) | 4 bytes | Monotonic `save_counter` from encrypted payload, incremented on every save |
| Random (invocation field) | 8 bytes | `RAND_bytes()` per encryption call |

The counter guarantees **uniqueness**: even if `RAND_bytes()` were to repeat, the counter value will differ. The random portion adds **unpredictability**. Together they satisfy NIST's deterministic construction requirements.

**Entry password IVs:** Each entry password ciphertext uses a fully random 12-byte IV, since individual entries are re-encrypted infrequently.

**Verification token IV:** Fully random 12-byte IV, since it is only encrypted on vault creation and `change-master`.

### 3.5 Password Generation

**Source of randomness:** `RAND_bytes()` from OpenSSL, which seeds from `/dev/urandom` (or OS CSPRNG equivalent).

**Method:** Rejection sampling over a configurable character set to ensure uniform distribution. Modulo bias is explicitly avoided.

```
character_set = [A-Z] ∪ [a-z] ∪ [0-9] ∪ [symbols]   (configurable)
for i in [0, length):
    do:
        byte = RAND_bytes(1)
    while byte >= floor(256 / |charset|) * |charset|   // reject to avoid bias
    password[i] = charset[byte % |charset|]
```

### 3.6 UUID Generation (New in v0.2)

UUIDs are generated via `RAND_bytes(16)` with version 4 bits set per RFC 4122:
- `uuid[6] = (uuid[6] & 0x0F) | 0x40` — version nibble
- `uuid[8] = (uuid[8] & 0x3F) | 0x80` — variant bits

The 122 bits of randomness ensure UUIDs are unpredictable, which is essential since they serve as the `info` parameter in HKDF — if an attacker could predict UUIDs, they could precompute entry keys.

### 3.7 Master Password Verification Token

To support the two-step authentication model without storing the master password or derived key, the vault header contains a **verification token** — a fixed known plaintext encrypted under the derived key.

**Construction (at vault creation):**
```
token_plaintext  = 0x00 × 32          (32 zero bytes)
token_iv         = RAND_bytes(12)      (fresh random IV)
token_ciphertext, token_tag = AES-256-GCM.encrypt(
    key    = vault_key,
    plain  = token_plaintext,
    aad    = vault_header_aad
)
```

Both `token_iv`, `token_ciphertext`, and `token_tag` are stored in the vault header.

**Verification (at re-authentication prompt):**
```
candidate_key = Argon2id(input_password, vault_salt, argon2_params)
result = AES-256-GCM.decrypt(
    key  = candidate_key,
    iv   = token_iv,
    data = token_ciphertext,
    tag  = token_tag,
    aad  = vault_header_aad
)
if result == success → password correct
if result == tag mismatch → password wrong
```

The Argon2id cost is paid in full on every verification attempt, making brute-force expensive. No timing difference leaks whether the password was close or not — GCM tag comparison is constant-time in OpenSSL.

### 3.8 Master Password Expiry

The vault stores two values inside the **encrypted index payload** (not the header) to enforce master password rotation:

| Field | Type | Description |
|-------|------|-------------|
| `master_password_changed_at` | `uint64` | Unix timestamp of the last successful `change-master` operation. Set at vault creation. |
| `master_password_expiry_days` | `uint32` | Expiry interval in days. Default: 30. Configurable per vault. 0 means no expiry (disabled). |

Storing these inside the encrypted payload rather than the plaintext header means an attacker cannot reset or extend the expiry without knowing the master password.

**Expiry check flow (on every unlock):**

```
expiry_deadline = master_password_changed_at + (expiry_days × 86400)

if current_time >= expiry_deadline:
    → transition to EXPIRED state (not BROWSING)
    → print clear warning: "Master password expired N days ago. You must change it to continue."
    → only allow: change-master, exit
    → block: list, get, add, update, delete
```

**Warning period:** Starting 7 days before the deadline, every unlock displays a non-blocking warning: `"Master password expires in N days. Consider changing it soon."` The user can continue normally during the warning period.

### 3.9 Memory Safety

- Master password buffer: zeroed with `OPENSSL_cleanse()` immediately after key derivation.
- Vault key: stored in a `SecureBuffer` wrapper backed by OpenSSL's secure heap (`OPENSSL_secure_malloc`), which provides mlock, guard pages, and MADV_DONTDUMP. Zeroed via `OPENSSL_secure_clear_free()` on destruction.
- Entry keys: derived on demand, stored in `SecureBuffer`, destroyed immediately after use.
- In BROWSING state, **password fields are never loaded** — only name and metadata fields exist in memory.
- Process hardening: `prctl(PR_SET_DUMPABLE, 0)` and `setrlimit(RLIMIT_CORE, {0, 0})` prevent core dumps and ptrace attachment.

---

## 4. Session Model & Two-Step Authentication

### 4.1 Session States

The session follows a strict four-state machine:

```
         init / load vault
              │
              ▼
          LOCKED ◄─────────────────────── auto-lock timeout
              │                                   │
     master password                              │
     → Argon2id → derive vault_key                │
     → decrypt index only                         │
     → check expiry                               │
              │                                   │
       ┌──────┴──────┐                            │
   not expired    expired                         │
       │              │                           │
       │           EXPIRED                        │
       │        (change-master only)              │
       │              │                           │
       │     rotation succeeds                    │
       │              │                           │
       └──────┬────────┘                          │
              ▼                                   │
          BROWSING ──────────────────────────────►┘
     (entry names + metadata visible)
     (passwords NOT in memory)
              │
     user selects entry
     → prompt master password
     → verify_master_password()
     → derive entry_key via HKDF
     → decrypt single password from disk
              │
              ▼
          RETRIEVING
     (single entry password revealed)
              │
     password shown / copied to clipboard
     → entry_key and password destroyed by RAII
              │
              ▼
          BROWSING  (immediately returns)
```

### 4.2 State Permissions

| Operation | LOCKED | EXPIRED | BROWSING | RETRIEVING |
|-----------|--------|---------|----------|------------|
| `list` / `search` | ✗ | ✗ | ✓ | ✓ |
| `get <entry>` | ✗ | ✗ | triggers re-auth | ✓ (momentary) |
| `add` | ✗ | ✗ | triggers re-auth | ✓ |
| `update` | ✗ | ✗ | triggers re-auth | ✓ |
| `delete` | ✗ | ✗ | triggers re-auth | ✓ |
| `change-master` | ✗ | ✓ (only allowed op) | triggers re-auth | ✓ |
| `config --expiry-days` | ✗ | ✗ | triggers re-auth | ✓ |

Write operations (`add`, `update`, `delete`, `change-master`) also require re-authentication.

### 4.3 BROWSING State Memory Layout (v0.2)

When the vault transitions from LOCKED to BROWSING, **only the index** is decrypted:

```
BrowsableEntry {
    id          : UUID (16 bytes)  ← kept in memory
    name        : string           ← kept in memory
    username    : string           ← kept in memory
    website     : string           ← kept in memory
    created_at  : uint64           ← kept in memory
    updated_at  : uint64           ← kept in memory
    expires_at  : uint64           ← kept in memory
    // NO password field — never loaded from disk
}
```

The password for any entry exists only on disk as an independently encrypted ciphertext. It is decrypted into RAM only during a RETRIEVING operation, then immediately destroyed.

---

## 5. System Architecture

```
key_manager/
├── CMakeLists.txt
├── src/
│   ├── main.cpp                  # Entry point, CLI dispatch, process hardening
│   ├── crypto/
│   │   ├── kdf.hpp / kdf.cpp     # Argon2id vault key + HKDF entry key derivation
│   │   ├── aead.hpp / aead.cpp   # AES-256-GCM encrypt/decrypt
│   │   └── random.hpp / random.cpp  # Secure password generation, UUID generation
│   ├── storage/
│   │   ├── vault.hpp / vault.cpp # Vault file read/write, two-layer binary format
│   │   └── entry.hpp / entry.cpp # PasswordEntry + BrowsableEntry models, split serialization
│   ├── core/
│   │   ├── session.hpp / session.cpp  # Session lifecycle, auto-lock
│   │   └── secure_buffer.hpp    # RAII wrapper using OpenSSL secure heap
│   └── cli/
│       ├── commands.hpp / commands.cpp  # add, get, update, delete, generate
│       └── input.hpp / input.cpp        # Masked input, clipboard ops
├── include/                      # Shared public headers (if needed)
├── tests/
│   ├── test_kdf.cpp
│   ├── test_aead.cpp
│   ├── test_vault.cpp
│   └── test_random.cpp
└── docs/
    ├── design_document-v0.2.md   # This document
    └── key_manager_roadmap.md
```

### Module Responsibilities

**`crypto/kdf`** — Wraps OpenSSL's EVP_KDF interface. `derive_vault_key()` uses Argon2id to derive the vault key from a password and salt. `derive_entry_key()` uses HKDF-SHA256 to derive per-entry keys from the vault key and entry UUID.

**`crypto/aead`** — Wraps AES-256-GCM encrypt/decrypt. Handles IV generation, tag verification. Returns `std::expected<>` or throws on auth failure.

**`crypto/random`** — Wraps `RAND_bytes`. Provides `generate_password(length, charset)`, `random_bytes(n)`, and `generate_uuid()`.

**`storage/entry`** — Data structs: `PasswordEntry` (full) and `BrowsableEntry` (no password). Split serialization: `serialize_index()` / `serialize_password()` and corresponding deserializers.

**`storage/vault`** — Manages the on-disk vault file. `load_vault` decrypts only the index. `get_entry(id)` derives the entry key and decrypts a single password on demand. `save_vault` re-encrypts index and modified entry passwords. Atomic write via `rename()`.

**`core/session`** — Implements the LOCKED / BROWSING / RETRIEVING state machine. Holds `vector<BrowsableEntry>` with no password data in BROWSING state. `retrieve()` performs HKDF derivation and on-demand decryption.

**`core/secure_buffer`** — RAII wrapper: allocates via `OPENSSL_secure_malloc()`, zeros and frees via `OPENSSL_secure_clear_free()`. Provides guard pages, mlock, and MADV_DONTDUMP via the secure heap.

**`cli/commands`** — Implements `add`, `get`, `list`, `update`, `delete`, `generate`, `change-master`. Calls into `core/session`.

**`cli/input`** — Reads masked passwords from the terminal (`termios` on POSIX). Handles clipboard write + delayed clear.

---

## 6. Vault File Format

The vault is a single binary file with the following layout. All multi-byte integers are stored in **little-endian** format.

```
┌─────────────────────────────────────────────┐
│  MAGIC (8 bytes): "KEYMGR\x01\x00"          │
├─────────────────────────────────────────────┤
│  FORMAT VERSION (2 bytes): uint16 = 2        │
├─────────────────────────────────────────────┤
│  CREATED_AT (8 bytes): uint64 (Unix time)    │
├─────────────────────────────────────────────┤
│  SALT (16 bytes): Argon2id salt              │
├─────────────────────────────────────────────┤
│  ARGON2_PARAMS (12 bytes):                   │
│    m_cost: uint32                            │
│    t_cost: uint32                            │
│    parallelism: uint32                       │
├─────────────────────────────────────────────┤  ← AAD boundary (all above is authenticated)
│  VERIFY_TOKEN_IV (12 bytes)                  │
├─────────────────────────────────────────────┤
│  VERIFY_TOKEN_TAG (16 bytes)                 │
├─────────────────────────────────────────────┤
│  VERIFY_TOKEN_CIPHERTEXT (32 bytes)          │
├─────────────────────────────────────────────┤
│  INDEX_IV (12 bytes)                         │
├─────────────────────────────────────────────┤
│  INDEX_TAG (16 bytes)                        │
├─────────────────────────────────────────────┤
│  INDEX_LENGTH (4 bytes): uint32              │
├─────────────────────────────────────────────┤
│  INDEX_CIPHERTEXT (variable)                 │
├─────────────────────────────────────────────┤
│  ENTRY_0_IV (12 bytes)        ┐              │
│  ENTRY_0_TAG (16 bytes)       │              │
│  ENTRY_0_LENGTH (4 bytes)     │  repeated    │
│  ENTRY_0_CIPHERTEXT (var)     │  N times     │
│  ...                          ┘              │
└─────────────────────────────────────────────┘
```

**AAD (Additional Authenticated Data):** The fields from MAGIC through ARGON2_PARAMS (inclusive) are fed as AAD into the verification token encryption, the index encryption, and every entry encryption. This ensures that even unencrypted metadata (format version, KDF parameters) cannot be silently tampered with.

**Index ciphertext plaintext format:**

```
[ SAVE_COUNTER: uint32 ]                 ← Monotonic counter for hybrid IV (starts at 0)
[ MASTER_PASSWORD_CHANGED_AT: uint64 ]   ← Unix timestamp of last change-master
[ MASTER_PASSWORD_EXPIRY_DAYS: uint32 ]  ← 0 = disabled, default = 30
[ ENTRY_COUNT: uint32 ]
[ ENTRY_0_INDEX ] [ ENTRY_1_INDEX ] ... [ ENTRY_N_INDEX ]
```

Each index record:
```
[ ID: 16 bytes UUID ]
[ NAME_LEN: uint16 ][ NAME: UTF-8 ]
[ WEBSITE_LEN: uint16 ][ WEBSITE: UTF-8 ]
[ USERNAME_LEN: uint16 ][ USERNAME: UTF-8 ]
[ CREATED_AT: uint64 ]
[ UPDATED_AT: uint64 ]
[ EXPIRES_AT: uint64 ]  ← 0 means no expiration
```

**Entry password ciphertext plaintext format (per entry):**
```
[ PASSWORD_LEN: uint16 ][ PASSWORD: UTF-8 ]
```

---

## 7. Key Rotation

When the user changes their master password:

1. Derive a new vault key from the new master password with a **fresh salt**.
2. Generate a new verification token encrypted under the new vault key with a fresh IV.
3. Reset `save_counter` to 0 inside the payload (new key = new counter domain).
4. Update `master_password_changed_at` to the current Unix timestamp inside the payload.
5. Re-encrypt the index under the new vault key with a hybrid IV (counter=0 || random).
6. Re-derive all entry keys from the new vault key (`HKDF(new_vault_key, uuid)`) and re-encrypt all password ciphertexts.
7. Write the new vault file atomically.
8. Zero the old key from memory.
9. Transition session state from EXPIRED (or BROWSING) to BROWSING.

This means key rotation is O(number of entries), since each entry password must be re-encrypted under the new entry key. The old vault file is overwritten; there is no key history stored.

---

## 8. Security Assumptions & Limitations

### Assumptions
- The OS and OpenSSL installation are trusted and not compromised.
- The filesystem provides atomic `rename()` semantics (POSIX).
- Hardware AES-NI is available for constant-time AES operations.
- The user's master password has sufficient entropy (no enforcement; this is a usability tradeoff).

### Limitations
- **No anti-keylogger protection.** Master password entry is vulnerable to OS-level keyloggers.
- **No swap encryption.** The secure heap provides mlock for its arena, but other process memory could theoretically be paged.
- **Single vault file.** No multi-vault or multi-user support.
- **No clipboard manager interaction.** Some clipboard managers log clipboard history; cleared clipboard data may persist there.
- **No integrity protection on the vault file path/name.** Vault file can be silently replaced with another valid vault (an attacker would need a valid key for it, so this is low-severity).
- **No protection against a malicious vault file triggering parser bugs.** Length fields in the payload are validated but deserve fuzzing.
- **Expiry relies on system clock.** A user (or attacker with access) could manipulate the system clock to bypass or accelerate expiry.
- **v0.1 vaults not backwards compatible.** Migration utility required.

---

## 9. Design Decisions & Rationale

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| KDF | Argon2id | PBKDF2, scrypt | Argon2id is the current recommended standard (RFC 9106). Resistant to GPU and side-channel attacks. Available in OpenSSL 3.2+. |
| Key hierarchy | HKDF-SHA256 per entry | Single key for all, separate Argon2id per entry | HKDF is computationally cheap (vs another Argon2id call) while providing cryptographic domain separation. Standard construction per RFC 5869. |
| AEAD scheme | AES-256-GCM | ChaCha20-Poly1305, AES-CBC+HMAC | GCM is hardware-accelerated on x86. Single-pass AEAD avoids MAC ordering pitfalls. Standardized and audited in OpenSSL. |
| Storage format | Two-layer encrypted binary | Single blob (v0.1), SQLite | Per-entry encryption eliminates bulk password exposure in RAM. Binary format leaks no metadata. |
| Session model | Two-step (LOCKED → BROWSING → RETRIEVING) | Single unlock, always-locked | Protects against opportunistic access to an unlocked session without leaking metadata on disk. |
| Re-authentication method | Verification token | Re-derive and compare keys directly | Token approach avoids storing the key anywhere. Standard industry pattern (used by VeraCrypt, KeePass). |
| BROWSING memory layout | No password fields at all (v0.2) | Zero password fields (v0.1) | Eliminates even the transient window where passwords exist in RAM during unlock. |
| Nonce strategy | Hybrid IV: counter(4B) ‖ random(8B) per NIST SP 800-38D §8.2.2 | Fully random 96-bit, counter-only | Counter guarantees uniqueness; random field adds unpredictability. Counter stored inside encrypted payload (tamper-proof). |
| Secure memory | OpenSSL secure heap (v0.2) | Manual mlock + new[] (v0.1) | Secure heap provides guard pages, MADV_DONTDUMP, and mlock automatically. Less error-prone than manual mlock. |
| Process hardening | prctl + setrlimit | None (v0.1) | Blocks ptrace attachment and core dumps at negligible cost. |
| AAD scope | Header fields (magic through KDF params) | None, or full header | Authenticating the header prevents an attacker from silently downgrading KDF parameters. |
| Atomic writes | `write tmp → rename` | Direct overwrite | Prevents vault corruption if the process is killed mid-write. |
| Memory zeroing | `OPENSSL_cleanse()` | `memset()` | `memset()` can be optimized away by the compiler. `OPENSSL_cleanse()` is guaranteed not to be elided. |
| Master password expiry | Time-based, stored in encrypted payload | Usage-count-based, plaintext header | Time-based expiry aligns with industry standards. Storing in encrypted payload prevents tampering. |
| UUID generation | RAND_bytes + RFC 4122 v4 bits | Sequential IDs, external UUID library | CSPRNG-based UUIDs are unpredictable (needed for HKDF info). No external dependency. |
| Build system | CMake | Makefile, Meson | CMake is the de facto standard for C++ projects, with good IDE integration and `find_package(OpenSSL)` support. |
