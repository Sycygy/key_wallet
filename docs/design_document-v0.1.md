# key_manager — Design Document & Threat Model
**Project:** Secure Password Manager  
**Language:** C++  
**Crypto Library:** OpenSSL 3.2+  
**Version:** 0.1

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

The application also enforces **master password expiry**: the vault tracks when the master password was last changed and hard-blocks all operations once the configurable expiry period elapses, forcing the user to rotate before continuing.

The system operates entirely offline. There is no network communication, no cloud sync, and no shared state between users.

---

## 2. Threat Model

### 2.1 Assets to Protect

| Asset | Sensitivity | Description |
|-------|-------------|-------------|
| Master password | Critical | Never stored; must not be recoverable from any artifact |
| Derived encryption key | Critical | Held in memory only during an active session |
| Vault plaintext | Critical | Website, username, and password for each entry |
| Vault ciphertext | High | Must resist offline brute-force and tampering |
| Session state | Medium | Unlocked vault in memory during use |
| Password expiry metadata | Medium | Last-changed timestamp and expiry interval; stored inside encrypted payload to prevent tampering |

### 2.2 Attacker Profiles

#### Attacker A — Disk/File Access (Primary Threat)
- **Capability:** Read-only or read-write access to the vault file on disk (e.g., stolen laptop, shared filesystem, malware exfiltrating files).
- **Goal:** Recover plaintext credentials without knowing the master password.
- **Mitigation:** AES-256-GCM encryption ensures confidentiality; authentication tag prevents undetected tampering. Argon2id with strong parameters makes offline brute-force computationally infeasible.

#### Attacker B — Memory Inspection (Secondary Threat)
- **Capability:** Can read process memory during an active session (e.g., local malware, ptrace attach, core dump analysis).
- **Goal:** Extract the master password or derived key from memory.
- **Mitigation:** Master password is zeroed immediately after key derivation using `OPENSSL_cleanse`. Derived key is held in a dedicated memory region, zeroed on lock/exit. Auto-lock minimizes the window of exposure.

#### Attacker C — Physical Access / Cold Boot (Tertiary Threat)
- **Capability:** Physical access to a running or recently-powered-off machine.
- **Goal:** Extract keys or plaintext from RAM.
- **Mitigation:** Short session timeout, eager memory zeroing. Full mitigation against cold boot attacks is outside scope for this version (would require OS-level memory encryption).

#### Attacker D — Malicious Vault Modification
- **Capability:** Can modify the vault file on disk between sessions.
- **Goal:** Inject or alter entries without detection, or cause the application to behave unexpectedly.
- **Mitigation:** AES-256-GCM provides authenticated encryption; any modification to the ciphertext or AAD will cause decryption to fail with an explicit integrity error. The vault is treated as fully untrusted input.

#### Attacker E — Shoulder Surfing / Screen Capture
- **Capability:** Visual observation of the terminal.
- **Goal:** Observe master password or retrieved credentials.
- **Mitigation:** Master password input is masked (no echo). Retrieved passwords are optionally written to clipboard (cleared after timeout) rather than printed to stdout.

#### Attacker F — Unlocked Session Opportunistic Access
- **Capability:** Briefly accesses a logged-in terminal while the user is away (e.g., unlocked workstation).
- **Goal:** Retrieve stored passwords without knowing the master password.
- **Mitigation:** Two-step authentication model. BROWSING state exposes only entry names and metadata. Retrieving any password requires re-entering the master password, verified against the vault's stored verification token.

### 2.3 Out-of-Scope Threats

- **Compromised OpenSSL library:** We assume the system's OpenSSL 3.2+ installation is trustworthy.
- **Keyloggers:** A keylogger operating at the OS level can capture the master password before it reaches the application. This is out of scope.
- **Side-channel attacks on AES:** We rely on OpenSSL's AES-NI hardware acceleration, which provides constant-time implementations on supported hardware.
- **Vault file metadata:** File creation time, size, and inode information may leak that a vault exists. Not addressed in this version.

---

## 3. Cryptographic Design

### 3.1 Key Derivation — Argon2id

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
master_password + salt  ──►  Argon2id  ──►  encryption_key (32 bytes)
                              (64MiB, t=3, p=4)
```

The salt is stored in the vault header in plaintext. It is not secret — its purpose is uniqueness, not confidentiality.

### 3.2 Authenticated Encryption — AES-256-GCM

**Algorithm:** AES-256-GCM  
**OpenSSL API:** `EVP_EncryptInit_ex2` / `EVP_CIPHER_CTX`

| Parameter | Value |
|-----------|-------|
| Key size | 256 bits (32 bytes) |
| IV (nonce) | 96 bits (12 bytes), hybrid construction (see below) |
| Authentication tag | 128 bits (16 bytes) |
| AAD | Vault format version + creation timestamp |

**Why GCM over CBC-HMAC?** GCM provides both confidentiality and integrity in a single pass with a clean, standardized API. CBC with a separate HMAC is error-prone to implement correctly (MAC-then-Encrypt vs Encrypt-then-MAC ordering). GCM natively produces an authentication tag, and OpenSSL's EVP interface handles this correctly.

**Nonce handling — hybrid construction (NIST SP 800-38D §8.2.2):**

The main vault ciphertext uses a **hybrid IV** composed of a deterministic counter and a random field:

```
IV (12 bytes) = [ counter (4 bytes, LE) ] || [ random (8 bytes) ]
```

| Component | Size | Source |
|-----------|------|--------|
| Counter (fixed field) | 4 bytes | Monotonic `save_counter` from encrypted payload, incremented on every save |
| Random (invocation field) | 8 bytes | `RAND_bytes()` per encryption call |

The counter guarantees **uniqueness**: even if `RAND_bytes()` were to repeat, the counter value will differ. The random portion adds **unpredictability**. Together they satisfy NIST's deterministic construction requirements.

The counter is stored inside the encrypted payload (`SAVE_COUNTER`, see §6), making it tamper-proof. On `create_vault`, the counter starts at 0. On every `save_vault`, the counter is incremented before encryption.

**Verification token IV:** The verification token uses a fully random 12-byte IV (no counter), since it is only encrypted on vault creation and `change-master` — at most a handful of times over a vault's lifetime.

### 3.3 Password Generation

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

### 3.4 Master Password Verification Token

To support the two-step authentication model without storing the master password or derived key, the vault header contains a **verification token** — a fixed known plaintext encrypted under the derived key.

**Construction (at vault creation):**
```
token_plaintext  = 0x00 × 32          (32 zero bytes)
token_iv         = RAND_bytes(12)      (fresh random IV)
token_ciphertext, token_tag = AES-256-GCM.encrypt(
    key    = derived_key,
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

**Why not compare derived keys directly?** The derived key is not stored anywhere. Comparing it would require either storing it (a security risk) or re-deriving it (which is exactly what this approach does implicitly via decryption). The token approach is the standard industry pattern.

### 3.5 Master Password Expiry

The vault stores two values inside the **encrypted payload** (not the header) to enforce master password rotation:

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

**EXPIRED state** is a fourth session state inserted between LOCKED and BROWSING:

```
LOCKED → unlock() → check expiry
                         │
              ┌──────────┴──────────┐
          not expired           expired
              │                    │
          BROWSING             EXPIRED
                                   │
                           change-master only
                                   │
                          (rotation succeeds)
                                   │
                               BROWSING
```

**Warning period:** Starting 7 days before the deadline, every unlock displays a non-blocking warning: `"Master password expires in N days. Consider changing it soon."` The user can continue normally during the warning period.

**Configuring the expiry interval:**

```
key_manager config --expiry-days <N>    # set custom interval (0 = disable)
key_manager config --show               # display current expiry settings
```

Changing `expiry_days` is a vault write operation and requires re-authentication.

### 3.6 Memory Safety

- Master password buffer: zeroed with `OPENSSL_cleanse()` immediately after key derivation.
- Derived key: stored in a `SecureBuffer` wrapper (see `core/`) that calls `OPENSSL_cleanse()` in its destructor.
- Vault plaintext in memory: zeroed on lock and on application exit.
- In BROWSING state, **password fields of all entries are zeroed** in memory — only name and metadata fields are retained.
- `mlock()` is called on sensitive buffers where the OS permits, to prevent paging to swap.

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
     → Argon2id → derive key                      │
     → decrypt vault                              │
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
     (password fields zeroed in memory)
              │
     user selects entry
     → prompt master password
     → verify_master_password()
              │
              ▼
          RETRIEVING
     (single entry password revealed)
              │
     password shown / copied to clipboard
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

Write operations (`add`, `update`, `delete`, `change-master`) also require re-authentication. This prevents an attacker with brief session access from silently modifying the vault.

### 4.3 BROWSING State Memory Layout

When the vault transitions from LOCKED to BROWSING, the decrypted payload is split in memory:

```
BrowsableEntry {
    id          : UUID        ← kept in memory
    name        : string      ← kept in memory
    username    : string      ← kept in memory
    website     : string      ← kept in memory
    created_at  : uint64      ← kept in memory
    updated_at  : uint64      ← kept in memory
    expires_at  : uint64      ← kept in memory
    password    : SecureBuffer ← ZEROED, not accessible
}
```

The full `PasswordEntry` (with password) is only reconstructed in memory for the duration of a RETRIEVING operation, then immediately zeroed again.

---

## 5. System Architecture

```
key_manager/
├── CMakeLists.txt
├── src/
│   ├── main.cpp                  # Entry point, CLI dispatch
│   ├── crypto/
│   │   ├── kdf.hpp / kdf.cpp     # Argon2id key derivation
│   │   ├── aead.hpp / aead.cpp   # AES-256-GCM encrypt/decrypt
│   │   └── random.hpp / random.cpp  # Secure password generation
│   ├── storage/
│   │   ├── vault.hpp / vault.cpp # Vault file read/write, binary format
│   │   └── entry.hpp / entry.cpp # PasswordEntry model
│   ├── core/
│   │   ├── session.hpp / session.cpp  # Session lifecycle, auto-lock
│   │   └── secure_buffer.hpp    # RAII wrapper for sensitive memory
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
    ├── key_manager_design.md     # This document
    ├── user_manual.md
    └── security_analysis.md
```

### Module Responsibilities

**`crypto/kdf`** — Wraps OpenSSL's EVP_KDF interface for Argon2id. Accepts a password and salt, returns a 32-byte key. Stateless.

**`crypto/aead`** — Wraps AES-256-GCM encrypt/decrypt. Handles IV generation, tag verification. Returns `std::expected<>` or throws on auth failure.

**`crypto/random`** — Wraps `RAND_bytes`. Provides `generate_password(length, charset)` and `random_bytes(n)`.

**`storage/entry`** — Plain data struct: `{ id, website, username, password, created_at, updated_at }`. Serialized to/from a binary format.

**`storage/vault`** — Manages the on-disk vault file. Loads the encrypted blob, calls `aead::decrypt`, deserializes entries. On save: serializes, calls `aead::encrypt`, writes to disk atomically (write to `.tmp`, then `rename()`).

**`core/session`** — Implements the LOCKED / BROWSING / RETRIEVING state machine. Holds the decrypted vault in memory with passwords zeroed in BROWSING state. Provides `unlock()`, `lock()`, `verify_master_password()`, and auto-lock timer. Exposes vault operations to the CLI layer, enforcing state permissions.

**`core/secure_buffer`** — RAII wrapper: allocates memory, optionally calls `mlock()`, zeros and unlocks on destruction.

**`cli/commands`** — Implements `add`, `get`, `list`, `update`, `delete`, `generate`, `change-master`. Calls into `core/session`.

**`cli/input`** — Reads masked passwords from the terminal (`termios` on POSIX). Handles clipboard write + delayed clear.

---

## 6. Vault File Format

The vault is a single binary file with the following layout. All multi-byte integers are stored in **little-endian** format.

```
┌─────────────────────────────────────────────┐
│  MAGIC (8 bytes): "KEYMGR\x01\x00"          │
├─────────────────────────────────────────────┤
│  FORMAT VERSION (2 bytes): uint16           │
├─────────────────────────────────────────────┤
│  CREATED_AT (8 bytes): uint64 (Unix time)   │
├─────────────────────────────────────────────┤
│  SALT (16 bytes): Argon2id salt             │
├─────────────────────────────────────────────┤
│  ARGON2_PARAMS (12 bytes):                  │
│    m_cost: uint32                           │
│    t_cost: uint32                           │
│    parallelism: uint32                      │
├─────────────────────────────────────────────┤  ← AAD boundary (all above is authenticated)
│  VERIFY_TOKEN_IV (12 bytes)                 │
├─────────────────────────────────────────────┤
│  VERIFY_TOKEN_TAG (16 bytes)                │
├─────────────────────────────────────────────┤
│  VERIFY_TOKEN_CIPHERTEXT (32 bytes)         │
├─────────────────────────────────────────────┤
│  IV / NONCE (12 bytes): AES-GCM nonce       │
├─────────────────────────────────────────────┤
│  AUTH TAG (16 bytes): GCM tag               │
├─────────────────────────────────────────────┤
│  CIPHERTEXT LENGTH (4 bytes): uint32        │
├─────────────────────────────────────────────┤
│  CIPHERTEXT (variable): encrypted payload   │
└─────────────────────────────────────────────┘
```

**AAD (Additional Authenticated Data):** The fields from MAGIC through ARGON2_PARAMS (inclusive) are fed as AAD into both the verification token encryption and the main vault AES-GCM encryption. They are authenticated but not encrypted. This ensures that even unencrypted metadata (format version, KDF parameters) cannot be silently tampered with.

**The verification token** (VERIFY_TOKEN_IV / TAG / CIPHERTEXT) sits between the AAD region and the main vault ciphertext. It uses the same derived key and same AAD, but an independent IV and tag.

**Encrypted payload format (plaintext inside the ciphertext):**

```
[ SAVE_COUNTER: uint32 ]                 ← Monotonic counter for hybrid IV construction (starts at 0)
[ MASTER_PASSWORD_CHANGED_AT: uint64 ]   ← Unix timestamp of last change-master
[ MASTER_PASSWORD_EXPIRY_DAYS: uint32 ]  ← 0 = disabled, default = 30
[ ENTRY_COUNT: uint32 ]
[ ENTRY_0 ] [ ENTRY_1 ] ... [ ENTRY_N ]
```

Each entry:
```
[ ID: 16 bytes UUID ]
[ NAME_LEN: uint16 ][ NAME: UTF-8 ]
[ WEBSITE_LEN: uint16 ][ WEBSITE: UTF-8 ]
[ USERNAME_LEN: uint16 ][ USERNAME: UTF-8 ]
[ PASSWORD_LEN: uint16 ][ PASSWORD: UTF-8 ]
[ CREATED_AT: uint64 ]
[ UPDATED_AT: uint64 ]
[ EXPIRES_AT: uint64 ]  ← 0 means no expiration
```

---

## 7. Key Rotation

When the user changes their master password:

1. Derive a new key from the new master password with a **fresh salt**.
2. Generate a new verification token encrypted under the new key with a fresh IV.
3. Reset `save_counter` to 0 inside the payload (new key = new counter domain).
4. Update `master_password_changed_at` to the current Unix timestamp inside the payload.
5. Re-encrypt the entire vault payload under the new key with a hybrid IV (counter=0 || random).
6. Write the new vault file atomically.
7. Zero the old key from memory.
8. Transition session state from EXPIRED (or BROWSING) to BROWSING.

This means key rotation is O(vault size), not O(number of entries). The old vault file is overwritten; there is no key history stored. Resetting `master_password_changed_at` restarts the expiry countdown from the moment of rotation.

---

## 8. Security Assumptions & Limitations

### Assumptions
- The OS and OpenSSL installation are trusted and not compromised.
- The filesystem provides atomic `rename()` semantics (POSIX).
- Hardware AES-NI is available for constant-time AES operations.
- The user's master password has sufficient entropy (no enforcement; this is a usability tradeoff).

### Limitations (v0.3)
- **No anti-keylogger protection.** Master password entry is vulnerable to OS-level keyloggers.
- **No swap encryption.** `mlock()` is best-effort; on systems where it fails (e.g., limits exceeded), sensitive data may be paged to swap.
- **Single vault file.** No multi-vault or multi-user support.
- **No clipboard manager interaction.** Some clipboard managers log clipboard history; cleared clipboard data may persist there.
- **No integrity protection on the vault file path/name.** Vault file can be silently replaced with another valid vault (an attacker would need a valid key for it, so this is low-severity).
- **No protection against a malicious vault file triggering parser bugs.** Length fields in the payload are validated but deserve fuzzing.
- **Expiry relies on system clock.** A user (or attacker with access) could manipulate the system clock to bypass or accelerate expiry. Fully preventing this would require a trusted time source, which is out of scope for a local-only tool.

---

## 9. Design Decisions & Rationale

| Decision | Chosen | Alternatives Considered | Rationale |
|----------|--------|------------------------|-----------|
| KDF | Argon2id | PBKDF2, scrypt | Argon2id is the current recommended standard (RFC 9106). Resistant to GPU and side-channel attacks. Available in OpenSSL 3.2+. |
| AEAD scheme | AES-256-GCM | ChaCha20-Poly1305, AES-CBC+HMAC | GCM is hardware-accelerated on x86. Single-pass AEAD avoids MAC ordering pitfalls. Standardized and audited in OpenSSL. |
| Storage format | Fully encrypted binary blob | Plaintext JSON + encrypted fields, SQLite | A single encrypted blob leaks no metadata about entry count, websites, or usernames. Simpler to reason about than partial encryption. |
| Session model | Two-step (LOCKED → BROWSING → RETRIEVING) | Single unlock, always-locked | Protects against opportunistic access to an unlocked session without leaking metadata on disk. Industry pattern used by hardware security keys. |
| Re-authentication method | Verification token (Option B) | Re-derive and compare keys directly | Token approach avoids storing the key anywhere. Re-derivation is implicitly performed via decryption. Standard industry pattern (used by VeraCrypt, KeePass). |
| BROWSING memory layout | Zero password fields, keep metadata | Keep all fields, re-zero on lock | Minimizes window where passwords are in memory. An attacker with memory access during BROWSING cannot read passwords. |
| Nonce strategy | Hybrid IV: counter(4B) ‖ random(8B) per NIST SP 800-38D §8.2.2 | Fully random 96-bit, counter-only | Counter guarantees uniqueness; random field adds unpredictability. Counter stored inside encrypted payload (tamper-proof, resets on key rotation). Verification token uses fully random IV since it is encrypted at most a few times per key lifetime. |
| AAD scope | Header fields (magic through KDF params) | None, or full header | Authenticating the header prevents an attacker from silently downgrading KDF parameters (e.g., lowering Argon2 memory cost to speed up brute-force). |
| Atomic writes | `write tmp → rename` | Direct overwrite | Prevents vault corruption if the process is killed mid-write. POSIX `rename()` is atomic on the same filesystem. |
| Memory zeroing | `OPENSSL_cleanse()` | `memset()` | `memset()` can be optimized away by the compiler. `OPENSSL_cleanse()` is guaranteed not to be elided. |
| Master password expiry | Time-based, stored in encrypted payload | Usage-count-based, plaintext header | Time-based expiry aligns with industry standards (NIST SP 800-63B). Storing in the encrypted payload prevents an attacker from resetting the counter without the master password. Clock manipulation is acknowledged as a residual limitation. |
| Expiry enforcement | Hard block (EXPIRED state) | Warn only, soft block | Hard block ensures the policy is actually enforced and not ignored. The 7-day warning window gives users adequate notice before being blocked. |
| Build system | CMake | Makefile, Meson | CMake is the de facto standard for C++ projects, with good IDE integration and `find_package(OpenSSL)` support. |
