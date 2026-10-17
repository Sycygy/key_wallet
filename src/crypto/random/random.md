# crypto/random

Cryptographically secure random byte and password generation backed by OpenSSL's private DRBG (`RAND_priv_bytes`).

## Files

| File | Purpose |
|---|---|
| `random.hpp` | Public API — `random_bytes()` and `generate_password()` |
| `random.cpp` | Implementation — internal helpers `pick_one()` and `secure_shuffle()` |

---

## Public API

### `random_bytes(size_t n) → SecureBuffer`

Returns `n` cryptographically random bytes in a `SecureBuffer` (RAII wrapper with `mlock` + `OPENSSL_cleanse` on destruction).

- Passing `n = 0` returns an empty buffer (safe, no-op).
- Throws `std::invalid_argument` if `n > INT_MAX`.
- Throws `std::runtime_error` if the PRNG is not seeded.

Intended use: generating salts, nonces, and IVs elsewhere in the vault.

---

### `generate_password(size_t length, CharsetFlags flags = Charset::All) → std::string`

Generates a random password of exactly `length` characters drawn from the character sets selected by `flags`.

#### Character set flags (`Charset::` namespace)

| Flag | Characters |
|---|---|
| `Charset::Uppercase` | `A–Z` (26) |
| `Charset::Lowercase` | `a–z` (26) |
| `Charset::Digits` | `0–9` (10) |
| `Charset::Symbols` | `!@#$%^&*()-_=+[]{}|;:,.<>?/` (28) |
| `Charset::All` | All of the above (90 total) |

Flags can be combined with `|`:
```cpp
generate_password(16, Charset::Uppercase | Charset::Digits);
```

**Guarantees:**
- At least one character from each requested charset appears in the result.
- No modulo bias — rejection sampling is used throughout.
- Result is cryptographically shuffled so mandatory characters do not cluster at predictable positions.

**Throws:**
- `std::invalid_argument` if `length == 0`, `flags == 0`, or `length < number of requested charsets`.
- `std::runtime_error` if the PRNG fails.

---

## Implementation details

### Why `RAND_priv_bytes` instead of `RAND_bytes`

OpenSSL maintains two separate DRBG instances. `RAND_priv_bytes` draws from the *private* instance, which is never used for public material (nonces, IVs). This ensures that generating a password does not weaken the entropy pool used for nonce generation and vice versa.

### Rejection sampling (modulo bias elimination)

Naively mapping a random byte to a pool of size `N` via `byte % N` over-represents values `0..(255 % N)` because 256 is rarely a multiple of `N`. This implementation computes the largest multiple of `N` that fits in the sample space and discards any byte at or above it, then retries. The rejection rate is at most `N / 256 < 0.4%` for the largest pool (90 chars).

### Fisher-Yates shuffle (`secure_shuffle`)

After assembling the password, a standard Fisher-Yates shuffle is applied. Each swap index is drawn from a 32-bit sample space (not a single byte) so the shuffle works correctly for strings of any length — a single-byte range would produce a zero threshold and an infinite loop for strings longer than 256 characters.

### Three-phase generation

```
Phase 1  Pick one guaranteed character from each requested charset.
Phase 2  Fill the remaining slots from the combined pool (256-byte chunks to amortise RAND_priv_bytes call overhead).
Phase 3  Shuffle the result so Phase 1 characters land at random positions.
```