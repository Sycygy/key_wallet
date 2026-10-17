#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include "core/secure_buffer.hpp"

/**
 * @brief Derive a 32-byte vault key from a master password and salt using Argon2id.
 *
 * @details Uses OpenSSL's EVP_KDF interface with fixed parameters:
 *   - Memory cost : 65536 KiB (64 MiB)
 *   - Time cost   : 3 iterations
 *   - Parallelism : 4 lanes
 *   - Output      : 32 bytes (256-bit key)
 *
 * The function is deterministic: identical (password, salt) pairs always
 * produce identical output. Callers must use a fresh random salt per vault
 * to ensure key uniqueness.
 *
 * @note Renamed from derive_key() in v0.1 for clarity — the vault key now
 *       decrypts only the index section. Per-entry keys are derived via
 *       derive_entry_key().
 *
 * @param password     Pointer to the master password bytes.
 * @param password_len Length of the master password in bytes.
 * @param salt         Pointer to the salt bytes (must be exactly 16 bytes).
 * @param salt_len     Length of the salt in bytes.
 * @return SecureBuffer of exactly 32 bytes containing the derived vault key.
 * @throws std::invalid_argument if password or salt is null, or salt_len != 16.
 * @throws std::runtime_error if Argon2id derivation fails.
 */
SecureBuffer derive_vault_key(const unsigned char* password, size_t password_len,
                              const unsigned char* salt,     size_t salt_len);

/**
 * @brief Derive a 32-byte per-entry key from the vault key and entry UUID.
 *
 * @details Uses HKDF-SHA256 (RFC 5869) via OpenSSL's EVP_KDF interface:
 *   - PRK (extract phase): vault_key (already high-entropy, so extract is a formality)
 *   - Info: "vault-entry-key:" + hex(uuid) — binds the derived key to a specific entry
 *   - Salt: empty (HKDF uses a zero-filled salt internally when none is provided)
 *   - Output: 32 bytes (256-bit key)
 *
 * The computational cost is negligible (a few HMAC-SHA256 calls), so deriving
 * entry keys on demand is practical even for large vaults.
 *
 * @param vault_key The 32-byte vault key derived from Argon2id.
 * @param uuid      16-byte entry UUID (used as domain separator in the info string).
 * @return SecureBuffer of exactly 32 bytes containing the entry key.
 * @throws std::invalid_argument if vault_key is empty or wrong size.
 * @throws std::runtime_error if HKDF derivation fails.
 */
SecureBuffer derive_entry_key(const SecureBuffer& vault_key,
                              const std::array<uint8_t, 16>& uuid);
