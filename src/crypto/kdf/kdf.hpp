#pragma once

#include <cstddef>
#include "core/secure_buffer.hpp"

/**
 * @brief Derive a 32-byte key from a master password and salt using Argon2id.
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
 * @param password     Pointer to the master password bytes.
 * @param password_len Length of the master password in bytes.
 * @param salt         Pointer to the salt bytes (must be exactly 16 bytes).
 * @param salt_len     Length of the salt in bytes.
 * @return SecureBuffer of exactly 32 bytes containing the derived key.
 * @throws std::invalid_argument if password or salt is null, or salt_len != 16.
 * @throws std::runtime_error if Argon2id derivation fails.
 */
SecureBuffer derive_key(const unsigned char* password, size_t password_len,
                        const unsigned char* salt,     size_t salt_len);