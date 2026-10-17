#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>
#include "core/secure_buffer.hpp"

/// AES-256-GCM constants
inline constexpr size_t AEAD_IV_LEN      = 12;  // 96-bit nonce
inline constexpr size_t AEAD_TAG_LEN     = 16;  // 128-bit auth tag
inline constexpr size_t AEAD_KEY_LEN     = 32;  // 256-bit key
inline constexpr size_t AEAD_IV_COUNTER_LEN = 4;   // fixed field  (counter, LE)
inline constexpr size_t AEAD_IV_RANDOM_LEN  = 8;   // invocation field (random)

/// Result of an AES-256-GCM encryption operation.
struct AeadCiphertext {
    std::vector<unsigned char> iv;          // 12 bytes
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;         // 16 bytes
};

/**
 * @brief Encrypt using a fully random 12-byte IV.
 *
 * Intended for the verification token, which is encrypted only on vault
 * creation and change-master (at most a handful of times per key lifetime).
 *
 * @param key       32-byte encryption key.
 * @param plaintext Data to encrypt.
 * @param pt_len    Length of plaintext in bytes.
 * @param aad       Additional authenticated data (may be nullptr if aad_len == 0).
 * @param aad_len   Length of AAD in bytes.
 * @return AeadCiphertext containing IV, ciphertext, and authentication tag.
 * @throws std::invalid_argument if key is null/wrong size.
 * @throws std::runtime_error on encryption failure.
 */
AeadCiphertext aead_encrypt(const SecureBuffer& key,
                            const unsigned char* plaintext, size_t pt_len,
                            const unsigned char* aad = nullptr, size_t aad_len = 0);

/**
 * @brief Encrypt using a hybrid IV: counter(4B, LE) || random(8B).
 *
 * Per NIST SP 800-38D Section 8.2.2 deterministic construction.
 * The counter guarantees uniqueness; the random field adds unpredictability.
 * Intended for main vault encryption where save_counter is available.
 *
 * @param key        32-byte encryption key.
 * @param plaintext  Data to encrypt.
 * @param pt_len     Length of plaintext in bytes.
 * @param iv_counter Monotonic counter value (stored as first 4 bytes of IV, LE).
 * @param aad        Additional authenticated data (may be nullptr if aad_len == 0).
 * @param aad_len    Length of AAD in bytes.
 * @return AeadCiphertext containing hybrid IV, ciphertext, and authentication tag.
 * @throws std::invalid_argument if key is null/wrong size.
 * @throws std::runtime_error on encryption failure.
 */
AeadCiphertext aead_encrypt(const SecureBuffer& key,
                            const unsigned char* plaintext, size_t pt_len,
                            uint32_t iv_counter,
                            const unsigned char* aad = nullptr, size_t aad_len = 0);

/**
 * @brief Decrypt ciphertext using AES-256-GCM and verify authenticity.
 *
 * Works with both fully random and hybrid IVs — the decrypt side is identical
 * since it receives the full 12-byte IV stored alongside the ciphertext.
 *
 * @param key        32-byte encryption key.
 * @param iv         12-byte initialisation vector.
 * @param ciphertext Encrypted data.
 * @param ct_len     Length of ciphertext in bytes.
 * @param tag        16-byte authentication tag.
 * @param aad        Additional authenticated data (may be nullptr if aad_len == 0).
 * @param aad_len    Length of AAD in bytes.
 * @return SecureBuffer containing the decrypted plaintext.
 * @throws std::invalid_argument if key/iv/tag is null or wrong size.
 * @throws std::runtime_error on decryption or tag verification failure.
 */
SecureBuffer aead_decrypt(const SecureBuffer& key,
                          const unsigned char* iv,
                          const unsigned char* ciphertext, size_t ct_len,
                          const unsigned char* tag,
                          const unsigned char* aad = nullptr, size_t aad_len = 0);