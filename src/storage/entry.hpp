#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include "core/secure_buffer.hpp"

/// Maximum allowed length for string fields (prevents buffer overflow on malformed input).
inline constexpr uint16_t ENTRY_MAX_STRING_LEN = 4096;

/**
 * @brief Full password entry — used only during RETRIEVING state.
 *
 * Contains all fields including the password. The password is stored in a
 * SecureBuffer so it is zeroed on destruction via OPENSSL_secure_clear_free.
 */
struct PasswordEntry {
    std::array<uint8_t, 16> id{};       // UUID v4
    std::string             name;
    std::string             website;
    std::string             username;
    SecureBuffer            password;    // decrypted on demand, destroyed by RAII
    uint64_t                created_at{};
    uint64_t                updated_at{};
    uint64_t                expires_at{}; // 0 = no expiry
};

/**
 * @brief Browsable entry — used in BROWSING state. No password field.
 *
 * Passwords are never loaded into RAM during BROWSING. This struct contains
 * only the index metadata that is decrypted when the vault is unlocked.
 */
struct BrowsableEntry {
    std::array<uint8_t, 16> id{};       // UUID v4
    std::string             name;
    std::string             website;
    std::string             username;
    uint64_t                created_at{};
    uint64_t                updated_at{};
    uint64_t                expires_at{}; // 0 = no expiry
};

/**
 * @brief Serialize a single entry's index record (everything except password).
 *
 * Binary format (little-endian):
 *   ID (16) | NAME_LEN (2) | NAME | WEBSITE_LEN (2) | WEBSITE |
 *   USERNAME_LEN (2) | USERNAME | CREATED_AT (8) | UPDATED_AT (8) | EXPIRES_AT (8)
 *
 * @param entry The entry to serialize (works with both PasswordEntry and BrowsableEntry).
 * @return Binary representation of the index record.
 * @throws std::invalid_argument if any string field exceeds ENTRY_MAX_STRING_LEN.
 */
std::vector<uint8_t> serialize_index(const BrowsableEntry& entry);
std::vector<uint8_t> serialize_index(const PasswordEntry& entry);

/**
 * @brief Serialize a single entry's password field.
 *
 * Binary format (little-endian):
 *   PASSWORD_LEN (2) | PASSWORD (UTF-8)
 *
 * @param password The password stored in a SecureBuffer.
 * @return Binary representation of the password record.
 * @throws std::invalid_argument if password exceeds ENTRY_MAX_STRING_LEN.
 */
SecureBuffer serialize_password(const SecureBuffer& password);

/**
 * @brief Deserialize an index record into a BrowsableEntry.
 *
 * @param data   Pointer to the start of the serialized index record.
 * @param len    Number of bytes available.
 * @param bytes_read Set to the number of bytes consumed on success.
 * @return Deserialized BrowsableEntry.
 * @throws std::runtime_error if data is malformed or truncated.
 */
BrowsableEntry deserialize_index(const uint8_t* data, size_t len, size_t& bytes_read);

/**
 * @brief Deserialize a password record into a SecureBuffer.
 *
 * @param data   Pointer to the start of the serialized password record.
 * @param len    Number of bytes available.
 * @param bytes_read Set to the number of bytes consumed on success.
 * @return SecureBuffer containing the password bytes.
 * @throws std::runtime_error if data is malformed or truncated.
 */
SecureBuffer deserialize_password(const uint8_t* data, size_t len, size_t& bytes_read);
