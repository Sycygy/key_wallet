#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "core/secure_buffer.hpp"
#include "storage/entry.hpp"

// ── Constants ────────────────────────────────────────────────────────────────

/// Magic bytes: "KEYMGR\x01\x00"
inline constexpr uint8_t VAULT_MAGIC[8] = {
    'K', 'E', 'Y', 'M', 'G', 'R', 0x01, 0x00
};
inline constexpr uint16_t VAULT_FORMAT_VERSION   = 2;
inline constexpr size_t   VAULT_SALT_LEN         = 16;
inline constexpr size_t   VAULT_VERIFY_PT_LEN    = 32;  // 32 zero bytes
inline constexpr uint32_t VAULT_DEFAULT_EXPIRY_DAYS = 30;

/// Fixed header size: MAGIC(8) + VERSION(2) + CREATED_AT(8) + SALT(16) + ARGON2_PARAMS(12) = 46
inline constexpr size_t VAULT_HEADER_LEN = 46;

// ── Expiry status ────────────────────────────────────────────────────────────

enum class ExpiryStatus {
    OK,         ///< Master password is valid, no warning needed
    WARNING,    ///< Expires within 7 days — non-blocking warning
    EXPIRED     ///< Past deadline — hard block (only change-master allowed)
};

// ── Encrypted entry block (in-memory representation of on-disk ciphertext) ──

struct EntryCiphertext {
    std::vector<uint8_t> iv;          // 12 bytes
    std::vector<uint8_t> tag;         // 16 bytes
    std::vector<uint8_t> ciphertext;  // variable
};

// ── Vault ────────────────────────────────────────────────────────────────────

/**
 * @brief In-memory representation of the two-layer encrypted vault.
 *
 * After load_vault(), the index (metadata) is decrypted into `entries` but
 * passwords remain as ciphertexts in `entry_passwords`. Individual passwords
 * are decrypted on demand via get_entry_password().
 */
struct Vault {
    // ── Header (plaintext, also used as AAD) ─────────────────────────────
    uint64_t                created_at{};
    std::array<uint8_t, 16> salt{};
    uint32_t                m_cost{65536};
    uint32_t                t_cost{3};
    uint32_t                parallelism{4};

    // ── Verification token (encrypted under vault_key) ───────────────────
    std::vector<uint8_t> verify_iv;
    std::vector<uint8_t> verify_tag;
    std::vector<uint8_t> verify_ciphertext;

    // ── Index metadata (decrypted on load) ───────────────────────────────
    uint32_t save_counter{0};
    uint64_t master_password_changed_at{0};
    uint32_t master_password_expiry_days{VAULT_DEFAULT_EXPIRY_DAYS};
    std::vector<BrowsableEntry> entries;

    // ── Per-entry encrypted passwords (kept as ciphertexts in RAM) ───────
    std::vector<EntryCiphertext> entry_passwords;

    // ── In-memory session state (not persisted) ──────────────────────────
    SecureBuffer vault_key;    ///< Held for HKDF derivation during session
    std::string  file_path;    ///< Path to the vault file on disk
};

// ── Vault API ────────────────────────────────────────────────────────────────

/**
 * @brief Build the AAD bytes from a vault's header fields.
 *
 * AAD = MAGIC(8) + VERSION(2) + CREATED_AT(8) + SALT(16) + ARGON2_PARAMS(12)
 */
std::vector<uint8_t> build_aad(const Vault& vault);

/**
 * @brief Create a new empty vault file on disk.
 *
 * Generates a random salt, derives the vault key, creates the verification
 * token, and writes an empty index with no entries.
 *
 * @param path            File path for the new vault.
 * @param master_password Master password bytes.
 * @param mp_len          Length of master password.
 * @return Vault ready for use (vault_key populated, file written).
 * @throws std::runtime_error on I/O or crypto failure.
 */
Vault create_vault(const std::string& path,
                   const unsigned char* master_password, size_t mp_len);

/**
 * @brief Load an existing vault from disk, decrypting only the index.
 *
 * Passwords remain as ciphertexts in entry_passwords. Use get_entry_password()
 * to decrypt individual passwords on demand.
 *
 * @param path            File path to the vault.
 * @param master_password Master password bytes.
 * @param mp_len          Length of master password.
 * @return Vault with decrypted index and vault_key populated.
 * @throws std::runtime_error on wrong password, tampered file, or I/O error.
 */
Vault load_vault(const std::string& path,
                 const unsigned char* master_password, size_t mp_len);

/**
 * @brief Save the vault to disk atomically (write .tmp then rename).
 *
 * Increments save_counter, re-encrypts the index with a hybrid IV, and writes
 * all entry password ciphertexts. The vault_key must still be populated.
 *
 * @param vault The vault to save (save_counter is incremented in-place).
 * @throws std::runtime_error on I/O or crypto failure.
 */
void save_vault(Vault& vault);

/**
 * @brief Decrypt a single entry's password on demand.
 *
 * Derives entry_key = HKDF(vault_key, uuid), decrypts the entry's password
 * ciphertext, and returns a full PasswordEntry. The caller is responsible for
 * zeroing the returned password via RAII (SecureBuffer destructor).
 *
 * @param vault The loaded vault (must have vault_key and entry_passwords).
 * @param id    UUID of the entry to retrieve.
 * @return PasswordEntry with the decrypted password.
 * @throws std::runtime_error if entry not found or decryption fails.
 */
PasswordEntry get_entry_password(const Vault& vault,
                                 const std::array<uint8_t, 16>& id);

// ── Entry CRUD ──────────────────────────────────────────────────────────────

/**
 * @brief Add a new entry to the vault.
 *
 * Generates a UUID, sets timestamps, derives entry_key via HKDF, encrypts
 * the password, and appends the entry to the index and ciphertext vectors.
 * Call save_vault() afterwards to persist changes to disk.
 *
 * @param vault    The vault to add the entry to (must have vault_key).
 * @param name     Entry name (e.g., service name).
 * @param website  Website URL.
 * @param username Username / email.
 * @param password Password to encrypt (stored in SecureBuffer).
 * @param expires_at Optional expiry timestamp (0 = no expiry).
 * @return The UUID assigned to the new entry.
 * @throws std::runtime_error if vault_key is not available.
 */
std::array<uint8_t, 16> vault_add_entry(Vault& vault,
                                         const std::string& name,
                                         const std::string& website,
                                         const std::string& username,
                                         const SecureBuffer& password,
                                         uint64_t expires_at = 0);

/**
 * @brief Find entries whose name or website contains the query (case-insensitive substring match).
 *
 * Searches only the decrypted index — no passwords are touched.
 *
 * @param vault The vault to search.
 * @param query Substring to match against name and website fields.
 * @return Vector of matching BrowsableEntry objects (no passwords).
 */
std::vector<BrowsableEntry> vault_find_entries(const Vault& vault,
                                                const std::string& query);

/**
 * @brief Update an existing entry's fields.
 *
 * If a new password is provided (non-empty SecureBuffer), the entry's password
 * ciphertext is re-encrypted under the same entry_key (UUID is preserved).
 * Updated fields: name, website, username, password (if provided), expires_at.
 * The updated_at timestamp is set to now.
 *
 * @param vault      The vault containing the entry.
 * @param id         UUID of the entry to update.
 * @param name       New name (empty string = keep existing).
 * @param website    New website (empty string = keep existing).
 * @param username   New username (empty string = keep existing).
 * @param password   New password (empty SecureBuffer = keep existing).
 * @param expires_at New expiry timestamp (pass existing value to keep, 0 = disable).
 * @throws std::runtime_error if entry not found or vault_key unavailable.
 */
void vault_update_entry(Vault& vault,
                         const std::array<uint8_t, 16>& id,
                         const std::string& name,
                         const std::string& website,
                         const std::string& username,
                         const SecureBuffer& password,
                         uint64_t expires_at);

/**
 * @brief Delete an entry from the vault.
 *
 * Removes the entry from the index and its ciphertext block.
 * Call save_vault() afterwards to persist changes to disk.
 *
 * @param vault The vault to remove the entry from.
 * @param id    UUID of the entry to delete.
 * @throws std::runtime_error if entry not found.
 */
void vault_delete_entry(Vault& vault, const std::array<uint8_t, 16>& id);

/**
 * @brief Re-derive the vault key from a candidate password and verify it
 *        against the stored verification token.
 *
 * @param vault    The loaded vault (needs salt, Argon2 params, verify token).
 * @param password Candidate master password bytes.
 * @param pw_len   Length of candidate password.
 * @return true if the password is correct.
 */
bool verify_master_password(const Vault& vault,
                            const unsigned char* password, size_t pw_len);

/**
 * @brief Check master password expiry status.
 *
 * @param vault The loaded vault (needs master_password_changed_at and expiry_days).
 * @return ExpiryStatus::OK, WARNING (≤7 days remaining), or EXPIRED.
 */
ExpiryStatus check_expiry(const Vault& vault);

/**
 * @brief Return the number of days until master password expires.
 *
 * Negative values mean the password expired that many days ago.
 * Returns INT64_MAX if expiry is disabled (expiry_days == 0).
 */
int64_t days_until_expiry(const Vault& vault);
