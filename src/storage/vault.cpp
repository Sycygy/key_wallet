#include "storage/vault.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <openssl/crypto.h>  // OPENSSL_cleanse

#include "crypto/aead/aead.hpp"
#include "crypto/kdf/kdf.hpp"
#include "crypto/random/random.hpp"

// ── Little-endian helpers ────────────────────────────────────────────────────

static void write_u16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

static void write_u32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i)
        buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

static void write_u64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

static uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) |
           (static_cast<uint16_t>(p[1]) << 8);
}

static uint32_t read_u32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i)
        v |= static_cast<uint32_t>(p[i]) << (i * 8);
    return v;
}

static uint64_t read_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

static uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// ── AAD construction ─────────────────────────────────────────────────────────

std::vector<uint8_t> build_aad(const Vault& vault) {
    std::vector<uint8_t> aad;
    aad.reserve(VAULT_HEADER_LEN);

    // MAGIC (8)
    aad.insert(aad.end(), VAULT_MAGIC, VAULT_MAGIC + 8);
    // FORMAT_VERSION (2)
    write_u16(aad, VAULT_FORMAT_VERSION);
    // CREATED_AT (8)
    write_u64(aad, vault.created_at);
    // SALT (16)
    aad.insert(aad.end(), vault.salt.begin(), vault.salt.end());
    // ARGON2_PARAMS (12)
    write_u32(aad, vault.m_cost);
    write_u32(aad, vault.t_cost);
    write_u32(aad, vault.parallelism);

    return aad;
}

// ── Index plaintext serialization ────────────────────────────────────────────

/// Build the index plaintext from vault metadata + entries.
static std::vector<uint8_t> serialize_index_payload(const Vault& vault) {
    std::vector<uint8_t> payload;

    // SAVE_COUNTER (4)
    write_u32(payload, vault.save_counter);
    // MASTER_PASSWORD_CHANGED_AT (8)
    write_u64(payload, vault.master_password_changed_at);
    // MASTER_PASSWORD_EXPIRY_DAYS (4)
    write_u32(payload, vault.master_password_expiry_days);
    // ENTRY_COUNT (4)
    write_u32(payload, static_cast<uint32_t>(vault.entries.size()));

    // Serialized index records
    for (const auto& entry : vault.entries) {
        auto record = serialize_index(entry);
        payload.insert(payload.end(), record.begin(), record.end());
    }

    return payload;
}

/// Parse the index plaintext into vault metadata + entries.
static void deserialize_index_payload(const uint8_t* data, size_t len, Vault& vault) {
    // Minimum: save_counter(4) + changed_at(8) + expiry_days(4) + entry_count(4) = 20
    if (len < 20)
        throw std::runtime_error("Truncated index payload");

    size_t offset = 0;
    vault.save_counter = read_u32(data + offset);              offset += 4;
    vault.master_password_changed_at = read_u64(data + offset); offset += 8;
    vault.master_password_expiry_days = read_u32(data + offset); offset += 4;
    uint32_t entry_count = read_u32(data + offset);             offset += 4;

    vault.entries.clear();
    vault.entries.reserve(entry_count);

    for (uint32_t i = 0; i < entry_count; ++i) {
        if (offset >= len)
            throw std::runtime_error("Truncated index: missing entry record");
        size_t bytes_read = 0;
        BrowsableEntry entry = deserialize_index(data + offset, len - offset, bytes_read);
        vault.entries.push_back(std::move(entry));
        offset += bytes_read;
    }
}

// ── File I/O helpers ─────────────────────────────────────────────────────────

static std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        throw std::runtime_error("Cannot open vault file: " + path);
    auto size = f.tellg();
    if (size < 0)
        throw std::runtime_error("Cannot determine vault file size");
    std::vector<uint8_t> data(static_cast<size_t>(size));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(data.data()), size);
    if (!f)
        throw std::runtime_error("Failed to read vault file");
    return data;
}

static void write_file_atomic(const std::string& path,
                               const std::vector<uint8_t>& data) {
    std::string tmp_path = path + ".tmp";
    {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f)
            throw std::runtime_error("Cannot create temporary vault file: " + tmp_path);
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
        if (!f)
            throw std::runtime_error("Failed to write temporary vault file");
        f.flush();
    }
    if (std::rename(tmp_path.c_str(), path.c_str()) != 0)
        throw std::runtime_error("Failed to rename temporary vault file to: " + path);
}

// ── Serialize vault to binary ────────────────────────────────────────────────

static std::vector<uint8_t> vault_to_bytes(Vault& vault, const std::vector<uint8_t>& aad) {
    // Encrypt index with hybrid IV
    auto index_pt = serialize_index_payload(vault);
    auto index_ct = aead_encrypt(vault.vault_key,
                                  index_pt.data(), index_pt.size(),
                                  vault.save_counter,
                                  aad.data(), aad.size());
    OPENSSL_cleanse(index_pt.data(), index_pt.size());

    // Build output
    std::vector<uint8_t> out;
    // Estimate size
    out.reserve(VAULT_HEADER_LEN + 12 + 16 + 32 + 12 + 16 + 4 + index_ct.ciphertext.size()
                + vault.entry_passwords.size() * 64);

    // ── Header (= AAD) ──
    out.insert(out.end(), aad.begin(), aad.end());

    // ── Verification token ──
    out.insert(out.end(), vault.verify_iv.begin(), vault.verify_iv.end());
    out.insert(out.end(), vault.verify_tag.begin(), vault.verify_tag.end());
    out.insert(out.end(), vault.verify_ciphertext.begin(), vault.verify_ciphertext.end());

    // ── Index ──
    out.insert(out.end(), index_ct.iv.begin(), index_ct.iv.end());
    out.insert(out.end(), index_ct.tag.begin(), index_ct.tag.end());
    write_u32(out, static_cast<uint32_t>(index_ct.ciphertext.size()));
    out.insert(out.end(), index_ct.ciphertext.begin(), index_ct.ciphertext.end());

    // ── Per-entry password ciphertexts ──
    for (const auto& ep : vault.entry_passwords) {
        out.insert(out.end(), ep.iv.begin(), ep.iv.end());
        out.insert(out.end(), ep.tag.begin(), ep.tag.end());
        write_u32(out, static_cast<uint32_t>(ep.ciphertext.size()));
        out.insert(out.end(), ep.ciphertext.begin(), ep.ciphertext.end());
    }

    return out;
}

// ── Public API ───────────────────────────────────────────────────────────────

Vault create_vault(const std::string& path,
                   const unsigned char* master_password, size_t mp_len) {
    if (!master_password || mp_len == 0)
        throw std::invalid_argument("Master password must not be empty");

    Vault vault;
    vault.file_path = path;
    vault.created_at = now_unix();
    vault.master_password_changed_at = vault.created_at;
    vault.master_password_expiry_days = VAULT_DEFAULT_EXPIRY_DAYS;
    vault.save_counter = 0;

    // Generate random salt
    SecureBuffer salt_buf = random_bytes(VAULT_SALT_LEN);
    std::memcpy(vault.salt.data(), salt_buf.data(), VAULT_SALT_LEN);

    // Derive vault key
    vault.vault_key = derive_vault_key(master_password, mp_len,
                                        vault.salt.data(), VAULT_SALT_LEN);

    // Build AAD
    auto aad = build_aad(vault);

    // Create verification token: encrypt 32 zero bytes
    SecureBuffer zero_pt(VAULT_VERIFY_PT_LEN);  // zero-initialized
    auto verify_ct = aead_encrypt(vault.vault_key,
                                   zero_pt.data(), zero_pt.size(),
                                   aad.data(), aad.size());
    vault.verify_iv         = std::move(verify_ct.iv);
    vault.verify_tag        = std::move(verify_ct.tag);
    vault.verify_ciphertext = std::move(verify_ct.ciphertext);

    // No entries yet
    vault.entries.clear();
    vault.entry_passwords.clear();

    // Serialize and write
    auto bytes = vault_to_bytes(vault, aad);
    write_file_atomic(path, bytes);

    return vault;
}

Vault load_vault(const std::string& path,
                 const unsigned char* master_password, size_t mp_len) {
    if (!master_password || mp_len == 0)
        throw std::invalid_argument("Master password must not be empty");

    auto file_data = read_file(path);
    const uint8_t* d = file_data.data();
    size_t len = file_data.size();

    // ── Parse header ──
    // Minimum: header(46) + verify_iv(12) + verify_tag(16) + verify_ct(32) +
    //          index_iv(12) + index_tag(16) + index_len(4) = 138
    if (len < 138)
        throw std::runtime_error("Vault file is too small or corrupt");

    // Check magic
    if (std::memcmp(d, VAULT_MAGIC, 8) != 0)
        throw std::runtime_error("Not a valid vault file (bad magic)");

    size_t offset = 8;

    // Format version
    uint16_t version = read_u16(d + offset); offset += 2;
    if (version == 1)
        throw std::runtime_error(
            "This vault was created with key_manager v0.1 and must be migrated. "
            "Run: key_manager migrate <vault_path>");
    if (version != VAULT_FORMAT_VERSION)
        throw std::runtime_error("Unsupported vault format version: " +
                                  std::to_string(version));

    Vault vault;
    vault.file_path = path;

    vault.created_at = read_u64(d + offset);  offset += 8;
    std::memcpy(vault.salt.data(), d + offset, 16); offset += 16;
    vault.m_cost      = read_u32(d + offset); offset += 4;
    vault.t_cost      = read_u32(d + offset); offset += 4;
    vault.parallelism = read_u32(d + offset); offset += 4;

    // ── AAD = bytes [0, VAULT_HEADER_LEN) ──
    std::vector<uint8_t> aad(d, d + VAULT_HEADER_LEN);

    // ── Derive vault key ──
    vault.vault_key = derive_vault_key(master_password, mp_len,
                                        vault.salt.data(), VAULT_SALT_LEN);

    // ── Verification token ──
    vault.verify_iv.assign(d + offset, d + offset + 12);   offset += 12;
    vault.verify_tag.assign(d + offset, d + offset + 16);  offset += 16;
    vault.verify_ciphertext.assign(d + offset, d + offset + VAULT_VERIFY_PT_LEN);
    offset += VAULT_VERIFY_PT_LEN;

    // Verify: decrypt the token — if tag fails, password is wrong
    try {
        aead_decrypt(vault.vault_key,
                     vault.verify_iv.data(),
                     vault.verify_ciphertext.data(), vault.verify_ciphertext.size(),
                     vault.verify_tag.data(),
                     aad.data(), aad.size());
    } catch (const std::runtime_error&) {
        throw std::runtime_error("Authentication failed");
    }

    // ── Index ──
    if (offset + 12 + 16 + 4 > len)
        throw std::runtime_error("Truncated vault: missing index header");
    const uint8_t* index_iv  = d + offset; offset += 12;
    const uint8_t* index_tag = d + offset; offset += 16;
    uint32_t index_len = read_u32(d + offset); offset += 4;

    if (offset + index_len > len)
        throw std::runtime_error("Truncated vault: index ciphertext extends beyond file");

    SecureBuffer index_pt = aead_decrypt(vault.vault_key,
                                          index_iv,
                                          d + offset, index_len,
                                          index_tag,
                                          aad.data(), aad.size());
    offset += index_len;

    deserialize_index_payload(index_pt.data(), index_pt.size(), vault);

    // ── Per-entry password ciphertexts ──
    vault.entry_passwords.clear();
    vault.entry_passwords.reserve(vault.entries.size());

    for (size_t i = 0; i < vault.entries.size(); ++i) {
        if (offset + 12 + 16 + 4 > len)
            throw std::runtime_error("Truncated vault: missing entry ciphertext header");
        EntryCiphertext ec;
        ec.iv.assign(d + offset, d + offset + 12);   offset += 12;
        ec.tag.assign(d + offset, d + offset + 16);   offset += 16;
        uint32_t ct_len = read_u32(d + offset);        offset += 4;

        if (offset + ct_len > len)
            throw std::runtime_error("Truncated vault: entry ciphertext extends beyond file");
        ec.ciphertext.assign(d + offset, d + offset + ct_len);
        offset += ct_len;

        vault.entry_passwords.push_back(std::move(ec));
    }

    // Cleanse raw file bytes — contains ciphertexts, IVs, tags, and header.
    OPENSSL_cleanse(file_data.data(), file_data.size());

    return vault;
}

void save_vault(Vault& vault) {
    if (vault.file_path.empty())
        throw std::runtime_error("Vault has no file path set");
    if (vault.vault_key.empty())
        throw std::runtime_error("Vault key not available — vault is locked");

    // Increment save counter
    vault.save_counter++;

    auto aad = build_aad(vault);

    // Re-encrypt entry passwords that need it
    // (entry_passwords vector is maintained by add/update/delete operations;
    //  save_vault just re-encrypts the index and writes everything out)

    auto bytes = vault_to_bytes(vault, aad);
    write_file_atomic(vault.file_path, bytes);
}

PasswordEntry get_entry_password(const Vault& vault,
                                  const std::array<uint8_t, 16>& id) {
    if (vault.vault_key.empty())
        throw std::runtime_error("Vault key not available — vault is locked");

    // Find entry index
    size_t idx = 0;
    bool found = false;
    for (size_t i = 0; i < vault.entries.size(); ++i) {
        if (vault.entries[i].id == id) {
            idx = i;
            found = true;
            break;
        }
    }
    if (!found)
        throw std::runtime_error("Entry not found");

    if (idx >= vault.entry_passwords.size())
        throw std::runtime_error("Entry password ciphertext missing");

    // Derive entry key via HKDF
    SecureBuffer entry_key = derive_entry_key(vault.vault_key, id);

    // Build AAD (same as vault header AAD)
    auto aad = build_aad(vault);

    // Decrypt password
    const auto& ec = vault.entry_passwords[idx];
    SecureBuffer pw_pt = aead_decrypt(entry_key,
                                       ec.iv.data(),
                                       ec.ciphertext.data(), ec.ciphertext.size(),
                                       ec.tag.data(),
                                       aad.data(), aad.size());

    // Deserialize password
    size_t bytes_read = 0;
    SecureBuffer password = deserialize_password(pw_pt.data(), pw_pt.size(), bytes_read);

    // Build full PasswordEntry
    const auto& be = vault.entries[idx];
    PasswordEntry pe;
    pe.id         = be.id;
    pe.name       = be.name;
    pe.website    = be.website;
    pe.username   = be.username;
    pe.password   = std::move(password);
    pe.created_at = be.created_at;
    pe.updated_at = be.updated_at;
    pe.expires_at = be.expires_at;

    return pe;
}

// ── Entry CRUD ──────────────────────────────────────────────────────────────

std::array<uint8_t, 16> vault_add_entry(Vault& vault,
                                         const std::string& name,
                                         const std::string& website,
                                         const std::string& username,
                                         const SecureBuffer& password,
                                         uint64_t expires_at) {
    if (vault.vault_key.empty())
        throw std::runtime_error("Vault key not available — vault is locked");

    auto uuid = generate_uuid();
    uint64_t now = now_unix();

    // Add to index
    BrowsableEntry be;
    be.id         = uuid;
    be.name       = name;
    be.website    = website;
    be.username   = username;
    be.created_at = now;
    be.updated_at = now;
    be.expires_at = expires_at;
    vault.entries.push_back(std::move(be));

    // Derive entry key and encrypt password
    SecureBuffer entry_key = derive_entry_key(vault.vault_key, uuid);
    auto pw_serialized = serialize_password(password);
    auto aad = build_aad(vault);
    auto ct = aead_encrypt(entry_key,
                           pw_serialized.data(), pw_serialized.size(),
                           aad.data(), aad.size());

    EntryCiphertext ec;
    ec.iv         = std::move(ct.iv);
    ec.tag        = std::move(ct.tag);
    ec.ciphertext = std::move(ct.ciphertext);
    vault.entry_passwords.push_back(std::move(ec));

    return uuid;
}

std::vector<BrowsableEntry> vault_find_entries(const Vault& vault,
                                                const std::string& query) {
    std::vector<BrowsableEntry> results;
    if (query.empty())
        return results;

    // Case-insensitive substring match
    std::string lower_query = query;
    std::transform(lower_query.begin(), lower_query.end(),
                   lower_query.begin(), ::tolower);

    for (const auto& entry : vault.entries) {
        std::string lower_name = entry.name;
        std::transform(lower_name.begin(), lower_name.end(),
                       lower_name.begin(), ::tolower);
        std::string lower_website = entry.website;
        std::transform(lower_website.begin(), lower_website.end(),
                       lower_website.begin(), ::tolower);

        if (lower_name.find(lower_query) != std::string::npos ||
            lower_website.find(lower_query) != std::string::npos) {
            results.push_back(entry);
        }
    }

    return results;
}

void vault_update_entry(Vault& vault,
                         const std::array<uint8_t, 16>& id,
                         const std::string& name,
                         const std::string& website,
                         const std::string& username,
                         const SecureBuffer& password,
                         uint64_t expires_at) {
    if (vault.vault_key.empty())
        throw std::runtime_error("Vault key not available — vault is locked");

    // Find entry index
    size_t idx = 0;
    bool found = false;
    for (size_t i = 0; i < vault.entries.size(); ++i) {
        if (vault.entries[i].id == id) {
            idx = i;
            found = true;
            break;
        }
    }
    if (!found)
        throw std::runtime_error("Entry not found");

    auto& entry = vault.entries[idx];

    // Update fields (empty string = keep existing)
    if (!name.empty())     entry.name     = name;
    if (!website.empty())  entry.website  = website;
    if (!username.empty()) entry.username = username;
    entry.expires_at = expires_at;
    entry.updated_at = now_unix();

    // If password provided, re-encrypt under same entry_key (UUID preserved)
    if (!password.empty()) {
        SecureBuffer entry_key = derive_entry_key(vault.vault_key, id);
        auto pw_serialized = serialize_password(password);
        auto aad = build_aad(vault);
        auto ct = aead_encrypt(entry_key,
                               pw_serialized.data(), pw_serialized.size(),
                               aad.data(), aad.size());

        vault.entry_passwords[idx].iv         = std::move(ct.iv);
        vault.entry_passwords[idx].tag        = std::move(ct.tag);
        vault.entry_passwords[idx].ciphertext = std::move(ct.ciphertext);
    }
}

void vault_delete_entry(Vault& vault, const std::array<uint8_t, 16>& id) {
    // Find entry index
    size_t idx = 0;
    bool found = false;
    for (size_t i = 0; i < vault.entries.size(); ++i) {
        if (vault.entries[i].id == id) {
            idx = i;
            found = true;
            break;
        }
    }
    if (!found)
        throw std::runtime_error("Entry not found");

    vault.entries.erase(vault.entries.begin() + static_cast<ptrdiff_t>(idx));
    vault.entry_passwords.erase(vault.entry_passwords.begin() + static_cast<ptrdiff_t>(idx));
}

bool verify_master_password(const Vault& vault,
                            const unsigned char* password, size_t pw_len) {
    if (!password || pw_len == 0)
        return false;

    // Re-derive vault key
    SecureBuffer candidate_key = derive_vault_key(password, pw_len,
                                                   vault.salt.data(), VAULT_SALT_LEN);

    // Build AAD
    auto aad = build_aad(vault);

    // Try to decrypt verification token
    try {
        aead_decrypt(candidate_key,
                     vault.verify_iv.data(),
                     vault.verify_ciphertext.data(), vault.verify_ciphertext.size(),
                     vault.verify_tag.data(),
                     aad.data(), aad.size());
        return true;
    } catch (const std::runtime_error&) {
        return false;
    }
}

ExpiryStatus check_expiry(const Vault& vault) {
    if (vault.master_password_expiry_days == 0)
        return ExpiryStatus::OK;  // expiry disabled

    int64_t days = days_until_expiry(vault);
    if (days < 0)
        return ExpiryStatus::EXPIRED;
    if (days <= 7)
        return ExpiryStatus::WARNING;
    return ExpiryStatus::OK;
}

int64_t days_until_expiry(const Vault& vault) {
    if (vault.master_password_expiry_days == 0)
        return INT64_MAX;

    uint64_t deadline = vault.master_password_changed_at +
                        static_cast<uint64_t>(vault.master_password_expiry_days) * 86400;
    uint64_t now = now_unix();

    if (now >= deadline)
        return -static_cast<int64_t>(now - deadline) / 86400;
    return static_cast<int64_t>(deadline - now) / 86400;
}
