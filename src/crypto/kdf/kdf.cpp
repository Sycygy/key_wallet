#include "kdf.hpp"

#include <stdexcept>
#include <string>
#include <cstdio>

#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

// Argon2id parameters — must match the vault header ARGON2_PARAMS field.
static constexpr uint32_t ARGON2_M_COST = 65536;  // KiB (64 MiB)
static constexpr uint32_t ARGON2_T_COST = 3;       // iterations
static constexpr uint32_t ARGON2_P_COST = 4;       // lanes / threads
static constexpr size_t   KEY_LEN       = 32;      // output bytes

SecureBuffer derive_vault_key(const unsigned char* password, size_t password_len,
                              const unsigned char* salt,     size_t salt_len)
{
    if (!password || password_len == 0)
        throw std::invalid_argument("derive_vault_key: password must not be null or empty");
    if (!salt || salt_len == 0)
        throw std::invalid_argument("derive_vault_key: salt must not be null or empty");

    // Fetch the Argon2id KDF algorithm (requires OpenSSL 3.2+).
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (!kdf)
        throw std::runtime_error("derive_vault_key: EVP_KDF_fetch failed — OpenSSL 3.2+ required");

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);   // context holds its own reference
    if (!kctx)
        throw std::runtime_error("derive_vault_key: EVP_KDF_CTX_new failed");

    // Mutable copies needed because OSSL_PARAM_construct_* takes non-const pointers
    // even for read-only input params.
    uint32_t m = ARGON2_M_COST;
    uint32_t t = ARGON2_T_COST;
    uint32_t p = ARGON2_P_COST;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_PASSWORD,
            const_cast<unsigned char*>(password), password_len),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT,
            const_cast<unsigned char*>(salt), salt_len),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &m),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER,           &t),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES,   &p),
        OSSL_PARAM_construct_end()
    };

    SecureBuffer key(KEY_LEN);

    int rc = EVP_KDF_derive(kctx, key.data(), KEY_LEN, params);
    EVP_KDF_CTX_free(kctx);

    if (rc != 1)
        throw std::runtime_error("derive_vault_key: Argon2id derivation failed");

    return key;
}

// ── HKDF-SHA256 per-entry key derivation ─────────────────────────────────────

SecureBuffer derive_entry_key(const SecureBuffer& vault_key,
                              const std::array<uint8_t, 16>& uuid)
{
    if (vault_key.empty() || vault_key.size() != KEY_LEN)
        throw std::invalid_argument("derive_entry_key: vault_key must be exactly 32 bytes");

    // Build info string: "vault-entry-key:" + hex(uuid)
    // 16 bytes → 32 hex chars + 17 prefix = 49 chars + NUL
    char info[50];
    const char* prefix = "vault-entry-key:";
    std::snprintf(info, sizeof(info),
                  "%s%02x%02x%02x%02x%02x%02x%02x%02x"
                  "%02x%02x%02x%02x%02x%02x%02x%02x",
                  prefix,
                  uuid[0],  uuid[1],  uuid[2],  uuid[3],
                  uuid[4],  uuid[5],  uuid[6],  uuid[7],
                  uuid[8],  uuid[9],  uuid[10], uuid[11],
                  uuid[12], uuid[13], uuid[14], uuid[15]);

    size_t info_len = std::strlen(info);

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
        throw std::runtime_error("derive_entry_key: EVP_KDF_fetch(HKDF) failed");

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx)
        throw std::runtime_error("derive_entry_key: EVP_KDF_CTX_new failed");

    // HKDF mode: extract-and-expand (default)
    int mode = EVP_KDF_HKDF_MODE_EXTRACT_AND_EXPAND;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0),
        OSSL_PARAM_construct_int(
            OSSL_KDF_PARAM_MODE, &mode),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY,
            const_cast<unsigned char*>(vault_key.data()), vault_key.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO,
            const_cast<char*>(info), info_len),
        OSSL_PARAM_construct_end()
    };

    SecureBuffer entry_key(KEY_LEN);

    int rc = EVP_KDF_derive(kctx, entry_key.data(), KEY_LEN, params);
    EVP_KDF_CTX_free(kctx);

    if (rc != 1)
        throw std::runtime_error("derive_entry_key: HKDF-SHA256 derivation failed");

    return entry_key;
}
