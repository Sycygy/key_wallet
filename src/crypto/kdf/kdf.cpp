#include "kdf.hpp"

#include <stdexcept>
#include <string>

#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>

// Argon2id parameters — must match the vault header ARGON2_PARAMS field.
static constexpr uint32_t ARGON2_M_COST = 65536;  // KiB (64 MiB)
static constexpr uint32_t ARGON2_T_COST = 3;       // iterations
static constexpr uint32_t ARGON2_P_COST = 4;       // lanes / threads
static constexpr size_t   KEY_LEN       = 32;      // output bytes

SecureBuffer derive_key(const unsigned char* password, size_t password_len,
                        const unsigned char* salt,     size_t salt_len)
{
    if (!password || password_len == 0)
        throw std::invalid_argument("derive_key: password must not be null or empty");
    if (!salt || salt_len == 0)
        throw std::invalid_argument("derive_key: salt must not be null or empty");

    // Fetch the Argon2id KDF algorithm (requires OpenSSL 3.2+).
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    if (!kdf)
        throw std::runtime_error("derive_key: EVP_KDF_fetch failed — OpenSSL 3.2+ required");

    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);   // context holds its own reference
    if (!kctx)
        throw std::runtime_error("derive_key: EVP_KDF_CTX_new failed");

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
        throw std::runtime_error("derive_key: Argon2id derivation failed");

    return key;
}
