#include "aead.hpp"

#include <cstring>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

// RAII guard for EVP_CIPHER_CTX.
struct CtxGuard {
    EVP_CIPHER_CTX* c;
    ~CtxGuard() { EVP_CIPHER_CTX_free(c); }
};

// Shared encrypt core — caller provides the fully-built 12-byte IV.
static AeadCiphertext encrypt_with_iv(const SecureBuffer& key,
                                      const unsigned char* iv,
                                      const unsigned char* plaintext, size_t pt_len,
                                      const unsigned char* aad, size_t aad_len)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("aead_encrypt: EVP_CIPHER_CTX_new failed");
    CtxGuard guard{ctx};

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("aead_encrypt: EncryptInit (cipher) failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(AEAD_IV_LEN), nullptr) != 1)
        throw std::runtime_error("aead_encrypt: set IV length failed");

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) != 1)
        throw std::runtime_error("aead_encrypt: EncryptInit (key+IV) failed");

    int len = 0;
    if (aad && aad_len > 0) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) != 1)
            throw std::runtime_error("aead_encrypt: AAD feed failed");
    }

    AeadCiphertext result;
    result.iv.assign(iv, iv + AEAD_IV_LEN);
    result.ciphertext.resize(pt_len);
    if (pt_len > 0) {
        if (EVP_EncryptUpdate(ctx, result.ciphertext.data(), &len,
                              plaintext, static_cast<int>(pt_len)) != 1)
            throw std::runtime_error("aead_encrypt: EncryptUpdate failed");
    }

    unsigned char final_buf[16];
    if (EVP_EncryptFinal_ex(ctx, final_buf, &len) != 1)
        throw std::runtime_error("aead_encrypt: EncryptFinal failed");

    result.tag.resize(AEAD_TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(AEAD_TAG_LEN), result.tag.data()) != 1)
        throw std::runtime_error("aead_encrypt: get tag failed");

    return result;
}

static void validate_encrypt_key(const SecureBuffer& key) {
    if (key.empty() || key.size() != AEAD_KEY_LEN)
        throw std::invalid_argument("aead_encrypt: key must be exactly 32 bytes");
}

// ── Fully random IV (for verification token) ────────────────────────────────

AeadCiphertext aead_encrypt(const SecureBuffer& key,
                            const unsigned char* plaintext, size_t pt_len,
                            const unsigned char* aad, size_t aad_len)
{
    validate_encrypt_key(key);

    unsigned char iv[AEAD_IV_LEN];
    if (RAND_bytes(iv, static_cast<int>(AEAD_IV_LEN)) != 1)
        throw std::runtime_error("aead_encrypt: RAND_bytes failed for IV");

    return encrypt_with_iv(key, iv, plaintext, pt_len, aad, aad_len);
}

// ── Hybrid IV: counter(4B, LE) || random(8B) (for vault payload) ────────────

AeadCiphertext aead_encrypt(const SecureBuffer& key,
                            const unsigned char* plaintext, size_t pt_len,
                            uint32_t iv_counter,
                            const unsigned char* aad, size_t aad_len)
{
    validate_encrypt_key(key);

    unsigned char iv[AEAD_IV_LEN];

    // Fixed field: 4-byte counter in little-endian.
    memcpy(iv, &iv_counter, AEAD_IV_COUNTER_LEN);

    // Invocation field: 8 random bytes.
    if (RAND_bytes(iv + AEAD_IV_COUNTER_LEN, static_cast<int>(AEAD_IV_RANDOM_LEN)) != 1)
        throw std::runtime_error("aead_encrypt: RAND_bytes failed for IV random field");

    return encrypt_with_iv(key, iv, plaintext, pt_len, aad, aad_len);
}

// ── Decrypt (works with both IV types) ──────────────────────────────────────

SecureBuffer aead_decrypt(const SecureBuffer& key,
                          const unsigned char* iv,
                          const unsigned char* ciphertext, size_t ct_len,
                          const unsigned char* tag,
                          const unsigned char* aad, size_t aad_len)
{
    if (key.empty() || key.size() != AEAD_KEY_LEN)
        throw std::invalid_argument("aead_decrypt: key must be exactly 32 bytes");
    if (!iv)
        throw std::invalid_argument("aead_decrypt: IV must not be null");
    if (!tag)
        throw std::invalid_argument("aead_decrypt: tag must not be null");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        throw std::runtime_error("aead_decrypt: EVP_CIPHER_CTX_new failed");
    CtxGuard guard{ctx};

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("aead_decrypt: DecryptInit (cipher) failed");

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(AEAD_IV_LEN), nullptr) != 1)
        throw std::runtime_error("aead_decrypt: set IV length failed");

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv) != 1)
        throw std::runtime_error("aead_decrypt: DecryptInit (key+IV) failed");

    int len = 0;
    if (aad && aad_len > 0) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, static_cast<int>(aad_len)) != 1)
            throw std::runtime_error("aead_decrypt: AAD feed failed");
    }

    SecureBuffer plaintext(ct_len);
    if (ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                              ciphertext, static_cast<int>(ct_len)) != 1)
            throw std::runtime_error("aead_decrypt: DecryptUpdate failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(AEAD_TAG_LEN),
                            const_cast<unsigned char*>(tag)) != 1)
        throw std::runtime_error("aead_decrypt: set tag failed");

    unsigned char final_buf[16];
    if (EVP_DecryptFinal_ex(ctx, final_buf, &len) != 1)
        throw std::runtime_error("aead_decrypt: authentication failed");

    return plaintext;
}