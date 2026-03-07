#include <gtest/gtest.h>
#include <cstring>
#include "crypto/aead/aead.hpp"
#include "crypto/random/random.hpp"

// Helper: build a 32-byte key from a fixed pattern.
static SecureBuffer make_test_key() {
    SecureBuffer key(AEAD_KEY_LEN);
    for (size_t i = 0; i < AEAD_KEY_LEN; ++i)
        key.data()[i] = static_cast<unsigned char>(i);
    return key;
}

static const unsigned char PLAINTEXT[] = "The quick brown fox jumps over the lazy dog";
static constexpr size_t    PT_LEN      = sizeof(PLAINTEXT) - 1;  // exclude null

static const unsigned char AAD[] = "KEYMGR\x01\x00\x01\x00";
static constexpr size_t    AAD_LEN = 10;

// =============================================================================
// Random IV overload (verification token use-case)
// =============================================================================

TEST(AeadTest, EncryptDecryptRoundTrip) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN);

    EXPECT_EQ(ct.iv.size(), AEAD_IV_LEN);
    EXPECT_EQ(ct.tag.size(), AEAD_TAG_LEN);
    EXPECT_EQ(ct.ciphertext.size(), PT_LEN);

    auto pt = aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                           ct.tag.data());
    ASSERT_EQ(pt.size(), PT_LEN);
    EXPECT_EQ(memcmp(pt.data(), PLAINTEXT, PT_LEN), 0);
}

TEST(AeadTest, EncryptDecryptRoundTripWithAad) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN, AAD, AAD_LEN);

    auto pt = aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                           ct.tag.data(), AAD, AAD_LEN);
    ASSERT_EQ(pt.size(), PT_LEN);
    EXPECT_EQ(memcmp(pt.data(), PLAINTEXT, PT_LEN), 0);
}

TEST(AeadTest, CiphertextDiffersFromPlaintext) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN);
    EXPECT_NE(memcmp(ct.ciphertext.data(), PLAINTEXT, PT_LEN), 0);
}

TEST(AeadTest, FreshIvPerEncryption) {
    auto key = make_test_key();
    auto ct1 = aead_encrypt(key, PLAINTEXT, PT_LEN);
    auto ct2 = aead_encrypt(key, PLAINTEXT, PT_LEN);

    EXPECT_NE(memcmp(ct1.iv.data(), ct2.iv.data(), AEAD_IV_LEN), 0);
}

TEST(AeadTest, TamperedCiphertextFails) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN);

    ct.ciphertext[0] ^= 0x01;

    EXPECT_THROW(
        aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                     ct.tag.data()),
        std::runtime_error);
}

TEST(AeadTest, TamperedTagFails) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN);

    ct.tag[0] ^= 0xff;

    EXPECT_THROW(
        aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                     ct.tag.data()),
        std::runtime_error);
}

TEST(AeadTest, TamperedIvFails) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN);

    ct.iv[0] ^= 0x01;

    EXPECT_THROW(
        aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                     ct.tag.data()),
        std::runtime_error);
}

TEST(AeadTest, WrongKeyFails) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN);

    SecureBuffer wrong_key(AEAD_KEY_LEN);
    for (size_t i = 0; i < AEAD_KEY_LEN; ++i)
        wrong_key.data()[i] = static_cast<unsigned char>(0xff - i);

    EXPECT_THROW(
        aead_decrypt(wrong_key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                     ct.tag.data()),
        std::runtime_error);
}

TEST(AeadTest, TamperedAadFails) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN, AAD, AAD_LEN);

    unsigned char bad_aad[AAD_LEN];
    memcpy(bad_aad, AAD, AAD_LEN);
    bad_aad[0] ^= 0x01;

    EXPECT_THROW(
        aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                     ct.tag.data(), bad_aad, AAD_LEN),
        std::runtime_error);
}

TEST(AeadTest, MissingAadOnDecryptFails) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN, AAD, AAD_LEN);

    EXPECT_THROW(
        aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                     ct.tag.data()),
        std::runtime_error);
}

TEST(AeadTest, EmptyPlaintextRoundTrip) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, nullptr, 0);

    EXPECT_EQ(ct.ciphertext.size(), 0u);

    auto pt = aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), 0, ct.tag.data());
    EXPECT_EQ(pt.size(), 0u);
}

TEST(AeadTest, InvalidKeySizeEncryptThrows) {
    SecureBuffer short_key(16);
    EXPECT_THROW(aead_encrypt(short_key, PLAINTEXT, PT_LEN), std::invalid_argument);
}

TEST(AeadTest, InvalidKeySizeDecryptThrows) {
    SecureBuffer short_key(16);
    unsigned char dummy_iv[AEAD_IV_LEN] = {};
    unsigned char dummy_tag[AEAD_TAG_LEN] = {};
    EXPECT_THROW(aead_decrypt(short_key, dummy_iv, PLAINTEXT, PT_LEN, dummy_tag),
                 std::invalid_argument);
}

TEST(AeadTest, NullIvDecryptThrows) {
    auto key = make_test_key();
    unsigned char dummy_tag[AEAD_TAG_LEN] = {};
    EXPECT_THROW(aead_decrypt(key, nullptr, PLAINTEXT, PT_LEN, dummy_tag),
                 std::invalid_argument);
}

TEST(AeadTest, NullTagDecryptThrows) {
    auto key = make_test_key();
    unsigned char dummy_iv[AEAD_IV_LEN] = {};
    EXPECT_THROW(aead_decrypt(key, dummy_iv, PLAINTEXT, PT_LEN, nullptr),
                 std::invalid_argument);
}

// =============================================================================
// Hybrid IV overload (vault payload use-case)
// =============================================================================

TEST(AeadHybridIvTest, RoundTrip) {
    auto key = make_test_key();
    uint32_t counter = 42;
    auto ct = aead_encrypt(key, PLAINTEXT, PT_LEN, counter);

    EXPECT_EQ(ct.iv.size(), AEAD_IV_LEN);

    auto pt = aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                           ct.tag.data());
    ASSERT_EQ(pt.size(), PT_LEN);
    EXPECT_EQ(memcmp(pt.data(), PLAINTEXT, PT_LEN), 0);
}

TEST(AeadHybridIvTest, RoundTripWithAad) {
    auto key = make_test_key();
    uint32_t counter = 1;
    auto ct = aead_encrypt(key, PLAINTEXT, PT_LEN, counter, AAD, AAD_LEN);

    auto pt = aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                           ct.tag.data(), AAD, AAD_LEN);
    ASSERT_EQ(pt.size(), PT_LEN);
    EXPECT_EQ(memcmp(pt.data(), PLAINTEXT, PT_LEN), 0);
}

TEST(AeadHybridIvTest, CounterPrefixIsCorrect) {
    auto key = make_test_key();
    uint32_t counter = 0x04030201;
    auto ct = aead_encrypt(key, PLAINTEXT, PT_LEN, counter);

    // First 4 bytes of IV should be the counter in little-endian.
    uint32_t extracted = 0;
    memcpy(&extracted, ct.iv.data(), sizeof(uint32_t));
    EXPECT_EQ(extracted, counter);
}

TEST(AeadHybridIvTest, CounterZeroPrefixIsCorrect) {
    auto key = make_test_key();
    uint32_t counter = 0;
    auto ct = aead_encrypt(key, PLAINTEXT, PT_LEN, counter);

    // First 4 bytes should be all zeros.
    unsigned char zeros[AEAD_IV_COUNTER_LEN] = {};
    EXPECT_EQ(memcmp(ct.iv.data(), zeros, AEAD_IV_COUNTER_LEN), 0);
}

TEST(AeadHybridIvTest, RandomSuffixDiffersAcrossCalls) {
    auto key = make_test_key();
    uint32_t counter = 7;
    auto ct1 = aead_encrypt(key, PLAINTEXT, PT_LEN, counter);
    auto ct2 = aead_encrypt(key, PLAINTEXT, PT_LEN, counter);

    // Same counter → first 4 bytes identical.
    EXPECT_EQ(memcmp(ct1.iv.data(), ct2.iv.data(), AEAD_IV_COUNTER_LEN), 0);

    // Random suffix (bytes 4–11) should differ.
    EXPECT_NE(memcmp(ct1.iv.data() + AEAD_IV_COUNTER_LEN,
                     ct2.iv.data() + AEAD_IV_COUNTER_LEN,
                     AEAD_IV_RANDOM_LEN), 0);
}

TEST(AeadHybridIvTest, DifferentCountersDifferentIvPrefix) {
    auto key = make_test_key();
    auto ct1 = aead_encrypt(key, PLAINTEXT, PT_LEN, uint32_t{0});
    auto ct2 = aead_encrypt(key, PLAINTEXT, PT_LEN, uint32_t{1});

    // First 4 bytes must differ.
    EXPECT_NE(memcmp(ct1.iv.data(), ct2.iv.data(), AEAD_IV_COUNTER_LEN), 0);
}

TEST(AeadHybridIvTest, TamperedCiphertextFails) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN, uint32_t{5});
    ct.ciphertext[0] ^= 0x01;

    EXPECT_THROW(
        aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                     ct.tag.data()),
        std::runtime_error);
}

TEST(AeadHybridIvTest, TamperedAadFails) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, PLAINTEXT, PT_LEN, uint32_t{5}, AAD, AAD_LEN);

    unsigned char bad_aad[AAD_LEN];
    memcpy(bad_aad, AAD, AAD_LEN);
    bad_aad[0] ^= 0x01;

    EXPECT_THROW(
        aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                     ct.tag.data(), bad_aad, AAD_LEN),
        std::runtime_error);
}

TEST(AeadHybridIvTest, EmptyPlaintextRoundTrip) {
    auto key = make_test_key();
    auto ct  = aead_encrypt(key, nullptr, 0, uint32_t{0});

    EXPECT_EQ(ct.ciphertext.size(), 0u);
    auto pt = aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), 0, ct.tag.data());
    EXPECT_EQ(pt.size(), 0u);
}

TEST(AeadHybridIvTest, InvalidKeySizeThrows) {
    SecureBuffer short_key(16);
    EXPECT_THROW(aead_encrypt(short_key, PLAINTEXT, PT_LEN, uint32_t{0}),
                 std::invalid_argument);
}

TEST(AeadHybridIvTest, MaxCounterValue) {
    auto key = make_test_key();
    uint32_t counter = UINT32_MAX;
    auto ct = aead_encrypt(key, PLAINTEXT, PT_LEN, counter);

    uint32_t extracted = 0;
    memcpy(&extracted, ct.iv.data(), sizeof(uint32_t));
    EXPECT_EQ(extracted, UINT32_MAX);

    auto pt = aead_decrypt(key, ct.iv.data(), ct.ciphertext.data(), ct.ciphertext.size(),
                           ct.tag.data());
    ASSERT_EQ(pt.size(), PT_LEN);
    EXPECT_EQ(memcmp(pt.data(), PLAINTEXT, PT_LEN), 0);
}