#include <gtest/gtest.h>
#include <cstring>
#include "crypto/kdf/kdf.hpp"

// 16-byte test salt (matches required vault salt length)
static const unsigned char SALT_A[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const unsigned char SALT_B[16] = {
    0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
    0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0
};

static const char PASSWORD_A[] = "hunter2";
static const char PASSWORD_B[] = "correct horse battery staple";

// Helper: cast a string literal to unsigned char*
static const unsigned char* ub(const char* s) {
    return reinterpret_cast<const unsigned char*>(s);
}

// ── Output properties ─────────────────────────────────────────────────────────

TEST(KdfTest, OutputIs32Bytes) {
    auto key = derive_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    EXPECT_EQ(key.size(), 32u);
}

TEST(KdfTest, OutputIsNotAllZeros) {
    auto key = derive_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    bool all_zero = true;
    for (size_t i = 0; i < key.size(); ++i)
        if (key.data()[i] != 0) { all_zero = false; break; }
    EXPECT_FALSE(all_zero);
}

// ── Determinism ───────────────────────────────────────────────────────────────

TEST(KdfTest, SameInputsSameOutput) {
    auto key1 = derive_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto key2 = derive_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    ASSERT_EQ(key1.size(), key2.size());
    EXPECT_EQ(memcmp(key1.data(), key2.data(), key1.size()), 0);
}

// ── Salt sensitivity ──────────────────────────────────────────────────────────

TEST(KdfTest, DifferentSaltDifferentOutput) {
    auto key1 = derive_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto key2 = derive_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_B, sizeof(SALT_B));
    ASSERT_EQ(key1.size(), key2.size());
    EXPECT_NE(memcmp(key1.data(), key2.data(), key1.size()), 0);
}

// ── Password sensitivity ──────────────────────────────────────────────────────

TEST(KdfTest, DifferentPasswordDifferentOutput) {
    auto key1 = derive_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto key2 = derive_key(ub(PASSWORD_B), strlen(PASSWORD_B), SALT_A, sizeof(SALT_A));
    ASSERT_EQ(key1.size(), key2.size());
    EXPECT_NE(memcmp(key1.data(), key2.data(), key1.size()), 0);
}

// ── Input validation ──────────────────────────────────────────────────────────

TEST(KdfTest, NullPasswordThrows) {
    EXPECT_THROW(derive_key(nullptr, 8, SALT_A, sizeof(SALT_A)), std::invalid_argument);
}

TEST(KdfTest, EmptyPasswordThrows) {
    EXPECT_THROW(derive_key(ub(PASSWORD_A), 0, SALT_A, sizeof(SALT_A)), std::invalid_argument);
}

TEST(KdfTest, NullSaltThrows) {
    EXPECT_THROW(derive_key(ub(PASSWORD_A), strlen(PASSWORD_A), nullptr, 16), std::invalid_argument);
}

TEST(KdfTest, EmptySaltThrows) {
    EXPECT_THROW(derive_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, 0), std::invalid_argument);
}
