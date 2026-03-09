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

// =============================================================================
// derive_vault_key (renamed from derive_key in v0.1)
// =============================================================================

TEST(KdfTest, OutputIs32Bytes) {
    auto key = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    EXPECT_EQ(key.size(), 32u);
}

TEST(KdfTest, OutputIsNotAllZeros) {
    auto key = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    bool all_zero = true;
    for (size_t i = 0; i < key.size(); ++i)
        if (key.data()[i] != 0) { all_zero = false; break; }
    EXPECT_FALSE(all_zero);
}

// ── Determinism ───────────────────────────────────────────────────────────────

TEST(KdfTest, SameInputsSameOutput) {
    auto key1 = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto key2 = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    ASSERT_EQ(key1.size(), key2.size());
    EXPECT_EQ(memcmp(key1.data(), key2.data(), key1.size()), 0);
}

// ── Salt sensitivity ──────────────────────────────────────────────────────────

TEST(KdfTest, DifferentSaltDifferentOutput) {
    auto key1 = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto key2 = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_B, sizeof(SALT_B));
    ASSERT_EQ(key1.size(), key2.size());
    EXPECT_NE(memcmp(key1.data(), key2.data(), key1.size()), 0);
}

// ── Password sensitivity ──────────────────────────────────────────────────────

TEST(KdfTest, DifferentPasswordDifferentOutput) {
    auto key1 = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto key2 = derive_vault_key(ub(PASSWORD_B), strlen(PASSWORD_B), SALT_A, sizeof(SALT_A));
    ASSERT_EQ(key1.size(), key2.size());
    EXPECT_NE(memcmp(key1.data(), key2.data(), key1.size()), 0);
}

// ── Input validation ──────────────────────────────────────────────────────────

TEST(KdfTest, NullPasswordThrows) {
    EXPECT_THROW(derive_vault_key(nullptr, 8, SALT_A, sizeof(SALT_A)), std::invalid_argument);
}

TEST(KdfTest, EmptyPasswordThrows) {
    EXPECT_THROW(derive_vault_key(ub(PASSWORD_A), 0, SALT_A, sizeof(SALT_A)), std::invalid_argument);
}

TEST(KdfTest, NullSaltThrows) {
    EXPECT_THROW(derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), nullptr, 16), std::invalid_argument);
}

TEST(KdfTest, EmptySaltThrows) {
    EXPECT_THROW(derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, 0), std::invalid_argument);
}

// =============================================================================
// derive_entry_key (HKDF-SHA256, new in v0.2)
// =============================================================================

static const std::array<uint8_t, 16> UUID_A = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x47, 0x08,
    0x89, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
};

static const std::array<uint8_t, 16> UUID_B = {
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x41, 0x22,
    0x83, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00
};

TEST(EntryKeyTest, OutputIs32Bytes) {
    auto vault_key = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto entry_key = derive_entry_key(vault_key, UUID_A);
    EXPECT_EQ(entry_key.size(), 32u);
}

TEST(EntryKeyTest, OutputIsNotAllZeros) {
    auto vault_key = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto entry_key = derive_entry_key(vault_key, UUID_A);
    bool all_zero = true;
    for (size_t i = 0; i < entry_key.size(); ++i)
        if (entry_key.data()[i] != 0) { all_zero = false; break; }
    EXPECT_FALSE(all_zero);
}

TEST(EntryKeyTest, Deterministic) {
    auto vault_key = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto ek1 = derive_entry_key(vault_key, UUID_A);
    auto ek2 = derive_entry_key(vault_key, UUID_A);
    ASSERT_EQ(ek1.size(), ek2.size());
    EXPECT_EQ(memcmp(ek1.data(), ek2.data(), ek1.size()), 0);
}

TEST(EntryKeyTest, DifferentUuidDifferentKey) {
    auto vault_key = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto ek1 = derive_entry_key(vault_key, UUID_A);
    auto ek2 = derive_entry_key(vault_key, UUID_B);
    ASSERT_EQ(ek1.size(), ek2.size());
    EXPECT_NE(memcmp(ek1.data(), ek2.data(), ek1.size()), 0);
}

TEST(EntryKeyTest, DifferentVaultKeyDifferentEntryKey) {
    auto vk1 = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto vk2 = derive_vault_key(ub(PASSWORD_B), strlen(PASSWORD_B), SALT_A, sizeof(SALT_A));
    auto ek1 = derive_entry_key(vk1, UUID_A);
    auto ek2 = derive_entry_key(vk2, UUID_A);
    ASSERT_EQ(ek1.size(), ek2.size());
    EXPECT_NE(memcmp(ek1.data(), ek2.data(), ek1.size()), 0);
}

TEST(EntryKeyTest, EntryKeyDiffersFromVaultKey) {
    auto vault_key = derive_vault_key(ub(PASSWORD_A), strlen(PASSWORD_A), SALT_A, sizeof(SALT_A));
    auto entry_key = derive_entry_key(vault_key, UUID_A);
    ASSERT_EQ(vault_key.size(), entry_key.size());
    EXPECT_NE(memcmp(vault_key.data(), entry_key.data(), vault_key.size()), 0);
}

TEST(EntryKeyTest, InvalidVaultKeyThrows) {
    SecureBuffer short_key(16);  // wrong size
    EXPECT_THROW(derive_entry_key(short_key, UUID_A), std::invalid_argument);

    SecureBuffer empty_key;
    EXPECT_THROW(derive_entry_key(empty_key, UUID_A), std::invalid_argument);
}
