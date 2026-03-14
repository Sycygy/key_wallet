#include <gtest/gtest.h>
#include <openssl/crypto.h>

#include <cstring>
#include <filesystem>
#include <fstream>

#include "storage/vault.hpp"
#include "crypto/aead/aead.hpp"
#include "crypto/kdf/kdf.hpp"
#include "crypto/random/random.hpp"

// ── Fixture ──────────────────────────────────────────────────────────────────

class VaultTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // Do NOT init a small secure heap here — Argon2id (m=64 MiB) uses
        // OPENSSL_secure_malloc internally and would exhaust it. SecureBuffer
        // gracefully falls back to OPENSSL_malloc when uninitialised.
    }

    void SetUp() override {
        vault_path_ = std::filesystem::temp_directory_path() / "test_vault.kwdb";
        // Clean up any leftover test file
        std::filesystem::remove(vault_path_);
        std::filesystem::remove(std::string(vault_path_) + ".tmp");
    }

    void TearDown() override {
        std::filesystem::remove(vault_path_);
        std::filesystem::remove(std::string(vault_path_) + ".tmp");
    }

    std::string vault_path_;
    const std::string master_pw_ = "correct-horse-battery-staple";
};

// ── Helpers ──────────────────────────────────────────────────────────────────

static SecureBuffer make_password(const std::string& pw) {
    SecureBuffer buf(pw.size());
    std::memcpy(buf.data(), pw.data(), pw.size());
    return buf;
}

/// Helper to add an entry to a vault (encrypt password, update index).
static void add_entry_to_vault(Vault& vault,
                                const std::string& name,
                                const std::string& website,
                                const std::string& username,
                                const std::string& password,
                                uint64_t expires_at = 0) {
    auto uuid = generate_uuid();

    BrowsableEntry be;
    be.id         = uuid;
    be.name       = name;
    be.website    = website;
    be.username   = username;
    be.created_at = 1700000000;
    be.updated_at = 1700000000;
    be.expires_at = expires_at;
    vault.entries.push_back(be);

    // Derive entry key and encrypt the password
    SecureBuffer entry_key = derive_entry_key(vault.vault_key, uuid);
    SecureBuffer pw_buf = make_password(password);
    auto pw_serialized = serialize_password(pw_buf);

    auto aad = build_aad(vault);
    auto ct = aead_encrypt(entry_key,
                           pw_serialized.data(), pw_serialized.size(),
                           aad.data(), aad.size());

    EntryCiphertext ec;
    ec.iv         = std::move(ct.iv);
    ec.tag        = std::move(ct.tag);
    ec.ciphertext = std::move(ct.ciphertext);
    vault.entry_passwords.push_back(std::move(ec));
}

// ═════════════════════════════════════════════════════════════════════════════
// Create → Load round-trip
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, CreateAndLoadEmptyVault) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());

    Vault created = create_vault(vault_path_, pw, master_pw_.size());
    EXPECT_EQ(created.entries.size(), 0u);
    EXPECT_EQ(created.save_counter, 0u);
    EXPECT_EQ(created.master_password_expiry_days, VAULT_DEFAULT_EXPIRY_DAYS);
    EXPECT_FALSE(created.vault_key.empty());

    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    EXPECT_EQ(loaded.entries.size(), 0u);
    EXPECT_EQ(loaded.save_counter, 0u);
    EXPECT_EQ(loaded.master_password_expiry_days, VAULT_DEFAULT_EXPIRY_DAYS);
    EXPECT_EQ(loaded.created_at, created.created_at);
}

TEST_F(VaultTest, CreateAndLoadWithEntries) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());

    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    // Add entries
    add_entry_to_vault(vault, "GitHub", "https://github.com", "user1", "gh_pass123");
    add_entry_to_vault(vault, "GitLab", "https://gitlab.com", "user2", "gl_secret!");

    save_vault(vault);

    // Reload
    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    ASSERT_EQ(loaded.entries.size(), 2u);
    EXPECT_EQ(loaded.entries[0].name, "GitHub");
    EXPECT_EQ(loaded.entries[0].website, "https://github.com");
    EXPECT_EQ(loaded.entries[0].username, "user1");
    EXPECT_EQ(loaded.entries[1].name, "GitLab");
    EXPECT_EQ(loaded.entries[1].website, "https://gitlab.com");
    EXPECT_EQ(loaded.entries[1].username, "user2");
    EXPECT_EQ(loaded.save_counter, 1u);  // incremented once by save_vault
}

// ═════════════════════════════════════════════════════════════════════════════
// Per-entry password decryption
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, GetEntryPasswordDecryptsOnDemand) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());

    Vault vault = create_vault(vault_path_, pw, master_pw_.size());
    add_entry_to_vault(vault, "TestSite", "https://test.com", "admin", "super_secret_pw!");
    save_vault(vault);

    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    ASSERT_EQ(loaded.entries.size(), 1u);

    PasswordEntry pe = get_entry_password(loaded, loaded.entries[0].id);
    EXPECT_EQ(pe.name, "TestSite");
    EXPECT_EQ(pe.website, "https://test.com");
    EXPECT_EQ(pe.username, "admin");
    std::string decrypted_pw(reinterpret_cast<const char*>(pe.password.data()),
                              pe.password.size());
    EXPECT_EQ(decrypted_pw, "super_secret_pw!");
}

TEST_F(VaultTest, GetEntryPasswordMultipleEntries) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());

    Vault vault = create_vault(vault_path_, pw, master_pw_.size());
    add_entry_to_vault(vault, "Site1", "https://s1.com", "u1", "pw1_value");
    add_entry_to_vault(vault, "Site2", "https://s2.com", "u2", "pw2_value");
    add_entry_to_vault(vault, "Site3", "https://s3.com", "u3", "pw3_value");
    save_vault(vault);

    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    ASSERT_EQ(loaded.entries.size(), 3u);

    // Decrypt each individually
    for (size_t i = 0; i < 3; ++i) {
        PasswordEntry pe = get_entry_password(loaded, loaded.entries[i].id);
        std::string decrypted(reinterpret_cast<const char*>(pe.password.data()),
                               pe.password.size());
        EXPECT_EQ(decrypted, "pw" + std::to_string(i + 1) + "_value");
    }
}

TEST_F(VaultTest, GetEntryPasswordNotFound) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());

    Vault vault = create_vault(vault_path_, pw, master_pw_.size());
    add_entry_to_vault(vault, "Site", "https://site.com", "u", "pass");
    save_vault(vault);

    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    auto fake_id = generate_uuid();
    EXPECT_THROW(get_entry_password(loaded, fake_id), std::runtime_error);
}

// ═════════════════════════════════════════════════════════════════════════════
// Wrong password → error
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, WrongPasswordRejected) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    create_vault(vault_path_, pw, master_pw_.size());

    std::string wrong = "wrong-password-123";
    auto wpw = reinterpret_cast<const unsigned char*>(wrong.data());
    EXPECT_THROW(load_vault(vault_path_, wpw, wrong.size()), std::runtime_error);
}

// ═════════════════════════════════════════════════════════════════════════════
// Verify master password
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, VerifyMasterPasswordCorrect) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    EXPECT_TRUE(verify_master_password(vault, pw, master_pw_.size()));
}

TEST_F(VaultTest, VerifyMasterPasswordWrong) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    std::string wrong = "nope";
    auto wpw = reinterpret_cast<const unsigned char*>(wrong.data());
    EXPECT_FALSE(verify_master_password(vault, wpw, wrong.size()));
}

TEST_F(VaultTest, VerifyMasterPasswordEmpty) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    EXPECT_FALSE(verify_master_password(vault, nullptr, 0));
}

// ═════════════════════════════════════════════════════════════════════════════
// Tampered file → error
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, TamperedFileFails) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    create_vault(vault_path_, pw, master_pw_.size());

    // Read, tamper, rewrite
    std::ifstream fin(vault_path_, std::ios::binary | std::ios::ate);
    auto size = fin.tellg();
    std::vector<uint8_t> data(static_cast<size_t>(size));
    fin.seekg(0);
    fin.read(reinterpret_cast<char*>(data.data()), size);
    fin.close();

    // Flip a byte in the verification token area
    data[VAULT_HEADER_LEN + 5] ^= 0xFF;

    std::ofstream fout(vault_path_, std::ios::binary | std::ios::trunc);
    fout.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));
    fout.close();

    EXPECT_THROW(load_vault(vault_path_, pw, master_pw_.size()), std::runtime_error);
}

// ═════════════════════════════════════════════════════════════════════════════
// Version detection
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, FormatVersion1Rejected) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    create_vault(vault_path_, pw, master_pw_.size());

    // Patch version to 1 in the file
    std::fstream f(vault_path_, std::ios::in | std::ios::out | std::ios::binary);
    f.seekp(8); // version is at offset 8
    uint8_t v1[2] = {1, 0};
    f.write(reinterpret_cast<const char*>(v1), 2);
    f.close();

    try {
        load_vault(vault_path_, pw, master_pw_.size());
        FAIL() << "Expected runtime_error for v0.1 vault";
    } catch (const std::runtime_error& e) {
        std::string msg = e.what();
        EXPECT_NE(msg.find("v0.1"), std::string::npos) << "Error should mention v0.1: " << msg;
        EXPECT_NE(msg.find("migrate"), std::string::npos) << "Error should mention migration: " << msg;
    }
}

TEST_F(VaultTest, UnsupportedVersionRejected) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    create_vault(vault_path_, pw, master_pw_.size());

    // Patch version to 99
    std::fstream f(vault_path_, std::ios::in | std::ios::out | std::ios::binary);
    f.seekp(8);
    uint8_t v99[2] = {99, 0};
    f.write(reinterpret_cast<const char*>(v99), 2);
    f.close();

    EXPECT_THROW(load_vault(vault_path_, pw, master_pw_.size()), std::runtime_error);
}

// ═════════════════════════════════════════════════════════════════════════════
// Save counter increments
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, SaveCounterIncrements) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());
    EXPECT_EQ(vault.save_counter, 0u);

    save_vault(vault);
    EXPECT_EQ(vault.save_counter, 1u);

    save_vault(vault);
    EXPECT_EQ(vault.save_counter, 2u);

    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    EXPECT_EQ(loaded.save_counter, 2u);
}

// ═════════════════════════════════════════════════════════════════════════════
// Expiry checks
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, ExpiryDisabled) {
    Vault vault;
    vault.master_password_expiry_days = 0;
    vault.master_password_changed_at = 0; // ancient
    EXPECT_EQ(check_expiry(vault), ExpiryStatus::OK);
    EXPECT_EQ(days_until_expiry(vault), INT64_MAX);
}

TEST_F(VaultTest, ExpiryOK) {
    Vault vault;
    vault.master_password_expiry_days = 30;
    // Changed just now
    vault.master_password_changed_at =
        static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    EXPECT_EQ(check_expiry(vault), ExpiryStatus::OK);
    int64_t d = days_until_expiry(vault);
    EXPECT_GE(d, 29);
    EXPECT_LE(d, 30);
}

TEST_F(VaultTest, ExpiryWarning) {
    Vault vault;
    vault.master_password_expiry_days = 30;
    // Changed 25 days ago → 5 days remaining
    uint64_t now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    vault.master_password_changed_at = now - (25 * 86400);
    EXPECT_EQ(check_expiry(vault), ExpiryStatus::WARNING);
    int64_t d = days_until_expiry(vault);
    EXPECT_GE(d, 4);
    EXPECT_LE(d, 5);
}

TEST_F(VaultTest, ExpiryExpired) {
    Vault vault;
    vault.master_password_expiry_days = 30;
    // Changed 35 days ago → 5 days overdue
    uint64_t now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    vault.master_password_changed_at = now - (35 * 86400);
    EXPECT_EQ(check_expiry(vault), ExpiryStatus::EXPIRED);
    int64_t d = days_until_expiry(vault);
    EXPECT_LE(d, -4);
    EXPECT_GE(d, -6);
}

// ═════════════════════════════════════════════════════════════════════════════
// AAD consistency
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, AadHasCorrectSize) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());
    auto aad = build_aad(vault);
    EXPECT_EQ(aad.size(), VAULT_HEADER_LEN);
}

TEST_F(VaultTest, AadStartsWithMagic) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());
    auto aad = build_aad(vault);
    EXPECT_EQ(std::memcmp(aad.data(), VAULT_MAGIC, 8), 0);
}

// ═════════════════════════════════════════════════════════════════════════════
// Edge cases
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, EmptyPasswordRejected) {
    EXPECT_THROW(create_vault(vault_path_, nullptr, 0), std::invalid_argument);
}

TEST_F(VaultTest, NonexistentFileRejected) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    EXPECT_THROW(load_vault("/tmp/nonexistent_vault_xyz.kwdb", pw, master_pw_.size()),
                 std::runtime_error);
}

TEST_F(VaultTest, TruncatedFileRejected) {
    // Write a file that's too small
    std::ofstream f(vault_path_, std::ios::binary);
    f.write("KEYMGR\x01\x00", 8);
    f.close();

    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    EXPECT_THROW(load_vault(vault_path_, pw, master_pw_.size()), std::runtime_error);
}

TEST_F(VaultTest, BadMagicRejected) {
    // Write a file with wrong magic
    std::vector<uint8_t> data(200, 0);
    data[0] = 'X';
    std::ofstream f(vault_path_, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    f.close();

    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    EXPECT_THROW(load_vault(vault_path_, pw, master_pw_.size()), std::runtime_error);
}

// ═════════════════════════════════════════════════════════════════════════════
// Entry password survives save → load → get_entry_password cycle
// ═════════════════════════════════════════════════════════════════════════════

TEST_F(VaultTest, PasswordSurvivesFullCycle) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());

    // Create, add entry, save
    Vault v1 = create_vault(vault_path_, pw, master_pw_.size());
    add_entry_to_vault(v1, "Acme", "https://acme.com", "roadrunner",
                       "beep-beep-123!@#$%^&*()_ñ");
    save_vault(v1);

    // Load, decrypt password
    Vault v2 = load_vault(vault_path_, pw, master_pw_.size());
    PasswordEntry pe = get_entry_password(v2, v2.entries[0].id);
    std::string decrypted(reinterpret_cast<const char*>(pe.password.data()),
                           pe.password.size());
    EXPECT_EQ(decrypted, "beep-beep-123!@#$%^&*()_ñ");
}

TEST_F(VaultTest, EntryExpiresAtPreserved) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());

    Vault vault = create_vault(vault_path_, pw, master_pw_.size());
    add_entry_to_vault(vault, "Expiring", "https://exp.com", "user",
                       "pw123", 1702592000);
    save_vault(vault);

    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    ASSERT_EQ(loaded.entries.size(), 1u);
    EXPECT_EQ(loaded.entries[0].expires_at, 1702592000u);
}
