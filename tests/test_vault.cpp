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

// ═════════════════════════════════════════════════════════════════════════════
// Phase 2.3 — Entry CRUD on Vault
// ═════════════════════════════════════════════════════════════════════════════

// ── vault_add_entry ─────────────────────────────────────────────────────────

TEST_F(VaultTest, AddEntryCreatesUuidAndEncryptsPassword) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer password = make_password("my_secret_pw");
    auto uuid = vault_add_entry(vault, "GitHub", "https://github.com",
                                 "user1", password, 0);

    ASSERT_EQ(vault.entries.size(), 1u);
    ASSERT_EQ(vault.entry_passwords.size(), 1u);
    EXPECT_EQ(vault.entries[0].id, uuid);
    EXPECT_EQ(vault.entries[0].name, "GitHub");
    EXPECT_EQ(vault.entries[0].website, "https://github.com");
    EXPECT_EQ(vault.entries[0].username, "user1");
    EXPECT_GT(vault.entries[0].created_at, 0u);
    EXPECT_EQ(vault.entries[0].created_at, vault.entries[0].updated_at);

    // Decrypt and verify password
    PasswordEntry pe = get_entry_password(vault, uuid);
    std::string decrypted(reinterpret_cast<const char*>(pe.password.data()),
                           pe.password.size());
    EXPECT_EQ(decrypted, "my_secret_pw");
}

TEST_F(VaultTest, AddEntryPersistsThroughSaveLoad) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p1 = make_password("pw_one");
    SecureBuffer p2 = make_password("pw_two");
    auto id1 = vault_add_entry(vault, "Site1", "https://s1.com", "u1", p1);
    auto id2 = vault_add_entry(vault, "Site2", "https://s2.com", "u2", p2, 1702592000);
    save_vault(vault);

    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    ASSERT_EQ(loaded.entries.size(), 2u);
    EXPECT_EQ(loaded.entries[0].name, "Site1");
    EXPECT_EQ(loaded.entries[1].name, "Site2");
    EXPECT_EQ(loaded.entries[1].expires_at, 1702592000u);

    PasswordEntry pe1 = get_entry_password(loaded, id1);
    std::string d1(reinterpret_cast<const char*>(pe1.password.data()), pe1.password.size());
    EXPECT_EQ(d1, "pw_one");

    PasswordEntry pe2 = get_entry_password(loaded, id2);
    std::string d2(reinterpret_cast<const char*>(pe2.password.data()), pe2.password.size());
    EXPECT_EQ(d2, "pw_two");
}

TEST_F(VaultTest, AddEntryLockedVaultThrows) {
    Vault vault;  // no vault_key
    SecureBuffer password = make_password("pw");
    EXPECT_THROW(vault_add_entry(vault, "X", "X", "X", password), std::runtime_error);
}

// ── vault_find_entries ──────────────────────────────────────────────────────

TEST_F(VaultTest, FindEntriesByName) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    vault_add_entry(vault, "GitHub", "https://github.com", "u1", p);
    vault_add_entry(vault, "GitLab", "https://gitlab.com", "u2", p);
    vault_add_entry(vault, "Bitbucket", "https://bitbucket.org", "u3", p);

    auto results = vault_find_entries(vault, "git");
    ASSERT_EQ(results.size(), 2u);
    // Both GitHub and GitLab should match
    bool found_gh = false, found_gl = false;
    for (const auto& r : results) {
        if (r.name == "GitHub") found_gh = true;
        if (r.name == "GitLab") found_gl = true;
    }
    EXPECT_TRUE(found_gh);
    EXPECT_TRUE(found_gl);
}

TEST_F(VaultTest, FindEntriesByWebsite) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    vault_add_entry(vault, "Work", "https://corp.example.com", "admin", p);
    vault_add_entry(vault, "Personal", "https://personal.example.com", "me", p);
    vault_add_entry(vault, "Other", "https://other.io", "user", p);

    auto results = vault_find_entries(vault, "example.com");
    ASSERT_EQ(results.size(), 2u);
}

TEST_F(VaultTest, FindEntriesCaseInsensitive) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    vault_add_entry(vault, "GitHub", "https://github.com", "u1", p);

    auto r1 = vault_find_entries(vault, "GITHUB");
    EXPECT_EQ(r1.size(), 1u);

    auto r2 = vault_find_entries(vault, "github");
    EXPECT_EQ(r2.size(), 1u);

    auto r3 = vault_find_entries(vault, "GiTh");
    EXPECT_EQ(r3.size(), 1u);
}

TEST_F(VaultTest, FindEntriesNoMatch) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    vault_add_entry(vault, "GitHub", "https://github.com", "u1", p);

    auto results = vault_find_entries(vault, "nonexistent");
    EXPECT_EQ(results.size(), 0u);
}

TEST_F(VaultTest, FindEntriesEmptyQuery) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    vault_add_entry(vault, "GitHub", "https://github.com", "u1", p);

    auto results = vault_find_entries(vault, "");
    EXPECT_EQ(results.size(), 0u);
}

// ── vault_update_entry ──────────────────────────────────────────────────────

TEST_F(VaultTest, UpdateEntryMetadataOnly) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("original_pw");
    auto uuid = vault_add_entry(vault, "OldName", "https://old.com", "olduser", p);

    // Update name and website, keep password (empty SecureBuffer)
    SecureBuffer empty_pw;
    vault_update_entry(vault, uuid, "NewName", "https://new.com", "newuser",
                        empty_pw, 0);

    EXPECT_EQ(vault.entries[0].name, "NewName");
    EXPECT_EQ(vault.entries[0].website, "https://new.com");
    EXPECT_EQ(vault.entries[0].username, "newuser");

    // Password should still be the original
    PasswordEntry pe = get_entry_password(vault, uuid);
    std::string decrypted(reinterpret_cast<const char*>(pe.password.data()),
                           pe.password.size());
    EXPECT_EQ(decrypted, "original_pw");
}

TEST_F(VaultTest, UpdateEntryWithNewPassword) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("old_password");
    auto uuid = vault_add_entry(vault, "Site", "https://site.com", "user", p);

    SecureBuffer new_pw = make_password("brand_new_password!");
    vault_update_entry(vault, uuid, "", "", "", new_pw, 0);

    // Name should be unchanged (empty string = keep existing)
    EXPECT_EQ(vault.entries[0].name, "Site");

    // Password should be updated
    PasswordEntry pe = get_entry_password(vault, uuid);
    std::string decrypted(reinterpret_cast<const char*>(pe.password.data()),
                           pe.password.size());
    EXPECT_EQ(decrypted, "brand_new_password!");
}

TEST_F(VaultTest, UpdateEntryPersistsThroughSaveLoad) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    auto uuid = vault_add_entry(vault, "Site", "https://site.com", "user", p);

    SecureBuffer new_pw = make_password("updated_pw");
    vault_update_entry(vault, uuid, "UpdatedSite", "", "", new_pw, 1702592000);
    save_vault(vault);

    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    ASSERT_EQ(loaded.entries.size(), 1u);
    EXPECT_EQ(loaded.entries[0].name, "UpdatedSite");
    EXPECT_EQ(loaded.entries[0].expires_at, 1702592000u);

    PasswordEntry pe = get_entry_password(loaded, uuid);
    std::string decrypted(reinterpret_cast<const char*>(pe.password.data()),
                           pe.password.size());
    EXPECT_EQ(decrypted, "updated_pw");
}

TEST_F(VaultTest, UpdateEntryNotFoundThrows) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    auto fake_id = generate_uuid();
    SecureBuffer p = make_password("pw");
    EXPECT_THROW(vault_update_entry(vault, fake_id, "X", "X", "X", p, 0),
                 std::runtime_error);
}

TEST_F(VaultTest, UpdateEntrySetsUpdatedAt) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    auto uuid = vault_add_entry(vault, "Site", "https://site.com", "user", p);
    uint64_t original_updated = vault.entries[0].updated_at;

    SecureBuffer empty_pw;
    vault_update_entry(vault, uuid, "NewName", "", "", empty_pw, 0);
    EXPECT_GE(vault.entries[0].updated_at, original_updated);
}

// ── vault_delete_entry ──────────────────────────────────────────────────────

TEST_F(VaultTest, DeleteEntryRemovesBoth) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    auto id1 = vault_add_entry(vault, "Site1", "https://s1.com", "u1", p);
    auto id2 = vault_add_entry(vault, "Site2", "https://s2.com", "u2", p);
    auto id3 = vault_add_entry(vault, "Site3", "https://s3.com", "u3", p);

    ASSERT_EQ(vault.entries.size(), 3u);
    ASSERT_EQ(vault.entry_passwords.size(), 3u);

    vault_delete_entry(vault, id2);

    ASSERT_EQ(vault.entries.size(), 2u);
    ASSERT_EQ(vault.entry_passwords.size(), 2u);
    EXPECT_EQ(vault.entries[0].name, "Site1");
    EXPECT_EQ(vault.entries[1].name, "Site3");

    // Remaining entries should still decrypt correctly
    PasswordEntry pe1 = get_entry_password(vault, id1);
    PasswordEntry pe3 = get_entry_password(vault, id3);
    std::string d1(reinterpret_cast<const char*>(pe1.password.data()), pe1.password.size());
    std::string d3(reinterpret_cast<const char*>(pe3.password.data()), pe3.password.size());
    EXPECT_EQ(d1, "pw");
    EXPECT_EQ(d3, "pw");
}

TEST_F(VaultTest, DeleteEntryPersistsThroughSaveLoad) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    auto id1 = vault_add_entry(vault, "Keep", "https://keep.com", "u1", p);
    vault_add_entry(vault, "Delete", "https://delete.com", "u2", p);

    vault_delete_entry(vault, vault.entries[1].id);
    save_vault(vault);

    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    ASSERT_EQ(loaded.entries.size(), 1u);
    EXPECT_EQ(loaded.entries[0].name, "Keep");

    PasswordEntry pe = get_entry_password(loaded, id1);
    std::string decrypted(reinterpret_cast<const char*>(pe.password.data()),
                           pe.password.size());
    EXPECT_EQ(decrypted, "pw");
}

TEST_F(VaultTest, DeleteEntryNotFoundThrows) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    auto fake_id = generate_uuid();
    EXPECT_THROW(vault_delete_entry(vault, fake_id), std::runtime_error);
}

TEST_F(VaultTest, DeleteAllEntries) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    SecureBuffer p = make_password("pw");
    auto id1 = vault_add_entry(vault, "S1", "https://s1.com", "u1", p);
    auto id2 = vault_add_entry(vault, "S2", "https://s2.com", "u2", p);

    vault_delete_entry(vault, id1);
    vault_delete_entry(vault, id2);

    EXPECT_EQ(vault.entries.size(), 0u);
    EXPECT_EQ(vault.entry_passwords.size(), 0u);

    save_vault(vault);
    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    EXPECT_EQ(loaded.entries.size(), 0u);
}

// ── CRUD integration ────────────────────────────────────────────────────────

TEST_F(VaultTest, FullCrudLifecycle) {
    auto pw = reinterpret_cast<const unsigned char*>(master_pw_.data());
    Vault vault = create_vault(vault_path_, pw, master_pw_.size());

    // Add
    SecureBuffer p1 = make_password("github_pass");
    SecureBuffer p2 = make_password("gitlab_pass");
    auto gh_id = vault_add_entry(vault, "GitHub", "https://github.com", "dev", p1);
    auto gl_id = vault_add_entry(vault, "GitLab", "https://gitlab.com", "dev", p2);
    ASSERT_EQ(vault.entries.size(), 2u);

    // Find
    auto found = vault_find_entries(vault, "git");
    EXPECT_EQ(found.size(), 2u);

    found = vault_find_entries(vault, "github");
    ASSERT_EQ(found.size(), 1u);
    EXPECT_EQ(found[0].name, "GitHub");

    // Get (decrypt on demand)
    PasswordEntry pe = get_entry_password(vault, gh_id);
    std::string d(reinterpret_cast<const char*>(pe.password.data()), pe.password.size());
    EXPECT_EQ(d, "github_pass");

    // Update
    SecureBuffer new_pw = make_password("new_github_pass!");
    vault_update_entry(vault, gh_id, "", "https://github.com/new", "", new_pw, 0);
    EXPECT_EQ(vault.entries[0].website, "https://github.com/new");

    pe = get_entry_password(vault, gh_id);
    d = std::string(reinterpret_cast<const char*>(pe.password.data()), pe.password.size());
    EXPECT_EQ(d, "new_github_pass!");

    // Delete
    vault_delete_entry(vault, gl_id);
    ASSERT_EQ(vault.entries.size(), 1u);
    EXPECT_THROW(get_entry_password(vault, gl_id), std::runtime_error);

    // Save and reload
    save_vault(vault);
    Vault loaded = load_vault(vault_path_, pw, master_pw_.size());
    ASSERT_EQ(loaded.entries.size(), 1u);
    EXPECT_EQ(loaded.entries[0].name, "GitHub");

    pe = get_entry_password(loaded, gh_id);
    d = std::string(reinterpret_cast<const char*>(pe.password.data()), pe.password.size());
    EXPECT_EQ(d, "new_github_pass!");
}
