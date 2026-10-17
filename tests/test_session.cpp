#include <gtest/gtest.h>
#include <openssl/crypto.h>

#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <thread>

#include "core/session.hpp"
#include "storage/vault.hpp"

// ── Fixture ──────────────────────────────────────────────────────────────────

class SessionTest : public ::testing::Test {
protected:
    void SetUp() override {
        vault_path_ = std::filesystem::temp_directory_path() / "test_session.kwdb";
        std::filesystem::remove(vault_path_);
        std::filesystem::remove(std::string(vault_path_) + ".tmp");
    }

    void TearDown() override {
        std::filesystem::remove(vault_path_);
        std::filesystem::remove(std::string(vault_path_) + ".tmp");
    }

    std::string vault_path_;
    const std::string master_pw_ = "correct-horse-battery-staple";
    const std::string other_pw_  = "different-password-123";
};

// ── Helpers ───────────────────────────────────────────────────────────────────

static SecureBuffer make_sb(const std::string& s) {
    SecureBuffer buf(s.size());
    std::memcpy(buf.data(), s.data(), s.size());
    return buf;
}

static uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

/// Build a vault with an expired master password saved to disk.
static void make_vault_expired(const std::string& path,
                                const std::string& password) {
    auto pw = make_sb(password);
    Vault v = create_vault(path, pw.data(), pw.size());
    v.master_password_expiry_days  = 1;
    v.master_password_changed_at   = now_unix() - 2 * 86400;  // 2 days ago
    save_vault(v);
}

/// Build a vault whose master password expires in 3 days (WARNING zone).
static void make_vault_warning(const std::string& path,
                                const std::string& password) {
    auto pw = make_sb(password);
    Vault v = create_vault(path, pw.data(), pw.size());
    v.master_password_expiry_days = 30;
    // Set changed_at so that 30 days from then = 3 days from now.
    v.master_password_changed_at = now_unix() - 27 * 86400;
    save_vault(v);
}

// ── Initial state ─────────────────────────────────────────────────────────────

TEST_F(SessionTest, InitialStateIsLocked) {
    Session session;
    EXPECT_EQ(session.state(), SessionState::LOCKED);
}

TEST_F(SessionTest, VaultAccessWhileLockedThrows) {
    Session session;
    EXPECT_THROW(session.vault(), std::logic_error);
    EXPECT_THROW(session.vault_mut(), std::logic_error);
}

// ── unlock ────────────────────────────────────────────────────────────────────

TEST_F(SessionTest, UnlockTransitionsToBrowsing) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.unlock(vault_path_, pw);
    EXPECT_EQ(session.state(), SessionState::BROWSING);
}

TEST_F(SessionTest, UnlockWrongPasswordThrows) {
    auto pw      = make_sb(master_pw_);
    auto bad_pw  = make_sb("wrong-password");
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    EXPECT_THROW(session.unlock(vault_path_, bad_pw), std::runtime_error);
    // Session must remain LOCKED after a failed unlock.
    EXPECT_EQ(session.state(), SessionState::LOCKED);
}

TEST_F(SessionTest, UnlockWhenNotLockedThrows) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.unlock(vault_path_, pw);
    EXPECT_THROW(session.unlock(vault_path_, pw), std::logic_error);
}

TEST_F(SessionTest, UnlockExpiredVaultTransitionsToExpired) {
    make_vault_expired(vault_path_, master_pw_);

    auto pw = make_sb(master_pw_);
    Session session;
    session.unlock(vault_path_, pw);
    EXPECT_EQ(session.state(), SessionState::EXPIRED);
}

TEST_F(SessionTest, UnlockWarningVaultTransitionsToBrowsing) {
    make_vault_warning(vault_path_, master_pw_);

    auto pw = make_sb(master_pw_);
    Session session;
    // Warning is printed to stderr; state should still be BROWSING.
    session.unlock(vault_path_, pw);
    EXPECT_EQ(session.state(), SessionState::BROWSING);
}

// ── lock ──────────────────────────────────────────────────────────────────────

TEST_F(SessionTest, LockFromBrowsingGoesLocked) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.unlock(vault_path_, pw);
    ASSERT_EQ(session.state(), SessionState::BROWSING);
    session.lock();
    EXPECT_EQ(session.state(), SessionState::LOCKED);
}

TEST_F(SessionTest, LockFromLockedIsNoOp) {
    Session session;
    EXPECT_NO_THROW(session.lock());
    EXPECT_EQ(session.state(), SessionState::LOCKED);
}

TEST_F(SessionTest, VaultInaccessibleAfterLock) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.unlock(vault_path_, pw);
    session.lock();
    EXPECT_THROW(session.vault(), std::logic_error);
}

// ── verify_master_password ────────────────────────────────────────────────────

TEST_F(SessionTest, VerifyCorrectPasswordReturnsTrue) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.unlock(vault_path_, pw);
    EXPECT_TRUE(session.verify_master_password(pw));
}

TEST_F(SessionTest, VerifyWrongPasswordReturnsFalse) {
    auto pw     = make_sb(master_pw_);
    auto bad_pw = make_sb("wrong");
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.unlock(vault_path_, pw);
    EXPECT_FALSE(session.verify_master_password(bad_pw));
}

TEST_F(SessionTest, VerifyFromLockedThrows) {
    auto pw = make_sb(master_pw_);
    Session session;
    EXPECT_THROW(session.verify_master_password(pw), std::logic_error);
}

TEST_F(SessionTest, VerifyFromExpiredStateWorks) {
    make_vault_expired(vault_path_, master_pw_);

    auto pw = make_sb(master_pw_);
    Session session;
    session.unlock(vault_path_, pw);
    ASSERT_EQ(session.state(), SessionState::EXPIRED);
    EXPECT_TRUE(session.verify_master_password(pw));
}

// ── retrieve ──────────────────────────────────────────────────────────────────

TEST_F(SessionTest, RetrieveReturnsCorrectPassword) {
    auto pw = make_sb(master_pw_);
    Vault v = create_vault(vault_path_, pw.data(), pw.size());

    auto entry_pw = make_sb("hunter2");
    auto uuid = vault_add_entry(v, "github", "github.com", "alice", entry_pw);
    save_vault(v);

    Session session;
    session.unlock(vault_path_, pw);
    PasswordEntry pe = session.retrieve(uuid, pw);

    ASSERT_EQ(pe.password.size(), 7u);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(pe.password.data()),
                          pe.password.size()),
              "hunter2");
}

TEST_F(SessionTest, RetrieveStateReturnsToBrowsing) {
    auto pw = make_sb(master_pw_);
    Vault v = create_vault(vault_path_, pw.data(), pw.size());

    auto entry_pw = make_sb("pass");
    auto uuid = vault_add_entry(v, "site", "example.com", "bob", entry_pw);
    save_vault(v);

    Session session;
    session.unlock(vault_path_, pw);
    session.retrieve(uuid, pw);
    EXPECT_EQ(session.state(), SessionState::BROWSING);
}

TEST_F(SessionTest, RetrieveWrongPasswordThrows) {
    auto pw      = make_sb(master_pw_);
    auto bad_pw  = make_sb("bad");
    Vault v = create_vault(vault_path_, pw.data(), pw.size());

    auto entry_pw = make_sb("pass");
    auto uuid = vault_add_entry(v, "site", "example.com", "bob", entry_pw);
    save_vault(v);

    Session session;
    session.unlock(vault_path_, pw);
    EXPECT_THROW(session.retrieve(uuid, bad_pw), std::runtime_error);
    // State must return to BROWSING even on auth failure.
    EXPECT_EQ(session.state(), SessionState::BROWSING);
}

TEST_F(SessionTest, RetrieveFromLockedThrows) {
    std::array<uint8_t, 16> dummy_id{};
    auto pw = make_sb(master_pw_);
    Session session;
    EXPECT_THROW(session.retrieve(dummy_id, pw), std::logic_error);
}

TEST_F(SessionTest, RetrieveNonExistentEntryThrows) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    std::array<uint8_t, 16> bad_id{};
    bad_id[0] = 0xDE; bad_id[1] = 0xAD;

    Session session;
    session.unlock(vault_path_, pw);
    EXPECT_THROW(session.retrieve(bad_id, pw), std::runtime_error);
    EXPECT_EQ(session.state(), SessionState::BROWSING);
}

// ── change_master ─────────────────────────────────────────────────────────────

TEST_F(SessionTest, ChangeMasterFromBrowsing) {
    auto pw     = make_sb(master_pw_);
    auto new_pw = make_sb("new-super-secret");
    Vault v = create_vault(vault_path_, pw.data(), pw.size());

    auto entry_pw = make_sb("mypass");
    auto uuid = vault_add_entry(v, "service", "service.io", "carol", entry_pw);
    save_vault(v);

    Session session;
    session.unlock(vault_path_, pw);
    session.change_master(pw, new_pw);

    // After rotation, state is BROWSING.
    EXPECT_EQ(session.state(), SessionState::BROWSING);

    // New password must verify correctly.
    EXPECT_TRUE(session.verify_master_password(new_pw));
    EXPECT_FALSE(session.verify_master_password(pw));

    // The entry password must still be retrievable under the new master password.
    PasswordEntry pe = session.retrieve(uuid, new_pw);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(pe.password.data()),
                          pe.password.size()),
              "mypass");
}

TEST_F(SessionTest, ChangeMasterFromExpired) {
    make_vault_expired(vault_path_, master_pw_);

    auto pw     = make_sb(master_pw_);
    auto new_pw = make_sb("brand-new-password");
    Session session;
    session.unlock(vault_path_, pw);
    ASSERT_EQ(session.state(), SessionState::EXPIRED);

    session.change_master(pw, new_pw);
    EXPECT_EQ(session.state(), SessionState::BROWSING);
    EXPECT_TRUE(session.verify_master_password(new_pw));
}

TEST_F(SessionTest, ChangeMasterWrongOldPasswordThrows) {
    auto pw     = make_sb(master_pw_);
    auto bad_pw = make_sb("wrong");
    auto new_pw = make_sb("new-pass");
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.unlock(vault_path_, pw);
    EXPECT_THROW(session.change_master(bad_pw, new_pw), std::runtime_error);
}

TEST_F(SessionTest, ChangeMasterPersistsToDisk) {
    auto pw     = make_sb(master_pw_);
    auto new_pw = make_sb("rotated-password");
    create_vault(vault_path_, pw.data(), pw.size());

    {
        Session session;
        session.unlock(vault_path_, pw);
        session.change_master(pw, new_pw);
    }

    // Reload with new password — must succeed.
    Session session2;
    EXPECT_NO_THROW(session2.unlock(vault_path_, new_pw));
    EXPECT_EQ(session2.state(), SessionState::BROWSING);

    // Old password must fail.
    Session session3;
    EXPECT_THROW(session3.unlock(vault_path_, pw), std::runtime_error);
}

TEST_F(SessionTest, ChangeMasterFromLockedThrows) {
    auto pw     = make_sb(master_pw_);
    auto new_pw = make_sb("new");
    Session session;
    EXPECT_THROW(session.change_master(pw, new_pw), std::logic_error);
}

TEST_F(SessionTest, ChangeMasterResetsExpiryStatus) {
    make_vault_expired(vault_path_, master_pw_);

    auto pw     = make_sb(master_pw_);
    auto new_pw = make_sb("fresh-password");
    Session session;
    session.unlock(vault_path_, pw);
    session.change_master(pw, new_pw);

    // After rotation the expiry clock resets; vault must be in BROWSING not EXPIRED.
    EXPECT_EQ(session.state(), SessionState::BROWSING);

    // Reload to confirm the saved changed_at is recent (not expired).
    session.lock();
    session.unlock(vault_path_, new_pw);
    EXPECT_EQ(session.state(), SessionState::BROWSING);
}

// ── vault accessor ────────────────────────────────────────────────────────────

TEST_F(SessionTest, VaultAccessibleWhenBrowsing) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.unlock(vault_path_, pw);
    EXPECT_NO_THROW({ [[maybe_unused]] const Vault& v = session.vault(); });
}

// ── auto-lock timer ───────────────────────────────────────────────────────────

TEST_F(SessionTest, AutoLockAfterInactivityTimeout) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.set_auto_lock_secs(2);  // 2-second timeout for testing
    session.unlock(vault_path_, pw);
    ASSERT_EQ(session.state(), SessionState::BROWSING);

    std::this_thread::sleep_for(std::chrono::seconds(3));
    EXPECT_EQ(session.state(), SessionState::LOCKED);
}

TEST_F(SessionTest, TouchResetsAutoLockTimer) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.set_auto_lock_secs(3);  // 3-second timeout
    session.unlock(vault_path_, pw);

    // Touch twice with gaps — total elapsed > 3s but each gap < 3s.
    std::this_thread::sleep_for(std::chrono::seconds(2));
    session.touch();
    std::this_thread::sleep_for(std::chrono::seconds(2));
    session.touch();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Should still be BROWSING because touch() kept resetting the clock.
    EXPECT_EQ(session.state(), SessionState::BROWSING);
}

// ── re-unlock after lock ───────────────────────────────────────────────────────

TEST_F(SessionTest, ReUnlockAfterManualLock) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.unlock(vault_path_, pw);
    session.lock();
    ASSERT_EQ(session.state(), SessionState::LOCKED);

    // Should be able to unlock again from LOCKED.
    EXPECT_NO_THROW(session.unlock(vault_path_, pw));
    EXPECT_EQ(session.state(), SessionState::BROWSING);
}

TEST_F(SessionTest, ReUnlockAfterAutoLock) {
    auto pw = make_sb(master_pw_);
    create_vault(vault_path_, pw.data(), pw.size());

    Session session;
    session.set_auto_lock_secs(2);
    session.unlock(vault_path_, pw);

    std::this_thread::sleep_for(std::chrono::seconds(3));
    ASSERT_EQ(session.state(), SessionState::LOCKED);

    EXPECT_NO_THROW(session.unlock(vault_path_, pw));
    EXPECT_EQ(session.state(), SessionState::BROWSING);
}
