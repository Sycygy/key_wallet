#include "core/session.hpp"

#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <vector>

#include "crypto/aead/aead.hpp"
#include "crypto/kdf/kdf.hpp"
#include "crypto/random/random.hpp"
#include "storage/entry.hpp"
#include "storage/vault.hpp"

// ── Helpers ──────────────────────────────────────────────────────────────────

static uint64_t session_now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// ── Constructor / Destructor ──────────────────────────────────────────────────

Session::Session() = default;

Session::~Session() {
    // Stop the timer first (without holding the mutex) to avoid joining a thread
    // that is itself waiting for the mutex.
    stop_timer();
    std::lock_guard<std::mutex> guard(mutex_);
    vault_.reset();
    state_ = SessionState::LOCKED;
}

// ── unlock ────────────────────────────────────────────────────────────────────

void Session::unlock(const std::string& vault_path,
                     const SecureBuffer& master_password) {
    // Stop any previous timer thread before acquiring the mutex.
    stop_timer();

    std::lock_guard<std::mutex> guard(mutex_);

    if (state_ != SessionState::LOCKED)
        throw std::logic_error("Session must be in LOCKED state to unlock");

    if (master_password.empty())
        throw std::invalid_argument("Master password must not be empty");

    // Load vault — decrypts index only; passwords remain as ciphertexts.
    vault_ = load_vault(vault_path, master_password.data(), master_password.size());

    // Check master password expiry.
    ExpiryStatus expiry = check_expiry(*vault_);
    if (expiry == ExpiryStatus::EXPIRED) {
        state_ = SessionState::EXPIRED;
        int64_t days = days_until_expiry(*vault_);
        std::cerr << "error: Master password expired " << (-days)
                  << " day(s) ago. Run change-master to continue.\n";
    } else {
        state_ = SessionState::BROWSING;
        if (expiry == ExpiryStatus::WARNING) {
            int64_t days = days_until_expiry(*vault_);
            std::cerr << "warning: Master password expires in " << days
                      << " day(s). Consider running change-master soon.\n";
        }
    }

    last_activity_ = std::chrono::steady_clock::now();
    start_timer();
}

// ── lock ──────────────────────────────────────────────────────────────────────

void Session::lock() {
    // Stop the timer without holding the mutex.
    stop_timer();
    std::lock_guard<std::mutex> guard(mutex_);
    vault_.reset();
    state_ = SessionState::LOCKED;
}

// ── verify_master_password ────────────────────────────────────────────────────

bool Session::verify_master_password(const SecureBuffer& master_password) {
    std::lock_guard<std::mutex> guard(mutex_);

    if (state_ != SessionState::BROWSING && state_ != SessionState::EXPIRED)
        throw std::logic_error(
            "Session must be in BROWSING or EXPIRED state to verify password");

    if (!vault_)
        throw std::logic_error("Vault not loaded");

    return ::verify_master_password(*vault_,
                                    master_password.data(),
                                    master_password.size());
}

// ── retrieve ──────────────────────────────────────────────────────────────────

PasswordEntry Session::retrieve(const std::array<uint8_t, 16>& entry_id,
                                 const SecureBuffer& master_password) {
    std::lock_guard<std::mutex> guard(mutex_);

    if (state_ != SessionState::BROWSING)
        throw std::logic_error("Session must be in BROWSING state to retrieve a password");

    if (!vault_)
        throw std::logic_error("Vault not loaded");

    // Re-authenticate before exposing any password material.
    if (!::verify_master_password(*vault_,
                                   master_password.data(),
                                   master_password.size())) {
        throw std::runtime_error("Authentication failed");
    }

    // Transient: BROWSING → RETRIEVING → BROWSING.
    state_ = SessionState::RETRIEVING;
    PasswordEntry pe;
    try {
        pe = get_entry_password(*vault_, entry_id);
    } catch (...) {
        state_ = SessionState::BROWSING;
        throw;
    }

    state_ = SessionState::BROWSING;
    last_activity_ = std::chrono::steady_clock::now();
    return pe;
}

// ── change_master ─────────────────────────────────────────────────────────────

void Session::change_master(const SecureBuffer& old_password,
                             const SecureBuffer& new_password) {
    std::lock_guard<std::mutex> guard(mutex_);

    if (state_ != SessionState::BROWSING && state_ != SessionState::EXPIRED)
        throw std::logic_error(
            "change-master requires BROWSING or EXPIRED state");

    if (!vault_)
        throw std::logic_error("Vault not loaded");

    if (new_password.empty())
        throw std::invalid_argument("New master password must not be empty");

    // Verify old password first.
    if (!::verify_master_password(*vault_,
                                   old_password.data(),
                                   old_password.size())) {
        throw std::runtime_error("Authentication failed");
    }

    try {
        Vault& v = *vault_;

        // 1. Decrypt all entry passwords under the current (old) vault key.
        //    Must happen BEFORE we overwrite vault.salt / vault.vault_key.
        std::vector<SecureBuffer> plaintexts;
        plaintexts.reserve(v.entries.size());
        for (const auto& entry : v.entries) {
            PasswordEntry pe = get_entry_password(v, entry.id);
            plaintexts.push_back(std::move(pe.password));
        }

        // 2. Generate new salt and derive new vault key.
        SecureBuffer new_salt_buf = random_bytes(VAULT_SALT_LEN);
        std::memcpy(v.salt.data(), new_salt_buf.data(), VAULT_SALT_LEN);

        v.vault_key = derive_vault_key(new_password.data(), new_password.size(),
                                        v.salt.data(), VAULT_SALT_LEN);

        // 3. Reset counters and expiry clock.
        v.save_counter = 0;  // Fresh counter for the new key lifetime.
        v.master_password_changed_at = session_now_unix();

        // 4. Build new AAD (reflects updated salt).
        auto aad = build_aad(v);

        // 5. Re-generate verification token under new vault key + new AAD.
        std::vector<uint8_t> zero_pt(VAULT_VERIFY_PT_LEN, 0);
        auto verify_ct = aead_encrypt(v.vault_key,
                                       zero_pt.data(), zero_pt.size(),
                                       aad.data(), aad.size());
        v.verify_iv         = std::move(verify_ct.iv);
        v.verify_tag        = std::move(verify_ct.tag);
        v.verify_ciphertext = std::move(verify_ct.ciphertext);

        // 6. Re-encrypt each entry password under the new entry key + new AAD.
        for (size_t i = 0; i < v.entries.size(); ++i) {
            SecureBuffer entry_key = derive_entry_key(v.vault_key, v.entries[i].id);
            auto pw_bytes = serialize_password(plaintexts[i]);
            auto ct = aead_encrypt(entry_key,
                                   pw_bytes.data(), pw_bytes.size(),
                                   aad.data(), aad.size());
            v.entry_passwords[i].iv         = std::move(ct.iv);
            v.entry_passwords[i].tag        = std::move(ct.tag);
            v.entry_passwords[i].ciphertext = std::move(ct.ciphertext);
        }

        // 7. Persist atomically (save_vault increments save_counter: 0 → 1).
        save_vault(v);

    } catch (...) {
        // Lock on any failure to prevent operating on a partially-updated vault.
        vault_.reset();
        state_ = SessionState::LOCKED;
        throw;
    }

    state_ = SessionState::BROWSING;
    last_activity_ = std::chrono::steady_clock::now();
}

// ── Accessors ─────────────────────────────────────────────────────────────────

SessionState Session::state() const {
    std::lock_guard<std::mutex> guard(mutex_);
    return state_;
}

const Vault& Session::vault() const {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!vault_ || state_ == SessionState::LOCKED)
        throw std::logic_error("No vault loaded (session is LOCKED)");
    return *vault_;
}

Vault& Session::vault_mut() {
    std::lock_guard<std::mutex> guard(mutex_);
    if (!vault_ || state_ == SessionState::LOCKED)
        throw std::logic_error("No vault loaded (session is LOCKED)");
    return *vault_;
}

unsigned int Session::auto_lock_secs() const noexcept {
    return auto_lock_secs_;
}

void Session::set_auto_lock_secs(unsigned int secs) {
    std::lock_guard<std::mutex> guard(mutex_);
    auto_lock_secs_ = secs;
}

void Session::touch() {
    std::lock_guard<std::mutex> guard(mutex_);
    last_activity_ = std::chrono::steady_clock::now();
}

// ── Timer ─────────────────────────────────────────────────────────────────────

void Session::start_timer() {
    // Precondition: caller holds mutex_.
    // timer_running_ is atomic so we can read it here safely.
    if (timer_running_.load()) return;  // Already running.

    // Join any previously-finished thread before creating a new one.
    if (timer_thread_.joinable())
        timer_thread_.join();

    timer_running_.store(true);
    timer_thread_ = std::thread(&Session::timer_loop, this);
}

void Session::stop_timer() {
    // Must be called WITHOUT holding mutex_ to avoid deadlock with timer_loop.
    timer_running_.store(false);
    if (timer_thread_.joinable())
        timer_thread_.join();
}

void Session::timer_loop() {
    while (timer_running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        if (!timer_running_.load()) break;

        std::lock_guard<std::mutex> guard(mutex_);

        // Only auto-lock in active states.
        if (state_ != SessionState::BROWSING &&
            state_ != SessionState::RETRIEVING)
            continue;

        auto now     = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                           now - last_activity_).count();

        if (static_cast<unsigned int>(elapsed) >= auto_lock_secs_) {
            vault_.reset();
            state_ = SessionState::LOCKED;
            timer_running_.store(false);  // Signal self to stop.
        }
    }
}
