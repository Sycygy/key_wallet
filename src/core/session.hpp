#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

#include "core/secure_buffer.hpp"
#include "storage/entry.hpp"
#include "storage/vault.hpp"

/// Session states for the key_wallet state machine.
enum class SessionState {
    LOCKED,      ///< No vault in memory; all sensitive data zeroed.
    EXPIRED,     ///< Master password past its deadline; only change-master is allowed.
    BROWSING,    ///< Index decrypted, vault_key held; passwords NOT in RAM.
    RETRIEVING,  ///< Transient: one password decrypted; returns to BROWSING immediately.
};

/**
 * @brief State machine managing the vault session lifecycle.
 *
 * After unlock(), the vault index is in memory but passwords are not.
 * Each password access (retrieve()) requires re-authentication and transitions
 * through RETRIEVING before returning to BROWSING.
 *
 * An inactivity timer auto-locks the session after a configurable timeout
 * (default: 5 minutes). The timer fires only in BROWSING/RETRIEVING states.
 *
 * Thread-safe: all public methods serialise on an internal mutex. The timer
 * runs in a background thread and coordinates via an atomic flag.
 */
class Session {
public:
    static constexpr unsigned int DEFAULT_AUTO_LOCK_SECS = 300;  // 5 minutes

    Session();
    ~Session();

    Session(const Session&)            = delete;
    Session& operator=(const Session&) = delete;
    Session(Session&&)                 = delete;
    Session& operator=(Session&&)      = delete;

    /**
     * @brief Load vault from disk and transition to BROWSING (or EXPIRED).
     *
     * LOCKED → BROWSING or EXPIRED.
     * Prints a warning to stderr if the master password expires within 7 days.
     * Prints a hard-block message to stderr if the master password has expired.
     *
     * @param vault_path      Path to the vault file on disk.
     * @param master_password Master password bytes (SecureBuffer).
     * @throws std::logic_error   if not currently in LOCKED state.
     * @throws std::runtime_error on wrong password, tampered file, or I/O error.
     */
    void unlock(const std::string& vault_path, const SecureBuffer& master_password);

    /**
     * @brief Zero all sensitive data and return to LOCKED state.
     *
     * Any state → LOCKED. Safe to call in any state including LOCKED.
     */
    void lock();

    /**
     * @brief Re-verify the master password against the stored verification token.
     *
     * @param master_password Candidate password.
     * @return true if the password is correct.
     * @throws std::logic_error if not in BROWSING or EXPIRED state.
     */
    bool verify_master_password(const SecureBuffer& master_password);

    /**
     * @brief Decrypt one entry's password on demand.
     *
     * BROWSING → RETRIEVING (transient) → BROWSING.
     * Re-authenticates with master_password before decrypting.
     *
     * @param entry_id        UUID of the entry to retrieve.
     * @param master_password Master password for re-auth.
     * @return PasswordEntry with decrypted password (password zeroed on destruction).
     * @throws std::runtime_error if authentication fails or entry not found.
     * @throws std::logic_error   if not in BROWSING state.
     */
    PasswordEntry retrieve(const std::array<uint8_t, 16>& entry_id,
                           const SecureBuffer& master_password);

    /**
     * @brief Rotate the master password and re-encrypt all entries.
     *
     * Allowed from BROWSING (with old-password re-auth) or EXPIRED (only op).
     * Generates a new salt, re-derives the vault key, re-encrypts all entry
     * passwords under new entry keys, and saves the vault atomically.
     * On success: state → BROWSING, expiry clock reset to now.
     *
     * If an error occurs mid-rotation the session is locked to prevent
     * operating on a partially-updated in-memory vault.
     *
     * @param old_password Current master password.
     * @param new_password New master password.
     * @throws std::runtime_error if old password is wrong or crypto/I/O fails.
     * @throws std::logic_error   if not in BROWSING or EXPIRED state.
     */
    void change_master(const SecureBuffer& old_password,
                       const SecureBuffer& new_password);

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Current state. Thread-safe.
    SessionState state() const;

    /// Read-only vault access. Throws std::logic_error if LOCKED.
    const Vault& vault() const;

    /// Mutable vault access (CRUD operations). Throws std::logic_error if LOCKED.
    Vault& vault_mut();

    /// Configured auto-lock timeout in seconds.
    unsigned int auto_lock_secs() const noexcept;

    /// Update the auto-lock timeout. Takes effect on the next timer tick.
    void set_auto_lock_secs(unsigned int secs);

    /// Reset the inactivity timer. Call after any user-visible operation.
    void touch();

private:
    void start_timer();   ///< Start the background auto-lock timer thread.
    void stop_timer();    ///< Signal the timer to stop and join the thread.
    void timer_loop();    ///< Background thread: fires lock when inactive.

    mutable std::mutex                    mutex_;
    SessionState                          state_{SessionState::LOCKED};
    std::optional<Vault>                  vault_;

    // Auto-lock timer
    unsigned int                          auto_lock_secs_{DEFAULT_AUTO_LOCK_SECS};
    std::chrono::steady_clock::time_point last_activity_;
    std::thread                           timer_thread_;
    std::atomic<bool>                     timer_running_{false};
};
