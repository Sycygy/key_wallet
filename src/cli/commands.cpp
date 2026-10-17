#include "cli/commands.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "cli/input.hpp"
#include "core/session.hpp"
#include "crypto/random/random.hpp"
#include "storage/entry.hpp"
#include "storage/vault.hpp"

// ── Error sanitization ────────────────────────────────────────────────────────
// Translate internal/crypto exception messages into user-friendly text.
// Phase 3.4: no stack traces, internal paths, or crypto details in output.

static std::string sanitize_error(const std::string& msg) {
    // Already user-friendly messages — pass through.
    if (msg == "Authentication failed")
        return msg;
    if (msg == "Entry not found")
        return msg;

    // Vault corruption / truncation
    if (msg.find("Truncated") != std::string::npos ||
        msg.find("corrupt") != std::string::npos ||
        msg.find("bad magic") != std::string::npos)
        return "Vault file appears to be damaged or corrupt.";

    // AEAD / tag verification failure (internal form of auth failure)
    if (msg.find("authentication failed") != std::string::npos ||
        msg.find("tag") != std::string::npos)
        return "Authentication failed";

    // OpenSSL / EVP internals
    if (msg.find("EVP_") != std::string::npos ||
        msg.find("RAND_") != std::string::npos ||
        msg.find("OpenSSL") != std::string::npos ||
        msg.find("aead_") != std::string::npos ||
        msg.find("derive_") != std::string::npos ||
        msg.find("HKDF") != std::string::npos)
        return "A cryptographic operation failed.";

    // File I/O errors — keep path info but strip internals
    if (msg.find("Cannot") != std::string::npos ||
        msg.find("Failed to") != std::string::npos)
        return "Failed to save vault.";

    // Vault locked (programming error, but handle gracefully)
    if (msg.find("vault is locked") != std::string::npos ||
        msg.find("Vault not loaded") != std::string::npos ||
        msg.find("No vault loaded") != std::string::npos)
        return "Session has expired. Please restart and unlock again.";

    // Fallback — generic message, never leak the raw internal text.
    return "An unexpected error occurred.";
}

// ── Internal helpers ──────────────────────────────────────────────────────────

static uint64_t cmd_now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

static std::string format_timestamp(uint64_t ts) {
    if (ts == 0) return "none";
    std::time_t t = static_cast<std::time_t>(ts);
    std::tm tm_val{};
    gmtime_r(&t, &tm_val);
    std::ostringstream ss;
    ss << std::put_time(&tm_val, "%Y-%m-%d");
    return ss.str();
}

/// Find a BrowsableEntry by name: exact match first, then case-insensitive.
/// Returns nullptr if not found, or the first match.
static const BrowsableEntry* find_entry_by_name(const Vault& vault,
                                                  const std::string& name) {
    // Exact match
    for (const auto& e : vault.entries) {
        if (e.name == name) return &e;
    }
    // Case-insensitive match
    auto lower = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    };
    std::string lname = lower(name);
    for (const auto& e : vault.entries) {
        if (lower(e.name) == lname) return &e;
    }
    return nullptr;
}

static void print_entry(const BrowsableEntry& e, uint64_t now) {
    bool pw_expired = (e.expires_at != 0 && e.expires_at <= now);
    std::cout << e.name;
    if (pw_expired) std::cout << "  [EXPIRED]";
    std::cout << "\n";
    if (!e.website.empty())  std::cout << "  website:  " << e.website  << "\n";
    if (!e.username.empty()) std::cout << "  username: " << e.username << "\n";
    if (e.expires_at != 0)
        std::cout << "  expires:  " << format_timestamp(e.expires_at) << "\n";
    std::cout << "\n";
}

// ── cmd::run_init ─────────────────────────────────────────────────────────────

int cmd::run_init(const std::string& vault_path) {
    // Warn if vault already exists
    {
        std::ifstream test(vault_path);
        if (test.good()) {
            std::cout << "Vault already exists at '" << vault_path << "'.\n"
                      << "Overwrite? [y/N]: " << std::flush;
            std::string answer;
            std::getline(std::cin, answer);
            if (answer != "y" && answer != "Y") {
                std::cout << "Aborted.\n";
                return 1;
            }
        }
    }

    SecureBuffer pw  = cli::read_password("New master password: ");
    SecureBuffer pw2 = cli::read_password("Confirm master password: ");

    if (pw.empty()) {
        std::cerr << "error: Master password must not be empty.\n";
        return 1;
    }
    if (pw.size() != pw2.size() ||
        std::memcmp(pw.data(), pw2.data(), pw.size()) != 0) {
        std::cerr << "error: Passwords do not match.\n";
        return 1;
    }

    try {
        create_vault(vault_path, pw.data(), pw.size());
        std::cout << "Vault created at '" << vault_path << "'.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << sanitize_error(e.what()) << "\n";
        return 1;
    }
}

// ── cmd::run_list ─────────────────────────────────────────────────────────────

int cmd::run_list(Session& session) {
    if (session.state() != SessionState::BROWSING) {
        std::cerr << "error: 'list' requires an active (unlocked) session.\n";
        return 1;
    }

    const auto& entries = session.vault().entries;
    if (entries.empty()) {
        std::cout << "No entries.\n";
        session.touch();
        return 0;
    }

    uint64_t now = cmd_now_unix();
    std::cout << entries.size() << " entr" << (entries.size() == 1 ? "y" : "ies") << ":\n\n";
    for (const auto& e : entries) {
        print_entry(e, now);
    }

    session.touch();
    return 0;
}

// ── cmd::run_search ───────────────────────────────────────────────────────────

int cmd::run_search(Session& session, const std::string& query) {
    if (session.state() != SessionState::BROWSING) {
        std::cerr << "error: 'search' requires an active (unlocked) session.\n";
        return 1;
    }

    auto matches = vault_find_entries(session.vault(), query);
    if (matches.empty()) {
        std::cout << "No entries matching '" << query << "'.\n";
        session.touch();
        return 0;
    }

    uint64_t now = cmd_now_unix();
    std::cout << matches.size() << " match" << (matches.size() == 1 ? "" : "es") << ":\n\n";
    for (const auto& e : matches) {
        print_entry(e, now);
    }

    session.touch();
    return 0;
}

// ── cmd::run_get ──────────────────────────────────────────────────────────────

int cmd::run_get(Session& session, const std::string& name) {
    if (session.state() != SessionState::BROWSING) {
        std::cerr << "error: 'get' requires an active (unlocked) session.\n";
        return 1;
    }

    const BrowsableEntry* be = find_entry_by_name(session.vault(), name);
    if (!be) {
        std::cerr << "error: No entry named '" << name << "'.\n";
        return 1;
    }

    auto id         = be->id;
    uint64_t exp_at = be->expires_at;

    SecureBuffer master_pw = cli::read_password("Master password: ");

    try {
        PasswordEntry pe = session.retrieve(id, master_pw);
        session.touch();

        // Warn if the entry password itself is expired
        if (exp_at != 0 && exp_at <= cmd_now_unix()) {
            std::cerr << "warning: This password has expired. "
                         "Consider running 'update " << name << "'.\n";
        }

        std::string_view pw_view(
            reinterpret_cast<const char*>(pe.password.data()),
            pe.password.size());

        if (cli::write_clipboard(pw_view)) {
            std::cout << "Password for '" << be->name << "' copied to clipboard. "
                         "Will clear in 30 seconds.\n";
            cli::schedule_clipboard_clear(30);
        } else {
            std::cerr << "warning: No clipboard tool found. "
                         "Password NOT copied.\n";
        }
        return 0;
    } catch (const std::runtime_error& e) {
        std::cerr << "error: " << sanitize_error(e.what()) << "\n";
        return 1;
    }
}

// ── cmd::run_add ──────────────────────────────────────────────────────────────

int cmd::run_add(Session& session) {
    if (session.state() != SessionState::BROWSING) {
        std::cerr << "error: 'add' requires an active (unlocked) session.\n";
        return 1;
    }

    // ── Collect metadata ──
    std::string name, website, username;

    std::cout << "Name: " << std::flush;
    std::getline(std::cin, name);
    if (name.empty()) {
        std::cerr << "error: Name is required.\n";
        return 1;
    }

    std::cout << "Website (optional): " << std::flush;
    std::getline(std::cin, website);

    std::cout << "Username: " << std::flush;
    std::getline(std::cin, username);

    // ── Password ──
    SecureBuffer password;

    std::cout << "Generate password? [Y/n]: " << std::flush;
    std::string gen_choice;
    std::getline(std::cin, gen_choice);
    if (gen_choice.empty() || gen_choice == "y" || gen_choice == "Y") {
        secure_string generated = generate_password(20, Charset::All);
        password = SecureBuffer(generated.size());
        std::memcpy(password.data(), generated.data(), generated.size());
        std::cout << "Password generated (20 chars, all charsets).\n";
    } else {
        password = cli::read_password("Password: ");
        SecureBuffer pw2 = cli::read_password("Confirm password: ");
        if (password.size() != pw2.size() ||
            std::memcmp(password.data(), pw2.data(), password.size()) != 0) {
            std::cerr << "error: Passwords do not match.\n";
            return 1;
        }
    }

    // ── Entry expiry ──
    uint64_t expires_at = 0;
    std::cout << "Password expiry in days (0 = none): " << std::flush;
    std::string exp_str;
    std::getline(std::cin, exp_str);
    if (!exp_str.empty()) {
        try {
            int days = std::stoi(exp_str);
            if (days > 0)
                expires_at = cmd_now_unix() + static_cast<uint64_t>(days) * 86400;
        } catch (...) {
            std::cerr << "warning: Invalid expiry value — using none.\n";
        }
    }

    // ── Re-authenticate ──
    SecureBuffer master_pw = cli::read_password("Master password: ");
    if (!session.verify_master_password(master_pw)) {
        std::cerr << "error: Authentication failed.\n";
        return 1;
    }

    try {
        session.touch();
        Vault& vault = session.vault_mut();
        vault_add_entry(vault, name, website, username, password, expires_at);
        save_vault(vault);
        std::cout << "Entry '" << name << "' added.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << sanitize_error(e.what()) << "\n";
        return 1;
    }
}

// ── cmd::run_update ───────────────────────────────────────────────────────────

int cmd::run_update(Session& session, const std::string& name) {
    if (session.state() != SessionState::BROWSING) {
        std::cerr << "error: 'update' requires an active (unlocked) session.\n";
        return 1;
    }

    const BrowsableEntry* be = find_entry_by_name(session.vault(), name);
    if (!be) {
        std::cerr << "error: No entry named '" << name << "'.\n";
        return 1;
    }

    auto id = be->id;

    // Keep a copy of current values as defaults
    std::string new_name     = be->name;
    std::string new_website  = be->website;
    std::string new_username = be->username;
    uint64_t    new_expires_at = be->expires_at;

    std::cout << "(Press Enter to keep current value)\n\n";

    // ── Metadata fields ──
    std::string input;

    std::cout << "Name [" << be->name << "]: " << std::flush;
    std::getline(std::cin, input);
    if (!input.empty()) new_name = input;

    std::cout << "Website [" << be->website << "]: " << std::flush;
    std::getline(std::cin, input);
    if (!input.empty()) new_website = input;

    std::cout << "Username [" << be->username << "]: " << std::flush;
    std::getline(std::cin, input);
    if (!input.empty()) new_username = input;

    // ── Password change ──
    SecureBuffer new_password;  // empty = keep existing

    std::cout << "Change password? [y/N]: " << std::flush;
    std::getline(std::cin, input);
    if (input == "y" || input == "Y") {
        std::cout << "Generate new password? [Y/n]: " << std::flush;
        std::getline(std::cin, input);
        if (input.empty() || input == "y" || input == "Y") {
            secure_string generated = generate_password(20, Charset::All);
            new_password = SecureBuffer(generated.size());
            std::memcpy(new_password.data(), generated.data(), generated.size());
            std::cout << "Password generated (20 chars, all charsets).\n";
        } else {
            new_password = cli::read_password("New password: ");
            SecureBuffer pw2 = cli::read_password("Confirm new password: ");
            if (new_password.size() != pw2.size() ||
                std::memcmp(new_password.data(), pw2.data(), new_password.size()) != 0) {
                std::cerr << "error: Passwords do not match.\n";
                return 1;
            }
        }
    }

    // ── Expiry ──
    std::string current_exp;
    if (be->expires_at == 0) {
        current_exp = "none";
    } else {
        int64_t days_left = (static_cast<int64_t>(be->expires_at) -
                             static_cast<int64_t>(cmd_now_unix())) / 86400;
        current_exp = format_timestamp(be->expires_at) +
                      (days_left >= 0
                           ? " (" + std::to_string(days_left) + " days left)"
                           : " (expired)");
    }
    std::cout << "New expiry in days from now (0 = disable) [current: "
              << current_exp << "]: " << std::flush;
    std::getline(std::cin, input);
    if (!input.empty()) {
        try {
            int days = std::stoi(input);
            new_expires_at = (days > 0)
                ? cmd_now_unix() + static_cast<uint64_t>(days) * 86400
                : 0;
        } catch (...) {
            std::cerr << "warning: Invalid expiry value — keeping current.\n";
        }
    }

    // ── Re-authenticate ──
    SecureBuffer master_pw = cli::read_password("Master password: ");
    if (!session.verify_master_password(master_pw)) {
        std::cerr << "error: Authentication failed.\n";
        return 1;
    }

    try {
        session.touch();
        Vault& vault = session.vault_mut();
        vault_update_entry(vault, id, new_name, new_website, new_username,
                           new_password, new_expires_at);
        save_vault(vault);
        std::cout << "Entry '" << new_name << "' updated.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << sanitize_error(e.what()) << "\n";
        return 1;
    }
}

// ── cmd::run_delete ───────────────────────────────────────────────────────────

int cmd::run_delete(Session& session, const std::string& name) {
    if (session.state() != SessionState::BROWSING) {
        std::cerr << "error: 'delete' requires an active (unlocked) session.\n";
        return 1;
    }

    const BrowsableEntry* be = find_entry_by_name(session.vault(), name);
    if (!be) {
        std::cerr << "error: No entry named '" << name << "'.\n";
        return 1;
    }

    auto id = be->id;

    // Confirm
    std::cout << "Delete '" << be->name << "'";
    if (!be->website.empty() || !be->username.empty()) {
        std::cout << " (" << be->username;
        if (!be->website.empty()) std::cout << " @ " << be->website;
        std::cout << ")";
    }
    std::cout << "? [y/N]: " << std::flush;
    std::string answer;
    std::getline(std::cin, answer);
    if (answer != "y" && answer != "Y") {
        std::cout << "Aborted.\n";
        return 0;
    }

    // Re-authenticate
    SecureBuffer master_pw = cli::read_password("Master password: ");
    if (!session.verify_master_password(master_pw)) {
        std::cerr << "error: Authentication failed.\n";
        return 1;
    }

    try {
        session.touch();
        Vault& vault = session.vault_mut();
        vault_delete_entry(vault, id);
        save_vault(vault);
        std::cout << "Entry '" << name << "' deleted.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << sanitize_error(e.what()) << "\n";
        return 1;
    }
}

// ── cmd::run_generate ─────────────────────────────────────────────────────────

int cmd::run_generate(int length, uint8_t charset_flags) {
    if (length <= 0) {
        std::cerr << "error: Length must be a positive integer.\n";
        return 1;
    }
    if (charset_flags == 0) {
        std::cerr << "error: At least one character set must be selected.\n";
        return 1;
    }

    try {
        secure_string pw = generate_password(static_cast<size_t>(length),
                                             charset_flags);
        std::cout << std::string_view(pw.data(), pw.size()) << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << sanitize_error(e.what()) << "\n";
        return 1;
    }
}

// ── cmd::run_change_master ────────────────────────────────────────────────────

int cmd::run_change_master(Session& session) {
    SessionState st = session.state();
    if (st != SessionState::BROWSING && st != SessionState::EXPIRED) {
        std::cerr << "error: 'change-master' requires an active session.\n";
        return 1;
    }

    SecureBuffer old_pw  = cli::read_password("Current master password: ");
    SecureBuffer new_pw  = cli::read_password("New master password: ");
    SecureBuffer new_pw2 = cli::read_password("Confirm new master password: ");

    if (new_pw.empty()) {
        std::cerr << "error: New master password must not be empty.\n";
        return 1;
    }
    if (new_pw.size() != new_pw2.size() ||
        std::memcmp(new_pw.data(), new_pw2.data(), new_pw.size()) != 0) {
        std::cerr << "error: New passwords do not match.\n";
        return 1;
    }

    try {
        session.change_master(old_pw, new_pw);
        session.touch();
        std::cout << "Master password changed successfully.\n";
        return 0;
    } catch (const std::runtime_error& e) {
        std::cerr << "error: " << sanitize_error(e.what()) << "\n";
        return 1;
    }
}

// ── cmd::run_config_expiry ────────────────────────────────────────────────────

int cmd::run_config_expiry(Session& session, uint32_t days) {
    if (session.state() != SessionState::BROWSING) {
        std::cerr << "error: 'config' requires an active (unlocked) session.\n";
        return 1;
    }

    SecureBuffer master_pw = cli::read_password("Master password: ");
    if (!session.verify_master_password(master_pw)) {
        std::cerr << "error: Authentication failed.\n";
        return 1;
    }

    try {
        session.touch();
        Vault& vault = session.vault_mut();
        vault.master_password_expiry_days = days;
        save_vault(vault);
        if (days == 0)
            std::cout << "Master password expiry disabled.\n";
        else
            std::cout << "Master password expiry set to " << days << " days.\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "error: " << sanitize_error(e.what()) << "\n";
        return 1;
    }
}

// ── cmd::run_config_show ──────────────────────────────────────────────────────

int cmd::run_config_show(Session& session) {
    if (session.state() != SessionState::BROWSING) {
        std::cerr << "error: 'config --show' requires an active (unlocked) session.\n";
        return 1;
    }

    const Vault& vault = session.vault();
    uint32_t expiry_days = vault.master_password_expiry_days;

    if (expiry_days == 0) {
        std::cout << "Master password expiry: disabled\n";
    } else {
        std::cout << "Master password expiry: " << expiry_days << " days\n";
        int64_t days_left = days_until_expiry(vault);
        if (days_left == INT64_MAX) {
            std::cout << "Days remaining:        unlimited\n";
        } else if (days_left < 0) {
            std::cout << "Status:                EXPIRED ("
                      << (-days_left) << " day(s) ago)\n";
        } else {
            std::cout << "Days remaining:        " << days_left << "\n";
        }
    }

    session.touch();
    return 0;
}
