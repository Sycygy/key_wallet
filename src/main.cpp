#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/crypto.h>   // CRYPTO_secure_malloc_init
#include <sys/prctl.h>        // prctl, PR_SET_DUMPABLE
#include <sys/resource.h>     // setrlimit, RLIMIT_CORE

#include "cli/commands.hpp"
#include "cli/input.hpp"
#include "core/session.hpp"
#include "crypto/random/random.hpp"  // Charset flags for generate

// ── Vault path resolution ─────────────────────────────────────────────────────

static std::string default_vault_path() {
    const char* env = std::getenv("KEY_WALLET_VAULT");
    if (env && env[0] != '\0') return env;
    const char* home = std::getenv("HOME");
    if (home) return std::string(home) + "/.key_wallet.vault";
    return ".key_wallet.vault";
}

// ── Usage ─────────────────────────────────────────────────────────────────────

static void print_usage(const char* prog) {
    std::cout
        << "key_wallet — secure local password manager\n\n"
        << "Usage: " << prog << " [--vault <path>] <command> [args...]\n\n"
        << "Commands:\n"
        << "  init                          Create a new vault\n"
        << "  list                          List all entries\n"
        << "  search <query>                Search entries by name or website\n"
        << "  get <name>                    Copy password to clipboard\n"
        << "  add                           Add a new entry\n"
        << "  update <name>                 Update an existing entry\n"
        << "  delete <name>                 Delete an entry\n"
        << "  generate [length]             Generate a random password (default: 20)\n"
        << "    --no-symbols                Exclude symbols\n"
        << "    --no-uppercase              Exclude uppercase letters\n"
        << "    --no-lowercase              Exclude lowercase letters\n"
        << "    --digits-only               Digits only\n"
        << "  change-master                 Change the master password\n"
        << "  config --expiry-days <N>      Set master password expiry (0 = disable)\n"
        << "  config --show                 Show expiry settings\n\n"
        << "Options:\n"
        << "  --vault <path>                Vault file (default: ~/.key_wallet.vault)\n"
        << "                                or set KEY_WALLET_VAULT env var\n";
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    // 1. Process hardening — must happen before any secrets are loaded.
    //
    // The secure heap must be large enough for Argon2id's working memory
    // (m_cost=65536 KiB = 64 MiB) plus overhead for SecureBuffer allocations.
    // On systems where mlock(2) cannot satisfy this request (typical for
    // unprivileged users with RLIMIT_MEMLOCK=64KiB), OpenSSL returns false and
    // all allocations fall back to regular malloc — SecureBuffer still calls
    // OPENSSL_cleanse() on destruction, and prctl/setrlimit remain effective.
    // On systems with raised mlock limits (e.g. root or capability), the full
    // secure heap is available for both Argon2id and SecureBuffer.
    static constexpr size_t SECURE_HEAP_SIZE = 128UL * 1024 * 1024;  // 128 MiB (must be power-of-2)
    CRYPTO_secure_malloc_init(SECURE_HEAP_SIZE, 32);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);

    // 2. Parse global options.
    std::vector<std::string> args(argv + 1, argv + argc);
    std::string vault_path = default_vault_path();

    size_t i = 0;
    while (i < args.size() && args[i].starts_with("--")) {
        if (args[i] == "--vault" && i + 1 < args.size()) {
            vault_path = args[++i];
        } else if (args[i] == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "error: Unknown option '" << args[i] << "'.\n";
            return 1;
        }
        ++i;
    }

    if (i >= args.size()) {
        print_usage(argv[0]);
        return 1;
    }

    const std::string command = args[i++];

    // 3. Commands that do NOT require an unlocked vault.

    if (command == "init") {
        // Optional positional vault path override.
        if (i < args.size()) vault_path = args[i];
        return cmd::run_init(vault_path);
    }

    if (command == "generate") {
        int length = 20;
        uint8_t flags = Charset::All;
        if (i < args.size() && !args[i].starts_with("--")) {
            try {
                length = std::stoi(args[i++]);
            } catch (...) {
                std::cerr << "error: Invalid length '" << args[i - 1] << "'.\n";
                return 1;
            }
        }
        while (i < args.size()) {
            if      (args[i] == "--no-symbols")   flags &= ~Charset::Symbols;
            else if (args[i] == "--no-uppercase")  flags &= ~Charset::Uppercase;
            else if (args[i] == "--no-lowercase")  flags &= ~Charset::Lowercase;
            else if (args[i] == "--digits-only")   flags  =  Charset::Digits;
            else {
                std::cerr << "error: Unknown option for generate: '" << args[i] << "'.\n";
                return 1;
            }
            ++i;
        }
        return cmd::run_generate(length, flags);
    }

    // 4. All remaining commands require an unlocked session.

    // Prompt for master password and unlock.
    SecureBuffer master_pw = cli::read_password("Master password: ");

    Session session;
    try {
        session.unlock(vault_path, master_pw);
    } catch (const std::exception& e) {
        std::string msg = e.what();
        if (msg.find("Cannot open vault file") != std::string::npos) {
            std::cerr << "error: Vault not found at '" << vault_path << "'.\n"
                      << "       Run '" << argv[0] << " init' to create a new vault.\n";
        } else if (msg == "Authentication failed" ||
                   msg.find("authentication failed") != std::string::npos) {
            std::cerr << "error: Authentication failed.\n";
        } else if (msg.find("v0.1") != std::string::npos ||
                   msg.find("must be migrated") != std::string::npos) {
            std::cerr << "error: " << msg << "\n";
        } else if (msg.find("bad magic") != std::string::npos ||
                   msg.find("too small") != std::string::npos ||
                   msg.find("Unsupported vault format") != std::string::npos) {
            std::cerr << "error: Vault file is corrupt or not a valid vault.\n";
        } else if (msg.find("Truncated") != std::string::npos) {
            std::cerr << "error: Vault file appears to be damaged or truncated.\n";
        } else {
            // Generic fallback — never expose internal crypto/OpenSSL details.
            std::cerr << "error: Failed to open vault. The file may be corrupt.\n";
        }
        return 1;
    }

    // 5. Enforce state restrictions before dispatch.
    if (session.state() == SessionState::EXPIRED && command != "change-master") {
        std::cerr << "error: Only 'change-master' is allowed when the master "
                     "password has expired.\n";
        return 1;
    }

    // 6. Dispatch.
    if (command == "list") {
        return cmd::run_list(session);

    } else if (command == "search") {
        if (i >= args.size()) {
            std::cerr << "error: 'search' requires a query argument.\n";
            return 1;
        }
        return cmd::run_search(session, args[i]);

    } else if (command == "get") {
        if (i >= args.size()) {
            std::cerr << "error: 'get' requires a name argument.\n";
            return 1;
        }
        return cmd::run_get(session, args[i]);

    } else if (command == "add") {
        return cmd::run_add(session);

    } else if (command == "update") {
        if (i >= args.size()) {
            std::cerr << "error: 'update' requires a name argument.\n";
            return 1;
        }
        return cmd::run_update(session, args[i]);

    } else if (command == "delete") {
        if (i >= args.size()) {
            std::cerr << "error: 'delete' requires a name argument.\n";
            return 1;
        }
        return cmd::run_delete(session, args[i]);

    } else if (command == "change-master") {
        return cmd::run_change_master(session);

    } else if (command == "config") {
        if (i >= args.size()) {
            std::cerr << "error: 'config' requires --expiry-days <N> or --show.\n";
            return 1;
        }
        if (args[i] == "--show") {
            return cmd::run_config_show(session);
        } else if (args[i] == "--expiry-days") {
            if (i + 1 >= args.size()) {
                std::cerr << "error: --expiry-days requires a value.\n";
                return 1;
            }
            uint32_t days = 0;
            try {
                int d = std::stoi(args[i + 1]);
                if (d < 0) throw std::out_of_range("negative");
                days = static_cast<uint32_t>(d);
            } catch (...) {
                std::cerr << "error: Invalid value for --expiry-days: '"
                          << args[i + 1] << "'.\n";
                return 1;
            }
            return cmd::run_config_expiry(session, days);
        } else {
            std::cerr << "error: Unknown config option '" << args[i] << "'.\n"
                      << "       Use --expiry-days <N> or --show.\n";
            return 1;
        }

    } else {
        std::cerr << "error: Unknown command '" << command << "'.\n\n";
        print_usage(argv[0]);
        return 1;
    }
}
