#include "cli/input.hpp"

#include <array>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>

#include <termios.h>
#include <unistd.h>

#include <openssl/crypto.h>  // OPENSSL_cleanse

namespace cli {

// ── Terminal state ─────────────────────────────────────────────────────────────

static struct termios g_saved_termios;
static volatile bool  g_termios_active = false;

static void restore_terminal() noexcept {
    if (g_termios_active && isatty(STDIN_FILENO)) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
        g_termios_active = false;
    }
}

static void signal_handler(int sig) {
    restore_terminal();
    std::signal(sig, SIG_DFL);
    std::raise(sig);
}

// ── read_password ──────────────────────────────────────────────────────────────

SecureBuffer read_password(const std::string& prompt) {
    std::cerr << prompt << std::flush;

    const bool is_tty = isatty(STDIN_FILENO);
    if (is_tty) {
        tcgetattr(STDIN_FILENO, &g_saved_termios);
        g_termios_active = true;

        std::signal(SIGINT,  signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Disable echo; keep canonical mode so the kernel handles line buffering.
        // We re-enable echo below after reading the line.
        struct termios raw = g_saved_termios;
        raw.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &raw);
    }

    // Read a line.  std::getline goes to the regular heap, but we minimise
    // exposure by immediately copying into a SecureBuffer and cleansing.
    std::string line;
    line.reserve(128);
    std::getline(std::cin, line);

    if (is_tty) {
        restore_terminal();
        std::cerr << '\n';  // visual newline — echo was off
    }

    SecureBuffer buf(line.size());
    if (!line.empty()) {
        std::memcpy(buf.data(), line.data(), line.size());
        OPENSSL_cleanse(line.data(), line.size());
        line.clear();
    }

    return buf;
}

// ── write_clipboard ────────────────────────────────────────────────────────────

bool write_clipboard(std::string_view text) {
#if defined(__APPLE__)
    // Redirect stderr to suppress "not found" noise from the shell.
    FILE* pipe = popen("pbcopy 2>/dev/null", "w");
    if (!pipe) return false;
    fwrite(text.data(), 1, text.size(), pipe);
    return pclose(pipe) == 0;
#else
    // Candidates in preference order.
    // stderr is redirected in each command to suppress "not found" shell noise.
    // clip.exe covers WSL (writes to the Windows clipboard).
    const std::array<const char*, 4> candidates = {
        "xclip -selection clipboard 2>/dev/null",
        "xsel --clipboard --input 2>/dev/null",
        "wl-copy 2>/dev/null",
        "/mnt/c/Windows/System32/clip.exe 2>/dev/null",
    };
    for (const char* cmd : candidates) {
        FILE* pipe = popen(cmd, "w");
        if (!pipe) continue;
        fwrite(text.data(), 1, text.size(), pipe);
        if (pclose(pipe) == 0) return true;
    }
    return false;
#endif
}

// ── schedule_clipboard_clear ───────────────────────────────────────────────────

void schedule_clipboard_clear(unsigned int timeout_sec) {
    std::thread([timeout_sec]() {
        std::this_thread::sleep_for(std::chrono::seconds(timeout_sec));
        write_clipboard("");
    }).detach();
}

} // namespace cli
