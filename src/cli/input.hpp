#pragma once

#include <string>
#include <string_view>

#include "core/secure_buffer.hpp"

namespace cli {

/// Read a password from stdin with terminal echo disabled.
/// Restores terminal state cleanly on SIGINT / SIGTERM or unexpected exit.
///
/// @param prompt  Text displayed before the hidden input field.
/// @returns       Password bytes in a SecureBuffer (no trailing newline).
SecureBuffer read_password(const std::string& prompt);

/// Copy text to the system clipboard.
/// On Linux: tries xclip first, then xsel.
/// On macOS: uses pbcopy.
///
/// @param text  Data to place on the clipboard.
/// @returns     true on success, false if no clipboard tool is available.
bool write_clipboard(std::string_view text);

/// Spawn a background thread that overwrites the clipboard with an empty
/// string after timeout_sec seconds, then detaches.
/// Intended to be called immediately after write_clipboard().
///
/// @param timeout_sec  Seconds before clipboard is cleared (default: 30).
void schedule_clipboard_clear(unsigned int timeout_sec = 30);

} // namespace cli
