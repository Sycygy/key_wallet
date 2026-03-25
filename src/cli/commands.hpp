#pragma once

#include <cstdint>
#include <string>

#include "core/session.hpp"

namespace cmd {

/// Create a new vault at vault_path, prompting for master password.
int run_init(const std::string& vault_path);

/// List all entries (name, website, username, expires_at — no passwords).
int run_list(Session& session);

/// Filter entries by name or website (case-insensitive substring match).
int run_search(Session& session, const std::string& query);

/// Re-authenticate and copy the named entry's password to clipboard.
int run_get(Session& session, const std::string& name);

/// Re-authenticate and interactively add a new entry.
int run_add(Session& session);

/// Re-authenticate and interactively update an existing entry by name.
int run_update(Session& session, const std::string& name);

/// Re-authenticate and delete an entry by name (with confirmation).
int run_delete(Session& session, const std::string& name);

/// Generate and print a random password without storing it.
int run_generate(int length, uint8_t charset_flags);

/// Re-authenticate and rotate the master password.
int run_change_master(Session& session);

/// Re-authenticate and set master password expiry interval (0 = disable).
int run_config_expiry(Session& session, uint32_t days);

/// Show current expiry settings and days remaining.
int run_config_show(Session& session);

} // namespace cmd
