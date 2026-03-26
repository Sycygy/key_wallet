#include "storage/entry.hpp"

#include <cstring>
#include <stdexcept>

// ── Little-endian helpers ───────────────────────────────────────────────────

static void write_u16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

static void write_u64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i)
        buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}

static uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) |
           (static_cast<uint16_t>(p[1]) << 8);
}

static uint64_t read_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i)
        v |= static_cast<uint64_t>(p[i]) << (i * 8);
    return v;
}

static void write_string(std::vector<uint8_t>& buf, const std::string& s) {
    if (s.size() > ENTRY_MAX_STRING_LEN)
        throw std::invalid_argument("String field exceeds maximum length");
    write_u16(buf, static_cast<uint16_t>(s.size()));
    buf.insert(buf.end(), s.begin(), s.end());
}

/// Read a length-prefixed string from data, advancing offset.
/// Throws on truncated or oversized input.
static std::string read_string(const uint8_t* data, size_t len, size_t& offset) {
    if (offset + 2 > len)
        throw std::runtime_error("Truncated entry: missing string length");
    uint16_t slen = read_u16(data + offset);
    offset += 2;
    if (slen > ENTRY_MAX_STRING_LEN)
        throw std::runtime_error("Entry string field exceeds maximum allowed length");
    if (offset + slen > len)
        throw std::runtime_error("Truncated entry: string data extends beyond buffer");
    std::string result(reinterpret_cast<const char*>(data + offset), slen);
    offset += slen;
    return result;
}

// ── Index serialization (shared logic) ──────────────────────────────────────

static std::vector<uint8_t> serialize_index_impl(
    const std::array<uint8_t, 16>& id,
    const std::string& name,
    const std::string& website,
    const std::string& username,
    uint64_t created_at,
    uint64_t updated_at,
    uint64_t expires_at)
{
    std::vector<uint8_t> buf;
    // Pre-reserve a reasonable estimate
    buf.reserve(16 + 6 + name.size() + website.size() + username.size() + 24);

    // UUID (16 bytes)
    buf.insert(buf.end(), id.begin(), id.end());

    // Length-prefixed strings
    write_string(buf, name);
    write_string(buf, website);
    write_string(buf, username);

    // Timestamps
    write_u64(buf, created_at);
    write_u64(buf, updated_at);
    write_u64(buf, expires_at);

    return buf;
}

// ── Public API ──────────────────────────────────────────────────────────────

std::vector<uint8_t> serialize_index(const BrowsableEntry& entry) {
    return serialize_index_impl(
        entry.id, entry.name, entry.website, entry.username,
        entry.created_at, entry.updated_at, entry.expires_at);
}

std::vector<uint8_t> serialize_index(const PasswordEntry& entry) {
    return serialize_index_impl(
        entry.id, entry.name, entry.website, entry.username,
        entry.created_at, entry.updated_at, entry.expires_at);
}

SecureBuffer serialize_password(const SecureBuffer& password) {
    if (password.size() > ENTRY_MAX_STRING_LEN)
        throw std::invalid_argument("Password exceeds maximum length");

    const uint16_t plen = static_cast<uint16_t>(password.size());
    SecureBuffer buf(2 + password.size());
    buf.data()[0] = static_cast<unsigned char>(plen & 0xFF);
    buf.data()[1] = static_cast<unsigned char>((plen >> 8) & 0xFF);
    if (password.size() > 0)
        std::memcpy(buf.data() + 2, password.data(), password.size());
    return buf;
}

BrowsableEntry deserialize_index(const uint8_t* data, size_t len, size_t& bytes_read) {
    if (!data)
        throw std::runtime_error("Null data pointer in deserialize_index");

    size_t offset = 0;

    // UUID (16 bytes)
    if (offset + 16 > len)
        throw std::runtime_error("Truncated entry: missing UUID");
    BrowsableEntry entry;
    std::memcpy(entry.id.data(), data + offset, 16);
    offset += 16;

    // Length-prefixed strings
    entry.name     = read_string(data, len, offset);
    entry.website  = read_string(data, len, offset);
    entry.username = read_string(data, len, offset);

    // Timestamps (3 × 8 bytes)
    if (offset + 24 > len)
        throw std::runtime_error("Truncated entry: missing timestamps");
    entry.created_at = read_u64(data + offset); offset += 8;
    entry.updated_at = read_u64(data + offset); offset += 8;
    entry.expires_at = read_u64(data + offset); offset += 8;

    bytes_read = offset;
    return entry;
}

SecureBuffer deserialize_password(const uint8_t* data, size_t len, size_t& bytes_read) {
    if (!data)
        throw std::runtime_error("Null data pointer in deserialize_password");

    if (len < 2)
        throw std::runtime_error("Truncated password record: missing length");

    uint16_t plen = read_u16(data);
    if (plen > ENTRY_MAX_STRING_LEN)
        throw std::runtime_error("Password field exceeds maximum allowed length");
    if (2u + plen > len)
        throw std::runtime_error("Truncated password record: data extends beyond buffer");

    SecureBuffer password(plen);
    if (plen > 0)
        std::memcpy(password.data(), data + 2, plen);

    bytes_read = 2 + plen;
    return password;
}