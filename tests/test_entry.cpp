#include <gtest/gtest.h>
#include <openssl/crypto.h>

#include "storage/entry.hpp"
#include "crypto/random/random.hpp"

// ── Fixture: initialise secure heap once ────────────────────────────────────

class EntryTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        CRYPTO_secure_malloc_init(65536, 32);
    }
};

// ── Helper ──────────────────────────────────────────────────────────────────

static SecureBuffer make_password(const std::string& pw) {
    SecureBuffer buf(pw.size());
    std::memcpy(buf.data(), pw.data(), pw.size());
    return buf;
}

static PasswordEntry make_sample_entry() {
    PasswordEntry e;
    e.id         = generate_uuid();
    e.name       = "GitHub";
    e.website    = "https://github.com";
    e.username   = "testuser";
    e.password   = make_password("s3cur3P@ss!");
    e.created_at = 1700000000;
    e.updated_at = 1700001000;
    e.expires_at = 1702592000;
    return e;
}

static BrowsableEntry make_sample_browsable() {
    BrowsableEntry e;
    e.id         = generate_uuid();
    e.name       = "GitLab";
    e.website    = "https://gitlab.com";
    e.username   = "dev_user";
    e.created_at = 1700000000;
    e.updated_at = 1700001000;
    e.expires_at = 0; // no expiry
    return e;
}

// ═══════════════════════════════════════════════════════════════════════════
// Index serialization round-trip tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, BrowsableEntryRoundTrip) {
    BrowsableEntry original = make_sample_browsable();
    std::vector<uint8_t> data = serialize_index(original);

    size_t bytes_read = 0;
    BrowsableEntry restored = deserialize_index(data.data(), data.size(), bytes_read);

    EXPECT_EQ(bytes_read, data.size());
    EXPECT_EQ(restored.id, original.id);
    EXPECT_EQ(restored.name, original.name);
    EXPECT_EQ(restored.website, original.website);
    EXPECT_EQ(restored.username, original.username);
    EXPECT_EQ(restored.created_at, original.created_at);
    EXPECT_EQ(restored.updated_at, original.updated_at);
    EXPECT_EQ(restored.expires_at, original.expires_at);
}

TEST_F(EntryTest, PasswordEntryIndexRoundTrip) {
    PasswordEntry original = make_sample_entry();
    std::vector<uint8_t> data = serialize_index(original);

    size_t bytes_read = 0;
    BrowsableEntry restored = deserialize_index(data.data(), data.size(), bytes_read);

    EXPECT_EQ(bytes_read, data.size());
    EXPECT_EQ(restored.id, original.id);
    EXPECT_EQ(restored.name, original.name);
    EXPECT_EQ(restored.website, original.website);
    EXPECT_EQ(restored.username, original.username);
    EXPECT_EQ(restored.created_at, original.created_at);
    EXPECT_EQ(restored.updated_at, original.updated_at);
    EXPECT_EQ(restored.expires_at, original.expires_at);
}

// ═══════════════════════════════════════════════════════════════════════════
// Password serialization round-trip tests
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, PasswordRoundTrip) {
    SecureBuffer original = make_password("hunter2_ñ_日本語");
    std::vector<uint8_t> data = serialize_password(original);

    size_t bytes_read = 0;
    SecureBuffer restored = deserialize_password(data.data(), data.size(), bytes_read);

    EXPECT_EQ(bytes_read, data.size());
    ASSERT_EQ(restored.size(), original.size());
    EXPECT_EQ(std::memcmp(restored.data(), original.data(), original.size()), 0);
}

TEST_F(EntryTest, EmptyPasswordRoundTrip) {
    SecureBuffer original(0);
    std::vector<uint8_t> data = serialize_password(original);

    size_t bytes_read = 0;
    SecureBuffer restored = deserialize_password(data.data(), data.size(), bytes_read);

    EXPECT_EQ(bytes_read, 2u); // just the length prefix
    EXPECT_EQ(restored.size(), 0u);
}

// ═══════════════════════════════════════════════════════════════════════════
// Empty / edge-case string fields
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, EmptyStringFieldsRoundTrip) {
    BrowsableEntry original{};
    original.id = generate_uuid();
    // name, website, username all empty
    original.created_at = 0;
    original.updated_at = 0;
    original.expires_at = 0;

    std::vector<uint8_t> data = serialize_index(original);
    size_t bytes_read = 0;
    BrowsableEntry restored = deserialize_index(data.data(), data.size(), bytes_read);

    EXPECT_EQ(bytes_read, data.size());
    EXPECT_EQ(restored.id, original.id);
    EXPECT_EQ(restored.name, "");
    EXPECT_EQ(restored.website, "");
    EXPECT_EQ(restored.username, "");
}

// ═══════════════════════════════════════════════════════════════════════════
// Multiple entries serialized back-to-back
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, MultipleEntriesBackToBack) {
    BrowsableEntry e1 = make_sample_browsable();
    e1.name = "Entry1";
    BrowsableEntry e2 = make_sample_browsable();
    e2.name = "Entry2";

    std::vector<uint8_t> data1 = serialize_index(e1);
    std::vector<uint8_t> data2 = serialize_index(e2);

    // Concatenate
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), data1.begin(), data1.end());
    combined.insert(combined.end(), data2.begin(), data2.end());

    size_t bytes_read = 0;
    BrowsableEntry r1 = deserialize_index(combined.data(), combined.size(), bytes_read);
    EXPECT_EQ(r1.name, "Entry1");

    size_t bytes_read2 = 0;
    BrowsableEntry r2 = deserialize_index(combined.data() + bytes_read,
                                           combined.size() - bytes_read, bytes_read2);
    EXPECT_EQ(r2.name, "Entry2");
    EXPECT_EQ(bytes_read + bytes_read2, combined.size());
}

// ═══════════════════════════════════════════════════════════════════════════
// Malformed input — truncation
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, DeserializeIndexTruncatedUUID) {
    uint8_t data[10] = {};
    size_t bytes_read = 0;
    EXPECT_THROW(deserialize_index(data, 10, bytes_read), std::runtime_error);
}

TEST_F(EntryTest, DeserializeIndexTruncatedString) {
    // Valid UUID (16 bytes) + name_len = 100 but only a few bytes available
    BrowsableEntry e = make_sample_browsable();
    std::vector<uint8_t> data = serialize_index(e);
    // Truncate mid-way through the name
    size_t truncated_len = 16 + 2 + 1; // UUID + name_len + 1 byte of name
    size_t bytes_read = 0;
    EXPECT_THROW(deserialize_index(data.data(), truncated_len, bytes_read), std::runtime_error);
}

TEST_F(EntryTest, DeserializeIndexTruncatedTimestamps) {
    BrowsableEntry e = make_sample_browsable();
    std::vector<uint8_t> data = serialize_index(e);
    // Truncate in the timestamp area (remove last 4 bytes)
    size_t bytes_read = 0;
    EXPECT_THROW(deserialize_index(data.data(), data.size() - 4, bytes_read), std::runtime_error);
}

TEST_F(EntryTest, DeserializePasswordTruncatedLength) {
    uint8_t data[1] = {0};
    size_t bytes_read = 0;
    EXPECT_THROW(deserialize_password(data, 1, bytes_read), std::runtime_error);
}

TEST_F(EntryTest, DeserializePasswordTruncatedData) {
    // Length says 10 bytes but only 5 available
    uint8_t data[7] = {10, 0, 'a', 'b', 'c', 'd', 'e'};
    size_t bytes_read = 0;
    EXPECT_THROW(deserialize_password(data, 7, bytes_read), std::runtime_error);
}

// ═══════════════════════════════════════════════════════════════════════════
// Malformed input — null pointer
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, DeserializeIndexNullPointer) {
    size_t bytes_read = 0;
    EXPECT_THROW(deserialize_index(nullptr, 100, bytes_read), std::runtime_error);
}

TEST_F(EntryTest, DeserializePasswordNullPointer) {
    size_t bytes_read = 0;
    EXPECT_THROW(deserialize_password(nullptr, 100, bytes_read), std::runtime_error);
}

// ═══════════════════════════════════════════════════════════════════════════
// Malformed input — oversized string length
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, DeserializeIndexOversizedStringLength) {
    // Construct: valid UUID + name_len = 0xFFFF (65535 > ENTRY_MAX_STRING_LEN)
    std::vector<uint8_t> data(16 + 2, 0);
    data[16] = 0xFF;
    data[17] = 0xFF;
    size_t bytes_read = 0;
    EXPECT_THROW(deserialize_index(data.data(), data.size(), bytes_read), std::runtime_error);
}

TEST_F(EntryTest, DeserializePasswordOversizedLength) {
    // password_len = 0xFFFF (65535 > ENTRY_MAX_STRING_LEN)
    uint8_t data[2] = {0xFF, 0xFF};
    size_t bytes_read = 0;
    EXPECT_THROW(deserialize_password(data, 2, bytes_read), std::runtime_error);
}

// ═══════════════════════════════════════════════════════════════════════════
// Serialize validation — oversized input rejected
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, SerializeIndexRejectsOversizedName) {
    BrowsableEntry e = make_sample_browsable();
    e.name = std::string(ENTRY_MAX_STRING_LEN + 1, 'A');
    EXPECT_THROW(serialize_index(e), std::invalid_argument);
}

TEST_F(EntryTest, SerializePasswordRejectsOversized) {
    SecureBuffer big(ENTRY_MAX_STRING_LEN + 1);
    EXPECT_THROW(serialize_password(big), std::invalid_argument);
}

// ═══════════════════════════════════════════════════════════════════════════
// UTF-8 content preserved
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, Utf8ContentPreserved) {
    BrowsableEntry e = make_sample_browsable();
    e.name     = "日本語テスト";
    e.website  = "https://例え.jp";
    e.username = "ñoño@correo.es";

    std::vector<uint8_t> data = serialize_index(e);
    size_t bytes_read = 0;
    BrowsableEntry restored = deserialize_index(data.data(), data.size(), bytes_read);

    EXPECT_EQ(restored.name, e.name);
    EXPECT_EQ(restored.website, e.website);
    EXPECT_EQ(restored.username, e.username);
}

// ═══════════════════════════════════════════════════════════════════════════
// bytes_read is set correctly (exact consumption)
// ═══════════════════════════════════════════════════════════════════════════

TEST_F(EntryTest, BytesReadExactForIndex) {
    BrowsableEntry e = make_sample_browsable();
    std::vector<uint8_t> data = serialize_index(e);

    // Append trailing garbage
    data.push_back(0xDE);
    data.push_back(0xAD);

    size_t bytes_read = 0;
    BrowsableEntry restored = deserialize_index(data.data(), data.size(), bytes_read);
    // bytes_read should NOT include the trailing garbage
    EXPECT_EQ(bytes_read, data.size() - 2);
    EXPECT_EQ(restored.name, e.name);
}

TEST_F(EntryTest, BytesReadExactForPassword) {
    SecureBuffer pw = make_password("test123");
    std::vector<uint8_t> data = serialize_password(pw);
    data.push_back(0xFF); // trailing garbage

    size_t bytes_read = 0;
    SecureBuffer restored = deserialize_password(data.data(), data.size(), bytes_read);
    EXPECT_EQ(bytes_read, data.size() - 1);
}