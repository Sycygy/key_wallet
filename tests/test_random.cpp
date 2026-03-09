#include <gtest/gtest.h>
#include "crypto/random/random.hpp"
#include <cctype>
#include <unordered_set>

// ── random_bytes ──────────────────────────────────────────────────────────────

TEST(RandomBytes, ZeroReturnsEmpty) {
    auto buf = random_bytes(0);
    EXPECT_EQ(buf.size(), 0u);
}

TEST(RandomBytes, ReturnsRequestedSize) {
    auto buf = random_bytes(32);
    EXPECT_EQ(buf.size(), 32u);
    EXPECT_NE(buf.data(), nullptr);
}

TEST(RandomBytes, NotAllZero) {
    auto buf = random_bytes(64);
    bool all_zero = true;
    for (size_t i = 0; i < buf.size(); ++i)
        if (buf.data()[i] != 0) { all_zero = false; break; }
    EXPECT_FALSE(all_zero);
}

TEST(RandomBytes, TwoCallsDiffer) {
    auto a = random_bytes(32);
    auto b = random_bytes(32);
    bool identical = true;
    for (size_t i = 0; i < 32; ++i)
        if (a.data()[i] != b.data()[i]) { identical = false; break; }
    EXPECT_FALSE(identical);
}

// ── generate_password — length & content ─────────────────────────────────────

TEST(GeneratePassword, CorrectLength) {
    // Charset::All requires 4 chars minimum — use a single charset for length=1.
    EXPECT_EQ(generate_password(1, Charset::Uppercase).size(),  1u);
    EXPECT_EQ(generate_password(16).size(), 16u);
    EXPECT_EQ(generate_password(64).size(), 64u);
}

TEST(GeneratePassword, UppercaseOnly) {
    auto pw = generate_password(100, Charset::Uppercase);
    for (char c : pw)
        EXPECT_TRUE(std::isupper(static_cast<unsigned char>(c))) << "unexpected: " << c;
}

TEST(GeneratePassword, LowercaseOnly) {
    auto pw = generate_password(100, Charset::Lowercase);
    for (char c : pw)
        EXPECT_TRUE(std::islower(static_cast<unsigned char>(c))) << "unexpected: " << c;
}

TEST(GeneratePassword, DigitsOnly) {
    auto pw = generate_password(100, Charset::Digits);
    for (char c : pw)
        EXPECT_TRUE(std::isdigit(static_cast<unsigned char>(c))) << "unexpected: " << c;
}

TEST(GeneratePassword, UpperAndLowerOnly) {
    CharsetFlags flags = Charset::Uppercase | Charset::Lowercase;
    auto pw = generate_password(200, flags);
    for (char c : pw)
        EXPECT_TRUE(std::isalpha(static_cast<unsigned char>(c))) << "unexpected: " << c;
}

TEST(GeneratePassword, AllCharsetsRepresented) {
    // With 200 chars drawn from all 4 categories, all must appear
    auto pw = generate_password(200, Charset::All);
    bool has_upper = false, has_lower = false, has_digit = false, has_sym = false;
    for (char c : pw) {
        unsigned char uc = static_cast<unsigned char>(c);
        if      (std::isupper(uc)) has_upper = true;
        else if (std::islower(uc)) has_lower = true;
        else if (std::isdigit(uc)) has_digit = true;
        else                       has_sym   = true;
    }
    EXPECT_TRUE(has_upper) << "no uppercase found";
    EXPECT_TRUE(has_lower) << "no lowercase found";
    EXPECT_TRUE(has_digit) << "no digit found";
    EXPECT_TRUE(has_sym)   << "no symbol found";
}

TEST(GeneratePassword, SymbolsOnly) {
    const std::string kSymbols = "!@#$%^&*()-_=+[]{}|;:,.<>?/";
    const std::unordered_set<char> valid(kSymbols.begin(), kSymbols.end());
    auto pw = generate_password(100, Charset::Symbols);
    for (char c : pw)
        EXPECT_TRUE(valid.count(c)) << "unexpected: " << c;
}

// ── generate_password — error handling ────────────────────────────────────────

TEST(GeneratePassword, ThrowsOnZeroLength) {
    EXPECT_THROW(generate_password(0), std::invalid_argument);
}

TEST(GeneratePassword, ThrowsOnEmptyCharset) {
    EXPECT_THROW(generate_password(16, 0), std::invalid_argument);
}

TEST(GeneratePassword, ThrowsWhenLengthLessThanCharsetCount) {
    // All 4 charsets requested but only 3 chars — cannot guarantee one from each.
    EXPECT_THROW(generate_password(3, Charset::All), std::invalid_argument);
    // Two charsets, one char — same problem.
    EXPECT_THROW(generate_password(1, Charset::Uppercase | Charset::Lowercase),
                 std::invalid_argument);
}

// ── generate_uuid ────────────────────────────────────────────────────────────

TEST(GenerateUuid, Returns16Bytes) {
    auto uuid = generate_uuid();
    EXPECT_EQ(uuid.size(), 16u);
}

TEST(GenerateUuid, VersionBitsAreV4) {
    auto uuid = generate_uuid();
    // Version nibble (uuid[6] high nibble) must be 0x40 (version 4)
    EXPECT_EQ(uuid[6] & 0xF0, 0x40);
}

TEST(GenerateUuid, VariantBitsAreRFC4122) {
    auto uuid = generate_uuid();
    // Variant bits (uuid[8] top 2 bits) must be 10xx xxxx
    EXPECT_EQ(uuid[8] & 0xC0, 0x80);
}

TEST(GenerateUuid, TwoCallsDiffer) {
    auto a = generate_uuid();
    auto b = generate_uuid();
    EXPECT_NE(a, b);
}

TEST(GenerateUuid, NotAllZero) {
    auto uuid = generate_uuid();
    bool all_zero = true;
    for (auto byte : uuid)
        if (byte != 0) { all_zero = false; break; }
    EXPECT_FALSE(all_zero);
}

// ── Bias check (rejection sampling) ──────────────────────────────────────────
/**
 * @brief Verify digit distribution is unbiased via rejection sampling.
 * @details Generates 1000 digits and verifies each appears roughly 100 times (±40%).
 *          A modulo-biased implementation would systematically over-represent
 *          digits 0-5 (since 256 % 10 = 6).
 */
TEST(GeneratePassword, DigitDistributionNotBiased) {
    constexpr size_t kSamples = 1000;
    auto pw = generate_password(kSamples, Charset::Digits);

    int counts[10] = {};
    for (char c : pw) counts[c - '0']++;

    const int expected = static_cast<int>(kSamples) / 10;  // 100
    const int tolerance = expected * 40 / 100;              // ±40 counts

    for (int i = 0; i < 10; ++i) {
        EXPECT_GE(counts[i], expected - tolerance) << "digit " << i << " underrepresented";
        EXPECT_LE(counts[i], expected + tolerance) << "digit " << i << " overrepresented";
    }
}
