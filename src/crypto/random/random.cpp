#include "crypto/random/random.hpp"

#include <openssl/rand.h>
#include <stdexcept>
#include <limits>
#include <array>
#include <cstdint>

namespace {
    constexpr char kUppercase[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    constexpr char kLowercase[] = "abcdefghijklmnopqrstuvwxyz";
    constexpr char kDigits[]    = "0123456789";
    constexpr char kSymbols[]   = "!@#$%^&*()-_=+[]{}|;:,.<>?/";

    // max pool size: 26 + 26 + 10 + 28 = 90
    constexpr size_t kMaxPoolSize = 90;

    /**
     * @brief Pick one unbiased random character from pool using rejection sampling.
     * @param pool Character pool to sample from.
     * @return A single random character from pool.
     * @throws std::runtime_error if RAND_priv_bytes fails.
     */
    char pick_one(const std::string& pool) {
        const size_t pool_size = pool.size();
        const unsigned threshold = (256u / pool_size) * pool_size;
        while (true) {
            // Request a single byte via the private DRBG for key material.
            unsigned char byte = 0;
            if (RAND_priv_bytes(&byte, 1) != 1)
                throw std::runtime_error("RAND_priv_bytes failed — PRNG not seeded");
            if (byte < threshold)
                return pool[byte % pool_size];
            // else: reject — this byte would introduce modulo bias
        }
    }

    /**
     * @brief Cryptographically secure in-place Fisher-Yates shuffle.
     * @details Avoids std::shuffle + std::mt19937 which is not cryptographically
     *          secure. Uses a 32-bit random value so it handles strings of any
     *          length without the infinite-loop that a single-byte threshold hits
     *          when range > 256.
     * @param s String to shuffle in place.
     * @throws std::runtime_error if RAND_priv_bytes fails.
     */
    void secure_shuffle(secure_string& s) {
        const size_t n = s.size();
        for (size_t i = n - 1; i > 0; --i) {
            // We need an unbiased index in [0, i].
            const uint64_t range = i + 1;
            // Largest multiple of range that fits in a uint32_t.
            const uint64_t threshold = (0x1'0000'0000ULL / range) * range;
            uint32_t val = 0;
            do {
                if (RAND_priv_bytes(reinterpret_cast<unsigned char*>(&val), sizeof(val)) != 1)
                    throw std::runtime_error("RAND_priv_bytes failed during shuffle");
            } while (static_cast<uint64_t>(val) >= threshold);

            const size_t j = val % range;
            std::swap(s[i], s[j]);
        }
    }
}

SecureBuffer random_bytes(size_t n) {
    // Guard: RAND_bytes(ptr, 0) is undefined behaviour in some OpenSSL builds.
    if (n == 0)
        return SecureBuffer{};

    // Guard: RAND_bytes takes an int length; prevent silent truncation on cast.
    if (n > static_cast<size_t>(std::numeric_limits<int>::max()))
        throw std::invalid_argument("requested byte count exceeds INT_MAX");

    SecureBuffer buf(n);
    // Use RAND_priv_bytes so password material comes from the private DRBG
    // instance, isolated from public nonce/IV generation elsewhere in the app.
    if (RAND_priv_bytes(buf.data(), static_cast<int>(n)) != 1)
        throw std::runtime_error("RAND_priv_bytes failed — PRNG not seeded");
    return buf;
}

secure_string generate_password(size_t length, CharsetFlags flags) {
    if (length == 0)
        throw std::invalid_argument("password length must be > 0");

    // Build the full character pool from the requested charsets.
    std::string pool;
    pool.reserve(kMaxPoolSize);
    if (flags & Charset::Uppercase) pool += kUppercase;
    if (flags & Charset::Lowercase) pool += kLowercase;
    if (flags & Charset::Digits)    pool += kDigits;
    if (flags & Charset::Symbols)   pool += kSymbols;

    if (pool.empty())
        throw std::invalid_argument("at least one charset flag must be set");

    // Count how many charsets were requested so we can enforce the
    // "at least one from each" guarantee below.
    const size_t num_charsets =
        ((flags & Charset::Uppercase) ? 1u : 0u) +
        ((flags & Charset::Lowercase) ? 1u : 0u) +
        ((flags & Charset::Digits)    ? 1u : 0u) +
        ((flags & Charset::Symbols)   ? 1u : 0u);

    if (length < num_charsets)
        throw std::invalid_argument(
            "password length is too short to satisfy the per-charset guarantee");

    secure_string result;
    result.reserve(length);

    // --- Phase 1: guarantee at least one character from each requested charset ---
    // This ensures the password always satisfies common policy requirements
    // (must contain a digit, must contain a symbol, etc.).
    if (flags & Charset::Uppercase) result += pick_one(kUppercase);
    if (flags & Charset::Lowercase) result += pick_one(kLowercase);
    if (flags & Charset::Digits)    result += pick_one(kDigits);
    if (flags & Charset::Symbols)   result += pick_one(kSymbols);

    // --- Phase 2: fill the remainder from the combined pool ---
    // Rejection sampling over 256-byte chunks amortises RAND_priv_bytes call
    // overhead (one syscall per chunk rather than one per character).
    const size_t pool_size = pool.size();
    const unsigned threshold = (256u / pool_size) * pool_size;

    while (result.size() < length) {
        // Fetch a chunk large enough to keep syscall overhead low.
        // 256 bytes is a reasonable balance: cheap to allocate, and for a
        // typical pool of ~62 chars the rejection rate is < 1%, so nearly
        // every byte produces a character.
        constexpr size_t kChunk = 256;
        SecureBuffer rnd = random_bytes(kChunk);
        for (size_t i = 0; i < kChunk && result.size() < length; ++i) {
            const unsigned byte = rnd.data()[i];
            if (byte < threshold)
                result += pool[byte % pool_size];
            // else: reject — this byte would introduce modulo bias
        }
    }

    // --- Phase 3: cryptographically secure shuffle ---
    // Mix the mandatory prefix characters into random positions so their
    // placement leaks no information about which positions satisfy the policy.
    secure_shuffle(result);

    return result;
}

std::array<uint8_t, 16> generate_uuid() {
    std::array<uint8_t, 16> uuid{};
    if (RAND_bytes(uuid.data(), static_cast<int>(uuid.size())) != 1)
        throw std::runtime_error("generate_uuid: RAND_bytes failed");

    // Set version 4 bits: uuid[6] high nibble = 0100
    uuid[6] = (uuid[6] & 0x0F) | 0x40;
    // Set variant bits: uuid[8] top 2 bits = 10
    uuid[8] = (uuid[8] & 0x3F) | 0x80;

    return uuid;
}