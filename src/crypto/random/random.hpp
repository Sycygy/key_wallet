#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include "core/secure_buffer.hpp"

/** @brief Bitmask type for selecting character sets in generate_password. */
using CharsetFlags = uint8_t;

namespace Charset {
    inline constexpr CharsetFlags Uppercase = 1 << 0;
    inline constexpr CharsetFlags Lowercase = 1 << 1;
    inline constexpr CharsetFlags Digits    = 1 << 2;
    inline constexpr CharsetFlags Symbols   = 1 << 3;
    inline constexpr CharsetFlags All       = Uppercase | Lowercase | Digits | Symbols;
}

/**
 * @brief Fill a SecureBuffer with n cryptographically random bytes.
 * @param n Number of bytes to generate. Pass 0 to get an empty buffer.
 * @return SecureBuffer containing n random bytes.
 * @throws std::invalid_argument if n > INT_MAX.
 * @throws std::runtime_error if RAND_priv_bytes fails.
 */
SecureBuffer random_bytes(size_t n);

/**
 * @brief Generate a random password drawn from the specified character sets.
 * @details Uses rejection sampling to eliminate modulo bias and guarantees at
 *          least one character from each requested charset. A cryptographically
 *          secure Fisher-Yates shuffle mixes the result so mandatory characters
 *          do not cluster at predictable positions.
 * @param length Number of characters in the generated password.
 * @param flags  Bitmask of Charset:: flags selecting which character sets to use.
 *               Defaults to Charset::All.
 * @return Random password string of exactly `length` characters.
 * @throws std::invalid_argument if length == 0, flags == 0, or length is less
 *         than the number of requested charsets.
 * @throws std::runtime_error if the PRNG fails.
 */
secure_string generate_password(size_t length, CharsetFlags flags = Charset::All);

/**
 * @brief Generate a random UUID v4 using RAND_bytes().
 * @details Sets version bits (uuid[6] = (uuid[6] & 0x0F) | 0x40) and variant
 *          bits (uuid[8] = (uuid[8] & 0x3F) | 0x80) per RFC 4122. The 122 bits
 *          of randomness from RAND_bytes ensure UUIDs are unpredictable, which
 *          is required for the HKDF info parameter to provide domain separation.
 * @return 16-byte array containing a valid UUID v4.
 * @throws std::runtime_error if RAND_bytes fails.
 */
std::array<uint8_t, 16> generate_uuid();