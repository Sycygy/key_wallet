#include <gtest/gtest.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

// Verify OpenSSL 3.2+ is present and RAND_bytes works
TEST(Scaffold, OpenSSLVersion) {
    EXPECT_GE(OPENSSL_VERSION_NUMBER, 0x30200000L)
        << "OpenSSL 3.2+ required for Argon2id (EVP_KDF)";
}

TEST(Scaffold, RandBytesWorks) {
    unsigned char buf[32] = {};
    EXPECT_EQ(RAND_bytes(buf, sizeof(buf)), 1);
    // Highly unlikely to be all zeros if PRNG works
    bool all_zero = true;
    for (unsigned char b : buf) if (b != 0) { all_zero = false; break; }
    EXPECT_FALSE(all_zero);
}
