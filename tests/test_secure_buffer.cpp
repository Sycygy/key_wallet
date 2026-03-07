#include <gtest/gtest.h>
#include "core/secure_buffer.hpp"

// ── Construction ─────────────────────────────────────────────────────────────

TEST(SecureBuffer, DefaultConstructorIsEmpty) {
    SecureBuffer buf;
    EXPECT_TRUE(buf.empty());
    EXPECT_EQ(buf.size(), 0u);
    EXPECT_EQ(buf.data(), nullptr);
}

TEST(SecureBuffer, AllocatesRequestedSize) {
    SecureBuffer buf(64);
    EXPECT_FALSE(buf.empty());
    EXPECT_EQ(buf.size(), 64u);
    EXPECT_NE(buf.data(), nullptr);
}

TEST(SecureBuffer, InitialisedToZero) {
    SecureBuffer buf(32);
    for (size_t i = 0; i < buf.size(); ++i)
        EXPECT_EQ(buf.data()[i], 0) << "byte " << i << " not zero";
}

// ── Read / Write ─────────────────────────────────────────────────────────────

TEST(SecureBuffer, CanWriteAndReadBack) {
    SecureBuffer buf(8);
    for (size_t i = 0; i < buf.size(); ++i)
        buf.data()[i] = static_cast<unsigned char>(i * 3);

    for (size_t i = 0; i < buf.size(); ++i)
        EXPECT_EQ(buf.data()[i], static_cast<unsigned char>(i * 3));
}

// ── Wipe ─────────────────────────────────────────────────────────────────────

TEST(SecureBuffer, WipeClearsContents) {
    SecureBuffer buf(16);
    std::memset(buf.data(), 0xAB, buf.size());

    buf.wipe();

    for (size_t i = 0; i < buf.size(); ++i)
        EXPECT_EQ(buf.data()[i], 0) << "byte " << i << " not zeroed after wipe";
}

// ── Move semantics ────────────────────────────────────────────────────────────

TEST(SecureBuffer, MoveConstructorTransfersOwnership) {
    SecureBuffer a(32);
    std::memset(a.data(), 0x42, 32);
    const unsigned char* original_ptr = a.data();

    SecureBuffer b(std::move(a));

    EXPECT_TRUE(a.empty());
    EXPECT_EQ(a.data(), nullptr);
    EXPECT_EQ(b.size(), 32u);
    EXPECT_EQ(b.data(), original_ptr);
    EXPECT_EQ(b.data()[0], 0x42);
}

TEST(SecureBuffer, MoveAssignmentTransfersOwnership) {
    SecureBuffer a(48);
    std::memset(a.data(), 0x7F, 48);
    const unsigned char* original_ptr = a.data();

    SecureBuffer b(8);
    b = std::move(a);

    EXPECT_TRUE(a.empty());
    EXPECT_EQ(b.size(), 48u);
    EXPECT_EQ(b.data(), original_ptr);
    EXPECT_EQ(b.data()[0], 0x7F);
}

TEST(SecureBuffer, SelfMoveAssignmentIsSafe) {
    SecureBuffer buf(16);
    std::memset(buf.data(), 0x55, 16);

    // Must not crash or corrupt — suppress compiler warning for intentional self-move
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wself-move"
    buf = std::move(buf);
#pragma GCC diagnostic pop
}

// ── Copy disabled (compile-time) ──────────────────────────────────────────────
// These would fail to compile — verified by the delete= declarations:
// SecureBuffer copy(buf);           // deleted
// SecureBuffer copy2; copy2 = buf;  // deleted
