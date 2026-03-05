#pragma once

#include <cstddef>
#include <cstring>
#include <openssl/crypto.h>  // OPENSSL_cleanse
#include <sys/mman.h>        // mlock, munlock

// SecureBuffer — RAII wrapper for sensitive in-memory data.
//
// Guarantees:
//   - Memory is zeroed on destruction via OPENSSL_cleanse() (compiler-safe,
//     unlike memset which can be elided).
//   - Best-effort mlock() prevents the pages from being swapped to disk.
//     If mlock() fails (e.g. insufficient RLIMIT_MEMLOCK), we continue
//     without locking — never fatal.
//   - Copying is disabled; move transfers ownership and zeros the source.

class SecureBuffer {
public:
    // Allocates `size` zero-initialised bytes and attempts mlock.
    explicit SecureBuffer(size_t size = 0)
        : size_(size), data_(nullptr), mlocked_(false)
    {
        if (size_ == 0) return;

        data_ = new unsigned char[size_]();   // value-init → zeroed

        if (mlock(data_, size_) == 0)
            mlocked_ = true;
        // mlock failure is silently ignored — best-effort
    }

    ~SecureBuffer() { release(); }

    // No copy — would expose sensitive data in an untracked allocation.
    SecureBuffer(const SecureBuffer&)            = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Move transfers ownership; source is left empty.
    SecureBuffer(SecureBuffer&& other) noexcept
        : size_(other.size_), data_(other.data_), mlocked_(other.mlocked_)
    {
        other.data_    = nullptr;
        other.size_    = 0;
        other.mlocked_ = false;
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            release();
            size_    = other.size_;
            data_    = other.data_;
            mlocked_ = other.mlocked_;
            other.data_    = nullptr;
            other.size_    = 0;
            other.mlocked_ = false;
        }
        return *this;
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    unsigned char*       data()  noexcept       { return data_; }
    const unsigned char* data()  const noexcept { return data_; }
    size_t               size()  const noexcept { return size_; }
    bool                 empty() const noexcept { return size_ == 0 || data_ == nullptr; }

    // ── Utilities ────────────────────────────────────────────────────────────

    // Explicit zero — useful before reuse without destruction.
    void wipe() noexcept {
        if (data_) OPENSSL_cleanse(data_, size_);
    }

private:
    void release() noexcept {
        if (data_) {
            OPENSSL_cleanse(data_, size_);
            if (mlocked_) munlock(data_, size_);
            delete[] data_;
            data_    = nullptr;
            size_    = 0;
            mlocked_ = false;
        }
    }

    size_t         size_;
    unsigned char* data_;
    bool           mlocked_;
};
