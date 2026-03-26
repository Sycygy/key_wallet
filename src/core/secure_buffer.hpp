#pragma once

#include <cstddef>
#include <cstring>
#include <string>
#include <openssl/crypto.h>  // OPENSSL_secure_malloc, OPENSSL_secure_clear_free

/**
 * @brief RAII wrapper for sensitive in-memory data using OpenSSL's secure heap.
 *
 * @details Guarantees (v0.2):
 *   - Memory allocated via OPENSSL_secure_malloc() from the secure heap arena,
 *     which provides: page-aligned allocation, mlock, guard pages, and
 *     MADV_DONTDUMP automatically.
 *   - Memory zeroed on destruction via OPENSSL_secure_clear_free() which calls
 *     OPENSSL_cleanse() before freeing (compiler-safe, unlike memset).
 *   - Requires CRYPTO_secure_malloc_init() to have been called in main().
 *     If the secure heap is not initialised, OPENSSL_secure_malloc falls back
 *     to regular malloc — the buffer still works but without hardening.
 *   - Copying is disabled; move transfers ownership and zeros the source.
 *
 * @note v0.1 used new[] + manual mlock/munlock. v0.2 delegates all memory
 *       hardening to OpenSSL's secure heap, which is more robust and provides
 *       guard pages and MADV_DONTDUMP that the v0.1 approach lacked.
 */
class SecureBuffer {
public:
    /**
     * @brief Allocates `size` zero-initialised bytes from the OpenSSL secure heap.
     * @param size Number of bytes to allocate (0 produces an empty buffer).
     */
    explicit SecureBuffer(size_t size = 0)
        : size_(size), data_(nullptr)
    {
        if (size_ == 0) return;

        data_ = static_cast<unsigned char*>(OPENSSL_secure_malloc(size_));
        if (!data_) {
            // Secure heap exhausted or not initialised — fall back to regular malloc
            data_ = static_cast<unsigned char*>(OPENSSL_malloc(size_));
            if (!data_)
                throw std::bad_alloc();
        }
        std::memset(data_, 0, size_);  // zero-init (secure heap does not guarantee this)
    }

    ~SecureBuffer() { release(); }

    /** @brief Copy disabled — would expose sensitive data in an untracked allocation. */
    SecureBuffer(const SecureBuffer&)            = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    /** @brief Move constructor — transfers ownership; source is left empty. */
    SecureBuffer(SecureBuffer&& other) noexcept
        : size_(other.size_), data_(other.data_)
    {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            release();
            size_ = other.size_;
            data_ = other.data_;
            other.data_ = nullptr;
            other.size_ = 0;
        }
        return *this;
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    unsigned char*       data()  noexcept       { return data_; }
    const unsigned char* data()  const noexcept { return data_; }
    size_t               size()  const noexcept { return size_; }
    bool                 empty() const noexcept { return size_ == 0 || data_ == nullptr; }

    // ── Utilities ────────────────────────────────────────────────────────────

    /** @brief Explicitly zero the buffer contents — useful before reuse without destruction. */
    void wipe() noexcept {
        if (data_) OPENSSL_cleanse(data_, size_);
    }

private:
    void release() noexcept {
        if (data_) {
            // OPENSSL_secure_clear_free calls OPENSSL_cleanse then frees from
            // whichever heap the pointer belongs to (secure or regular).
            OPENSSL_secure_clear_free(data_, size_);
            data_ = nullptr;
            size_ = 0;
        }
    }

    size_t         size_;
    unsigned char* data_;
};

// ── SecureAllocator + secure_string ────────────────────────────────────────

/**
 * @brief STL-compatible allocator backed by OpenSSL's secure heap.
 *
 * @details Provides the same hardening guarantees as SecureBuffer
 *   (mlock, guard pages, MADV_DONTDUMP, compiler-safe zeroing) but in a form
 *   usable with std::basic_string and other STL containers.
 *
 *   Memory is zeroed via OPENSSL_secure_clear_free() on deallocation, so
 *   sensitive strings are wiped automatically when they go out of scope or
 *   when the container reallocates.
 */
template <typename T>
struct SecureAllocator {
    using value_type = T;

    SecureAllocator() noexcept = default;

    template <typename U>
    SecureAllocator(const SecureAllocator<U>&) noexcept {}

    T* allocate(std::size_t n) {
        if (n == 0) return nullptr;

        void* p = OPENSSL_secure_malloc(n * sizeof(T));
        if (!p) {
            p = OPENSSL_malloc(n * sizeof(T));
            if (!p) throw std::bad_alloc();
        }
        return static_cast<T*>(p);
    }

    void deallocate(T* p, std::size_t n) noexcept {
        if (p) OPENSSL_secure_clear_free(p, n * sizeof(T));
    }

    template <typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template <typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

/**
 * @brief std::string replacement that lives on the OpenSSL secure heap.
 *
 * @details Drop-in for std::string in sensitive contexts (passwords, keys).
 *   Automatically zeroed on destruction, reallocation, and scope exit.
 */
using secure_string = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;
