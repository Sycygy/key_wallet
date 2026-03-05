# SecureBuffer — Documentation

## Summary

`SecureBuffer` is a C++ RAII wrapper for holding sensitive data in memory (passwords, private keys, decryption secrets). Its purpose is to minimize the window in which sensitive data exists and prevent it from leaking in unexpected ways.

C++ gives no built-in protection for sensitive data — the language was designed for performance, not secrets. Every guarantee this class provides you would otherwise have to build and remember yourself.

### What C++ gives you by default

| Concern | Default C++ behavior |
|---|---|
| Zeroing memory on free | ❌ doesn't happen |
| Preventing swap to disk | ❌ OS decides freely |
| Preventing accidental copies | ❌ copies happen silently |
| Cleanup on exceptions | ❌ manual, easy to miss |

`SecureBuffer` turns all of those from **things you have to remember** into **things that just happen automatically**.

---

## The Three Core Problems It Solves

### 1. Compilers erase your cleanup code

When you write `memset(password, 0, len)` before freeing memory, the compiler often optimizes it away — it sees "you're writing to memory you're about to free, so this is pointless" and removes it. `OPENSSL_cleanse()` is specifically designed to defeat this; it uses platform-specific tricks to guarantee the zero-write actually happens.

### 2. RAM can be swapped to disk

The OS can page memory out to a swap file at any time. A swap file can persist after a crash and be read by processes with elevated privileges. `mlock()` asks the kernel to pin the pages in RAM so they're never swapped. It's best-effort — if the process lacks permission, the class continues without locking rather than crashing.

### 3. Copies create untracked exposure

If you copy sensitive data, you have two copies and have to remember to wipe both. `SecureBuffer` disables copying entirely, making it a compile-time error rather than a runtime mistake.

---

## Full Class Breakdown

### Constructor

```cpp
explicit SecureBuffer(size_t size = 0)
    : size_(size), data_(nullptr), mlocked_(false)
{
    if (size_ == 0) return;
    data_ = new unsigned char[size_]();
    if (mlock(data_, size_) == 0)
        mlocked_ = true;
}
```

- **`explicit`** — prevents the compiler from silently converting a plain integer into a `SecureBuffer`. Forces intentional construction.
- **`size_t`** — unsigned integer for sizes; can't be negative.
- **`= 0` default** — allows declaring an empty `SecureBuffer` to assign into later via move.
- **Initializer list** — sets `data_` to `nullptr` before the body runs, so the object is always in a safe state.
- **`new unsigned char[size_]()`** — heap-allocates an array of bytes. The trailing `()` is value-initialization, which zero-initializes the memory so no garbage exists before you write your secret.
- **`mlock()`** — system call that pins the allocated pages in physical RAM, preventing the OS from swapping them to disk. Recorded in `mlocked_` so the destructor knows to call `munlock()`. Failure is silently ignored — best-effort.

---

### Destructor

```cpp
~SecureBuffer() { release(); }
```

Runs automatically when the object goes out of scope. Delegates to `release()` so the same cleanup logic can be reused by the move assignment operator.

```cpp
void release() noexcept {
    if (data_) {
        OPENSSL_cleanse(data_, size_);  // 1. guaranteed zero
        if (mlocked_) munlock(data_, size_);  // 2. unpin from RAM
        delete[] data_;  // 3. free heap memory
        data_ = nullptr; size_ = 0; mlocked_ = false;
    }
}
```

The order matters: wipe first (while memory is still pinned), unlock second, free last. Any other order creates a window where sensitive data is in a state you no longer control.

**Why `delete[]`?** Memory allocated with `new[]` must be freed with `delete[]`. Using plain `delete` instead is undefined behavior. Without freeing at all, the memory leaks — allocated but abandoned for the lifetime of the process.

---

### Deleted Copy Operations

```cpp
SecureBuffer(const SecureBuffer&)            = delete;
SecureBuffer& operator=(const SecureBuffer&) = delete;
```

C++ automatically generates copy operations for classes. `= delete` tells the compiler not to, making any attempt to copy a `SecureBuffer` a **compile-time error**.

If copying were allowed, you'd end up with two independent allocations holding the same secret. If one is destroyed properly but the other isn't, the secret leaks. The class can't track or control copies it doesn't know about. Deleting these makes the wrong thing impossible, not just inadvisable.

---

### Move Constructor

```cpp
SecureBuffer(SecureBuffer&& other) noexcept
    : size_(other.size_), data_(other.data_), mlocked_(other.mlocked_)
{
    other.data_ = nullptr;
    other.size_ = 0;
    other.mlocked_ = false;
}
```

Since copying is forbidden, moving is the alternative. Instead of duplicating data, it transfers ownership.

- **`&&`** — rvalue reference; signals the caller is giving up ownership, not just lending.
- **`noexcept`** — promises no exceptions will be thrown. Required for the standard library to prefer moves over copies in containers like `std::vector`.
- **Initializer list** — steals `other`'s pointer and state. No new allocation happens — just the pointer value is copied across.
- **Nulling out `other`** — critical. When `other` is eventually destroyed, its destructor calls `release()`. If the pointer wasn't nulled, `release()` would wipe and free memory that now belongs to the new object — a double free.

```
Before move:          After move:
a → [secret data]     a → nullptr (empty, harmless)
b → (uninitialized)   b → [secret data]
```

The secret data never moved — only the pointer to it did. One owner at all times.

---

### Move Assignment Operator

```cpp
SecureBuffer& operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        release();
        size_ = other.size_; data_ = other.data_; mlocked_ = other.mlocked_;
        other.data_ = nullptr; other.size_ = 0; other.mlocked_ = false;
    }
    return *this;
}
```

Handles the case where **both objects already exist** and `b` already holds its own data:

```cpp
SecureBuffer a(64);  // exists
SecureBuffer b(32);  // exists, has its own data
b = std::move(a);    // move assignment
```

- **Self-assignment check** (`this != &other`) — guards against `a = std::move(a)`. Without it, `release()` would destroy the data before it could be stolen.
- **`release()` first** — `b` already owns an allocation. It must be wiped and freed before overwriting `b`'s pointer, otherwise that memory leaks permanently.
- **Steal and null** — same as the move constructor from here.
- **`return *this`** — standard convention for assignment operators; enables chaining like `a = b = std::move(c)`.

| | Move Constructor | Move Assignment |
|---|---|---|
| `b` beforehand | doesn't exist yet | already owns data |
| Extra step needed | none | `release()` to clean up `b` first |
| Self-assignment check | not needed | required |

---

### Accessors

```cpp
unsigned char*       data()  noexcept       { return data_; }
const unsigned char* data()  const noexcept { return data_; }
size_t               size()  const noexcept { return size_; }
bool                 empty() const noexcept { return size_ == 0 || data_ == nullptr; }
```

- **Two `data()` overloads** — the compiler picks the right one automatically. On a mutable object, returns a non-const pointer (writes allowed). On a const object, returns a const pointer (read only). This is called const overloading.
- **`size()`** — returns the byte count. Marked `const` since reading size shouldn't modify anything.
- **`empty()`** — checks both `size_ == 0` and `data_ == nullptr` with `||`. After a move, both will be zero/null anyway, but guarding both independently means no weird intermediate state is mistaken for a valid buffer.

---

### `wipe()`

```cpp
void wipe() noexcept {
    if (data_) OPENSSL_cleanse(data_, size_);
}
```

Zeros the buffer without destroying it — useful when you want to reuse the same allocation rather than destroy and recreate:

```cpp
SecureBuffer buf(32);
// ... use buf ...
buf.wipe();       // zeroed, still allocated
// ... reuse buf ...
```

The `if (data_)` guard means calling `wipe()` on an empty or moved-from buffer is safe and does nothing.

---

## Lifecycle Example

```cpp
SecureBuffer buf(32);     // allocates 32 zeroed bytes, calls mlock()

buf.data()[0] = 0xFF;     // write sensitive data via raw pointer

buf.wipe();               // zero it mid-life before reuse

SecureBuffer other = std::move(buf);  // transfer ownership; buf is now empty

// other goes out of scope:
//   1. OPENSSL_cleanse()  — guaranteed zero
//   2. munlock()          — unpin from RAM
//   3. delete[]           — return to heap
```