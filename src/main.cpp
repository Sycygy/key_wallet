#include <iostream>

#include <openssl/crypto.h>   // CRYPTO_secure_malloc_init
#include <sys/prctl.h>        // prctl, PR_SET_DUMPABLE
#include <sys/resource.h>     // setrlimit, RLIMIT_CORE

int main([[maybe_unused]] int argc, [[maybe_unused]] char* argv[]) {
    // 1. Initialize OpenSSL secure heap (mlock'd, MADV_DONTDUMP, guard pages).
    //    SecureBuffer allocations will use this arena automatically.
    if (!CRYPTO_secure_malloc_init(65536, 32)) {
        std::cerr << "warning: secure heap init failed — falling back to regular malloc\n";
    }

    // 2. Disable core dumps — also blocks same-user ptrace attach.
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    // 3. Belt-and-suspenders core dump disable via resource limit.
    struct rlimit rl = {0, 0};
    setrlimit(RLIMIT_CORE, &rl);

    std::cout << "key_wallet — Phase 1 scaffold (v0.2)\n";
    return 0;
}
