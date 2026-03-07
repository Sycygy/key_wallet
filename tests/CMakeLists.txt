include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG        v1.15.2
)
# Prevent GTest from overriding our compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)

# ── Helper: define a test target ─────────────────────────────────────────────
function(add_kw_test name)
    add_executable(${name} ${ARGN})
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/include
        ${OPENSSL_INCLUDE_DIR}
    )
    target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic -O2)
    target_link_libraries(${name} PRIVATE GTest::gtest_main OpenSSL::SSL OpenSSL::Crypto)
    gtest_discover_tests(${name})
endfunction()

# ── Smoke test ────────────────────────────────────────────────────────────────
add_kw_test(test_scaffold test_scaffold.cpp)

# ── Phase 1.2 — SecureBuffer ──────────────────────────────────────────────────
add_kw_test(test_secure_buffer test_secure_buffer.cpp)

# ── Phase 1.3 — random ────────────────────────────────────────────────────────
add_kw_test(test_random test_random.cpp ../src/crypto/random/random.cpp)

# ── Phase 1.4 — kdf ───────────────────────────────────────────────────────────
add_kw_test(test_kdf test_kdf.cpp ../src/crypto/kdf/kdf.cpp)

# ── Phase 1.5 — aead ─────────────────────────────────────────────────────────
add_kw_test(test_aead test_aead.cpp ../src/crypto/aead/aead.cpp ../src/crypto/random/random.cpp)
