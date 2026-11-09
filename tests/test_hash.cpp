#include "test_harness.hpp"

#include "syscall/hash.hpp"

#include <cstdint>

static_assert(syscall::fnv1a("") == 0xCBF29CE484222325ULL);
static_assert(syscall::fnv1a("a") == 0xAF63DC4C8601EC8CULL);
static_assert(syscall::fnv1a("foobar") == 0x85944171F73967E8ULL);

SC_TEST_CASE("fnv1a matches the reference vectors") {
    SC_REQUIRE_EQ(0xCBF29CE484222325ULL, syscall::fnv1a(""));
    SC_REQUIRE_EQ(0xAF63DC4C8601EC8CULL, syscall::fnv1a("a"));
    SC_REQUIRE_EQ(0x85944171F73967E8ULL, syscall::fnv1a("foobar"));
}

SC_TEST_CASE("fnv1a is case sensitive") {
    SC_REQUIRE(syscall::fnv1a("NtClose") != syscall::fnv1a("ntclose"));
}

SC_TEST_CASE("SC_HASH matches fnv1a") {
    SC_REQUIRE_EQ(syscall::fnv1a("NtClose"), SC_HASH("NtClose"));
}
