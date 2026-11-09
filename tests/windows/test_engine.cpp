#include "test_harness.hpp"

#include "syscall/engine.hpp"

#include <windows.h>

namespace {

using NtQuerySystemTimeFn = LONG(NTAPI*)(LARGE_INTEGER*);

}

SC_TEST_CASE("init reports a fresh ntdll source") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect));
    SC_REQUIRE(engine.source() == syscall::ImageSource::kFresh);
}

SC_TEST_CASE("init reports a fresh source in indirect mode") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirect));
    SC_REQUIRE(engine.source() == syscall::ImageSource::kFresh);
}

SC_TEST_CASE("fresh resolution finds exported syscalls") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect));
    SC_REQUIRE(engine.resolve("NtClose") != nullptr);
    SC_REQUIRE(engine.resolve("NtQuerySystemTime") != nullptr);
    SC_REQUIRE(engine.resolve("NtNotARealFunction") == nullptr);
}

SC_TEST_CASE("a committed direct stub executes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect));
    const auto query = engine.get<NtQuerySystemTimeFn>("NtQuerySystemTime");
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit());

    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("a committed indirect stub executes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirect));
    const auto query = engine.get<NtQuerySystemTimeFn>("NtQuerySystemTime");
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit());

    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("resolve is rejected after commit") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect));
    SC_REQUIRE(engine.resolve("NtClose") != nullptr);
    SC_REQUIRE(engine.commit());
    SC_REQUIRE(engine.resolve("NtQuerySystemTime") == nullptr);
}

SC_TEST_CASE("a second commit is rejected") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect));
    SC_REQUIRE(engine.commit());
    SC_REQUIRE(!engine.commit());
}

SC_TEST_CASE("a second init is rejected") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect));
    SC_REQUIRE(!engine.init(syscall::Mode::kDirect));
}
