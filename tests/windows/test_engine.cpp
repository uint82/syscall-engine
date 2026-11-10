#include "test_harness.hpp"

#include "syscall/engine.hpp"
#include "syscall/hash.hpp"

#include <windows.h>

namespace {

using NtQuerySystemTimeFn = LONG(NTAPI*)(LARGE_INTEGER*);

}

SC_TEST_CASE("init reports a fresh ntdll source") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    SC_REQUIRE(engine.source() == syscall::ImageSource::kFresh);
}

SC_TEST_CASE("init reports a fresh source in indirect mode") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirect) == syscall::Status::kOk);
    SC_REQUIRE(engine.source() == syscall::ImageSource::kFresh);
}

SC_TEST_CASE("fresh resolution finds exported syscalls") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    SC_REQUIRE(engine.resolve("NtClose") != nullptr);
    SC_REQUIRE(engine.resolve("NtQuerySystemTime") != nullptr);
    SC_REQUIRE(engine.resolve("NtNotARealFunction") == nullptr);
    SC_REQUIRE(engine.last_error() == syscall::Status::kUnknownExport);
}

SC_TEST_CASE("resolution caches stubs per export") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    void* by_name = engine.resolve("NtClose");
    SC_REQUIRE(by_name != nullptr);
    SC_REQUIRE(engine.resolve("NtClose") == by_name);
    SC_REQUIRE(engine.resolve(SC_HASH("NtClose")) == by_name);
}

SC_TEST_CASE("a committed direct stub executes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    const auto query = engine.get<NtQuerySystemTimeFn>("NtQuerySystemTime");
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("a committed indirect stub executes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirect) == syscall::Status::kOk);
    const auto query = engine.get<NtQuerySystemTimeFn>("NtQuerySystemTime");
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("resolve is rejected after commit") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    SC_REQUIRE(engine.resolve("NtClose") != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);
    SC_REQUIRE(engine.resolve("NtQuerySystemTime") == nullptr);
    SC_REQUIRE(engine.last_error() == syscall::Status::kAlreadyCommitted);
}

SC_TEST_CASE("a second commit is rejected") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);
    SC_REQUIRE(engine.commit() == syscall::Status::kAlreadyCommitted);
}

SC_TEST_CASE("hashed resolution finds exported syscalls") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    SC_REQUIRE(engine.resolve(SC_HASH("NtClose")) != nullptr);
    SC_REQUIRE(engine.resolve(SC_HASH("NtNotARealFunction")) == nullptr);
}

SC_TEST_CASE("a committed hashed direct stub executes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    const auto query =
        engine.get<NtQuerySystemTimeFn>(SC_HASH("NtQuerySystemTime"));
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("a committed hashed indirect stub executes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirect) == syscall::Status::kOk);
    const auto query =
        engine.get<NtQuerySystemTimeFn>(SC_HASH("NtQuerySystemTime"));
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("hashed resolution is rejected after commit") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);
    SC_REQUIRE(engine.resolve(SC_HASH("NtQuerySystemTime")) == nullptr);
    SC_REQUIRE(engine.last_error() == syscall::Status::kAlreadyCommitted);
}

SC_TEST_CASE("a second init is rejected") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kAlreadyInitialized);
    SC_REQUIRE(engine.last_error() == syscall::Status::kAlreadyInitialized);
}

SC_TEST_CASE("resolution before init is rejected") {
    syscall::Engine engine;
    SC_REQUIRE(engine.resolve("NtClose") == nullptr);
    SC_REQUIRE(engine.last_error() == syscall::Status::kNotInitialized);
}

SC_TEST_CASE("a null name is rejected") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    SC_REQUIRE(engine.resolve(static_cast<const char*>(nullptr)) == nullptr);
    SC_REQUIRE(engine.last_error() == syscall::Status::kInvalidArgument);
}

SC_TEST_CASE("commit before init is rejected") {
    syscall::Engine engine;
    SC_REQUIRE(engine.commit() == syscall::Status::kNotInitialized);
}
