#include "test_harness.hpp"

#include "syscall/engine.hpp"
#include "syscall/hash.hpp"

#include <windows.h>

#include <cstddef>

namespace {

using NtQuerySystemTimeFn = LONG(NTAPI*)(LARGE_INTEGER*);
using NtQueryVirtualMemoryFn =
    LONG(NTAPI*)(HANDLE, const void*, int, void*, std::size_t, std::size_t*);

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

SC_TEST_CASE("init reports the active mode") {
    syscall::Engine direct;
    SC_REQUIRE(direct.init(syscall::Mode::kDirect) == syscall::Status::kOk);
    SC_REQUIRE(direct.mode() == syscall::Mode::kDirect);

    syscall::Engine indirect;
    SC_REQUIRE(indirect.init(syscall::Mode::kIndirect) == syscall::Status::kOk);
    SC_REQUIRE(indirect.mode() == syscall::Mode::kIndirect);

    syscall::Engine spoofed;
    SC_REQUIRE(spoofed.init(syscall::Mode::kIndirectSpoofed) == syscall::Status::kOk);
    SC_REQUIRE(spoofed.mode() == syscall::Mode::kIndirectSpoofed);

    syscall::Engine unwind;
    SC_REQUIRE(unwind.init(syscall::Mode::kIndirectUnwindSpoofed) == syscall::Status::kOk);
    SC_REQUIRE(unwind.mode() == syscall::Mode::kIndirectUnwindSpoofed);
}

SC_TEST_CASE("a committed spoofed stub executes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectSpoofed) == syscall::Status::kOk);
    const auto query = engine.get<NtQuerySystemTimeFn>("NtQuerySystemTime");
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("a committed hashed spoofed stub executes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectSpoofed) == syscall::Status::kOk);
    const auto query =
        engine.get<NtQuerySystemTimeFn>(SC_HASH("NtQuerySystemTime"));
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("a committed spoofed stub forwards stack arguments") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectSpoofed) == syscall::Status::kOk);
    const auto query = engine.get<NtQueryVirtualMemoryFn>("NtQueryVirtualMemory");
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    MEMORY_BASIC_INFORMATION info{};
    std::size_t returned = 0;
    const LONG status = query(GetCurrentProcess(), GetModuleHandleA(nullptr), 0, &info,
                              sizeof(info), &returned);
    SC_REQUIRE(status >= 0);
    SC_REQUIRE(returned > 0);
}

SC_TEST_CASE("a committed unwind spoofed stub executes") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectUnwindSpoofed) == syscall::Status::kOk);
    const auto query = engine.get<NtQuerySystemTimeFn>("NtQuerySystemTime");
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    LARGE_INTEGER time{};
    SC_REQUIRE(query(&time) >= 0);
    SC_REQUIRE(time.QuadPart != 0);
}

SC_TEST_CASE("a committed unwind spoofed stub forwards stack arguments") {
    syscall::Engine engine;
    SC_REQUIRE(engine.init(syscall::Mode::kIndirectUnwindSpoofed) == syscall::Status::kOk);
    const auto query = engine.get<NtQueryVirtualMemoryFn>("NtQueryVirtualMemory");
    SC_REQUIRE(query != nullptr);
    SC_REQUIRE(engine.commit() == syscall::Status::kOk);

    MEMORY_BASIC_INFORMATION info{};
    std::size_t returned = 0;
    const LONG status = query(GetCurrentProcess(), GetModuleHandleA(nullptr), 0, &info,
                              sizeof(info), &returned);
    SC_REQUIRE(status >= 0);
    SC_REQUIRE(returned > 0);
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
