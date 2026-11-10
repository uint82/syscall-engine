#include "test_harness.hpp"
#include "unwind_fixture.hpp"

#include "syscall/unwind.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

SC_TEST_CASE("read_simple_frame_layout reads a small allocation") {
    const auto fixture = support::build_single_function_image(
        support::make_unwind_info(
            1, 4, 0, {{4, support::kAllocSmall, 8, 0}}));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(layout.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x48), layout->frame_size);
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x48), layout->local_alloc);
    SC_REQUIRE_EQ(static_cast<std::size_t>(0), layout->push_count);
}

SC_TEST_CASE("read_simple_frame_layout counts pushed registers") {
    const auto fixture = support::build_single_function_image(
        support::make_unwind_info(
            1, 6, 0,
            {{1, support::kPushNonvol, 3, 0},
             {2, support::kAllocSmall, 4, 0}}));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(layout.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x30), layout->frame_size);
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x28), layout->local_alloc);
    SC_REQUIRE_EQ(static_cast<std::size_t>(1), layout->push_count);
}

SC_TEST_CASE("read_simple_frame_layout rejects a frame pointer") {
    const auto fixture = support::build_single_function_image(
        support::make_unwind_info(
            1, 4, 0, {{2, support::kSetFpreg, 0, 0}}));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(!layout.has_value());
}

SC_TEST_CASE("read_simple_frame_layout rejects chained unwind info") {
    const auto fixture = support::build_single_function_image(
        support::make_unwind_info(
            0x21, 4, 0, {{4, support::kAllocSmall, 0, 0}}));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(!layout.has_value());
}

SC_TEST_CASE("read_simple_frame_layout ignores saved registers") {
    const auto fixture = support::build_single_function_image(
        support::make_unwind_info(
            1, 4, 0,
            {{2, support::kAllocSmall, 4, 0},
             {4, support::kSaveNonvol, 0, 1}}));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(layout.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x28), layout->frame_size);
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x28), layout->local_alloc);
    SC_REQUIRE_EQ(static_cast<std::size_t>(0), layout->push_count);
}

SC_TEST_CASE("read_simple_frame_layout reads a large allocation") {
    const auto fixture = support::build_single_function_image(
        support::make_alloc_large_unwind(0, 0x80));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(layout.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x80), layout->frame_size);
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x80), layout->local_alloc);
}

SC_TEST_CASE("read_simple_frame_layout reads a far large allocation") {
    const auto fixture = support::build_single_function_image(
        support::make_alloc_large_unwind(1, 0x1234));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(layout.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x1234), layout->frame_size);
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x1234), layout->local_alloc);
}

SC_TEST_CASE("read_simple_frame_layout ignores far xmm saves") {
    for (const auto info : {std::uint8_t{0}, std::uint8_t{1}}) {
        const auto fixture = support::build_single_function_image(
            support::make_unwind_info(
                1, 4, 0,
                {{2, support::kAllocSmall, 4, 0},
                 {4, support::kSaveXmm128Far, info, 2}}));

        const auto layout = syscall::unwind::read_simple_frame_layout(
            fixture.layout.bytes.data(), fixture.layout.bytes.size(),
            fixture.function);
        SC_REQUIRE(layout.has_value());
        SC_REQUIRE_EQ(static_cast<std::size_t>(0x28), layout->frame_size);
        SC_REQUIRE_EQ(static_cast<std::size_t>(0x28), layout->local_alloc);
        SC_REQUIRE_EQ(static_cast<std::size_t>(0), layout->push_count);
    }
}

SC_TEST_CASE("read_simple_frame_layout rejects a machine frame push") {
    const auto fixture = support::build_single_function_image(
        support::make_unwind_info(
            1, 4, 0,
            {{2, support::kAllocSmall, 4, 0},
             {4, support::kPushMachframe, 0, 0}}));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(!layout.has_value());
}

SC_TEST_CASE("read_simple_frame_layout rejects an unknown version") {
    const auto fixture = support::build_single_function_image(
        support::make_unwind_info(
            2, 4, 0, {{4, support::kAllocSmall, 4, 0}}));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(!layout.has_value());
}

SC_TEST_CASE("read_simple_frame_layout rejects a nonzero frame offset") {
    const auto fixture = support::build_single_function_image(
        support::make_unwind_info(
            1, 4, 0x10, {{4, support::kAllocSmall, 4, 0}}));

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(!layout.has_value());
}

SC_TEST_CASE("read_simple_frame_layout rejects truncated unwind codes") {
    const std::vector<std::uint8_t> info{1, 4, 1, 0};
    const auto fixture = support::build_single_function_image(info);

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(!layout.has_value());
}

SC_TEST_CASE("read_simple_frame_layout rejects missing operand slots") {
    const std::vector<std::uint8_t> info{
        1, 4, 1, 0, 4,
        static_cast<std::uint8_t>((1 << 4) | support::kAllocLarge)};
    const auto fixture = support::build_single_function_image(info);

    const auto layout = syscall::unwind::read_simple_frame_layout(
        fixture.layout.bytes.data(), fixture.layout.bytes.size(),
        fixture.function);
    SC_REQUIRE(!layout.has_value());
}
