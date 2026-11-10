#include "test_harness.hpp"
#include "unwind_fixture.hpp"

#include "syscall/unwind.hpp"

#include <cstdint>
#include <optional>

namespace {

std::optional<std::uint8_t> read_prolog(const support::UnwindFixture& image) {
    return syscall::unwind::read_rbp_prolog_size(
        image.layout.bytes.data(), image.layout.bytes.size(), image.function);
}

}

SC_TEST_CASE("read_rbp_prolog_size accepts a canonical rbp frame") {
    const auto image = support::build_single_function_image(
        support::canonical_rbp_unwind());
    const auto prolog = read_prolog(image);
    SC_REQUIRE(prolog.has_value());
    SC_REQUIRE_EQ(8, static_cast<int>(*prolog));
}

SC_TEST_CASE("read_rbp_prolog_size rejects a missing frame register") {
    const auto info = support::make_unwind_info(1, 8, 0, support::canonical_rbp_codes());
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a nonzero frame offset") {
    const auto info = support::make_unwind_info(
        1, 8, static_cast<std::uint8_t>(support::kRbp | (1 << 4)),
        support::canonical_rbp_codes());
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects chained unwind info") {
    const auto info = support::make_unwind_info(
        1 | 0x20, 8, support::kRbp, support::canonical_rbp_codes());
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects an unknown version") {
    const auto info = support::make_unwind_info(
        2, 8, support::kRbp, support::canonical_rbp_codes());
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a missing set fpreg") {
    const auto info = support::make_unwind_info(
        1, 8, support::kRbp,
        {{4, support::kAllocSmall, 3, 0},
         {0, support::kPushNonvol, support::kRbp, 0}});
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a missing rbp push") {
    const auto info = support::make_unwind_info(
        1, 8, support::kRbp,
        {{4, support::kAllocSmall, 3, 0}, {1, support::kSetFpreg, 0, 0}});
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a push after the frame setup") {
    const auto info = support::make_unwind_info(
        1, 8, support::kRbp,
        {{4, support::kAllocSmall, 3, 0},
         {2, support::kPushNonvol, support::kRbp, 0},
         {1, support::kSetFpreg, 0, 0}});
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a duplicate rbp push") {
    const auto info = support::make_unwind_info(
        1, 8, support::kRbp,
        {{4, support::kAllocSmall, 3, 0},
         {2, support::kPushNonvol, support::kRbp, 0},
         {1, support::kSetFpreg, 0, 0},
         {0, support::kPushNonvol, support::kRbp, 0}});
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects another pushed register") {
    const auto info = support::make_unwind_info(
        1, 8, support::kRbp,
        {{4, support::kAllocSmall, 3, 0},
         {2, support::kSetFpreg, 0, 0},
         {1, support::kPushNonvol, support::kRbp, 0},
         {0, support::kPushNonvol, 3, 0}});
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a machine frame push") {
    const auto info = support::make_unwind_info(
        1, 8, support::kRbp,
        {{8, support::kPushMachframe, 0, 0},
         {4, support::kAllocSmall, 3, 0},
         {1, support::kSetFpreg, 0, 0},
         {0, support::kPushNonvol, support::kRbp, 0}});
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects an allocation before the frame") {
    const auto info = support::make_unwind_info(
        1, 8, support::kRbp,
        {{2, support::kSetFpreg, 0, 0},
         {1, support::kAllocSmall, 3, 0},
         {0, support::kPushNonvol, support::kRbp, 0}});
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a nonvolatile save of rbp") {
    const auto info = support::make_unwind_info(
        1, 8, support::kRbp,
        {{4, support::kAllocSmall, 3, 0},
         {2, support::kSaveNonvol, support::kRbp, 1},
         {1, support::kSetFpreg, 0, 0},
         {0, support::kPushNonvol, support::kRbp, 0}});
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a frame setup outside the prolog") {
    const auto info =
        support::make_unwind_info(1, 1, support::kRbp, support::canonical_rbp_codes());
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size walks extra operation slots") {
    const auto info = support::make_unwind_info(
        1, 16, support::kRbp,
        {{12, support::kAllocLarge, 1, 2},
         {8, support::kSaveXmm128Far, 3, 2},
         {4, support::kSaveNonvol, 1, 1},
         {1, support::kSetFpreg, 0, 0},
         {0, support::kPushNonvol, support::kRbp, 0}});
    const auto prolog = read_prolog(support::build_single_function_image(info));
    SC_REQUIRE(prolog.has_value());
    SC_REQUIRE_EQ(16, static_cast<int>(*prolog));
}

SC_TEST_CASE("read_rbp_prolog_size rejects an unknown operation") {
    const auto info = support::make_unwind_info(
        1, 8, support::kRbp,
        {{4, 7, 0, 0},
         {1, support::kSetFpreg, 0, 0},
         {0, support::kPushNonvol, support::kRbp, 0}});
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a truncated code array") {
    auto info = support::canonical_rbp_unwind();
    info.resize(6);
    SC_REQUIRE(!read_prolog(support::build_single_function_image(info)).has_value());
}

SC_TEST_CASE("read_rbp_prolog_size rejects a truncated header") {
    SC_REQUIRE(
        !read_prolog(support::build_single_function_image({1, 8})).has_value());
}
