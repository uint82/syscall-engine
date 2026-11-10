#include "test_harness.hpp"
#include "unwind_fixture.hpp"

#include "syscall/pe_types.hpp"
#include "syscall/unwind.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace {

std::optional<std::uint8_t> read_prolog(const support::UnwindFixture& image) {
    return syscall::unwind::read_rbp_prolog_size(
        image.layout.bytes.data(), image.layout.bytes.size(), image.function);
}

}

SC_TEST_CASE("read_runtime_functions returns an empty table without a directory") {
    support::ImageBuilder builder;
    builder.add_section({"text", support::kCodeSection, {0x90}});
    const auto layout = builder.build();

    const auto functions = syscall::unwind::read_runtime_functions(
        layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(functions.has_value());
    SC_REQUIRE(functions->empty());
}

SC_TEST_CASE("read_runtime_functions sorts entries by begin rva") {
    const auto layout = support::build_two_function_image(false);
    const auto functions = syscall::unwind::read_runtime_functions(
        layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(functions.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(2), functions->size());
    SC_REQUIRE_EQ(layout.section_rvas[0], (*functions)[0].begin_rva);
    SC_REQUIRE_EQ(layout.section_rvas[0] + 0x20, (*functions)[1].begin_rva);
}

SC_TEST_CASE("read_runtime_functions rejects a misaligned directory size") {
    auto layout = support::build_single_function_image(
        support::canonical_rbp_unwind()).layout;
    SC_REQUIRE(support::patch_data_directory(
        layout.bytes, layout, syscall::pe::kExceptionDirectoryIndex,
        layout.section_rvas[1], support::kRuntimeFunctionSize + 1));

    SC_REQUIRE(!syscall::unwind::read_runtime_functions(
                    layout.bytes.data(), layout.bytes.size())
                    .has_value());
}

SC_TEST_CASE("read_runtime_functions rejects an entry outside the image") {
    auto fixture = support::build_single_function_image(
        support::canonical_rbp_unwind());
    support::patch_runtime_function(
        fixture.layout,
        {fixture.layout.section_rvas[0], 0xFFFFFF, fixture.layout.section_rvas[2]});

    SC_REQUIRE(!syscall::unwind::read_runtime_functions(
                    fixture.layout.bytes.data(), fixture.layout.bytes.size())
                    .has_value());
}

SC_TEST_CASE("read_runtime_functions rejects unwind info outside the image") {
    auto fixture = support::build_single_function_image(
        support::canonical_rbp_unwind());
    support::patch_runtime_function(
        fixture.layout,
        {fixture.layout.section_rvas[0],
         fixture.layout.section_rvas[0] + support::kFunctionSize, 0xFFFFFF});

    SC_REQUIRE(!syscall::unwind::read_runtime_functions(
                    fixture.layout.bytes.data(), fixture.layout.bytes.size())
                    .has_value());
}

SC_TEST_CASE("read_runtime_functions rejects a zero unwind info rva") {
    auto fixture = support::build_single_function_image(
        support::canonical_rbp_unwind());
    support::patch_runtime_function(
        fixture.layout,
        {fixture.layout.section_rvas[0],
         fixture.layout.section_rvas[0] + support::kFunctionSize, 0});

    SC_REQUIRE(!syscall::unwind::read_runtime_functions(
                    fixture.layout.bytes.data(), fixture.layout.bytes.size())
                    .has_value());
}

SC_TEST_CASE("read_runtime_functions rejects overlapping entries") {
    const auto layout = support::build_two_function_image(true);
    SC_REQUIRE(!syscall::unwind::read_runtime_functions(
                    layout.bytes.data(), layout.bytes.size())
                    .has_value());
}

SC_TEST_CASE("find_runtime_function locates covered rvas") {
    const auto layout = support::build_two_function_image(false);
    const auto functions = syscall::unwind::read_runtime_functions(
        layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(functions.has_value());

    const auto text = layout.section_rvas[0];
    const auto first = syscall::unwind::find_runtime_function(*functions, text);
    const auto last =
        syscall::unwind::find_runtime_function(*functions, text + 0x3F);
    const auto between =
        syscall::unwind::find_runtime_function(*functions, text + 0x20);
    const auto outside =
        syscall::unwind::find_runtime_function(*functions, text + 0x40);
    const auto before = syscall::unwind::find_runtime_function(*functions, text - 1);

    SC_REQUIRE(first.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(0), *first);
    SC_REQUIRE(last.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(1), *last);
    SC_REQUIRE(between.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(1), *between);
    SC_REQUIRE(!outside.has_value());
    SC_REQUIRE(!before.has_value());
}

SC_TEST_CASE("find_runtime_function returns nothing for an empty table") {
    const std::vector<syscall::unwind::RuntimeFunction> functions;
    SC_REQUIRE(
        !syscall::unwind::find_runtime_function(functions, 0x1000).has_value());
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
