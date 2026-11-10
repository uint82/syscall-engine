#include "test_harness.hpp"
#include "unwind_fixture.hpp"

#include "syscall/unwind.hpp"

namespace {

bool is_leaf(const support::UnwindFixture& image) {
    return syscall::unwind::is_leaf_function(
        image.layout.bytes.data(), image.layout.bytes.size(), image.function);
}

}

SC_TEST_CASE("is_leaf_function accepts an empty unwind header") {
    const auto info = support::make_unwind_info(1, 0, 0, {});
    SC_REQUIRE(is_leaf(support::build_single_function_image(info)));
}

SC_TEST_CASE("is_leaf_function rejects a frame prolog") {
    SC_REQUIRE(!is_leaf(
        support::build_single_function_image(support::canonical_rbp_unwind())));
}

SC_TEST_CASE("is_leaf_function rejects chained unwind info") {
    const auto info = support::make_unwind_info(0x21, 0, 0, {});
    SC_REQUIRE(!is_leaf(support::build_single_function_image(info)));
}

SC_TEST_CASE("is_leaf_function rejects a newer unwind version") {
    const auto info = support::make_unwind_info(2, 0, 0, {});
    SC_REQUIRE(!is_leaf(support::build_single_function_image(info)));
}

SC_TEST_CASE("is_leaf_function rejects frame register metadata") {
    const auto info = support::make_unwind_info(1, 0, support::kRbp, {});
    SC_REQUIRE(!is_leaf(support::build_single_function_image(info)));
}

SC_TEST_CASE("is_leaf_function rejects a truncated header") {
    SC_REQUIRE(!is_leaf(support::build_single_function_image({1, 0})));
}
