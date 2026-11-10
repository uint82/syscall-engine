#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace syscall::unwind {

struct RuntimeFunction {
    std::uint32_t begin_rva;
    std::uint32_t end_rva;
    std::uint32_t unwind_info_rva;
};

static_assert(sizeof(RuntimeFunction) == 12);

std::optional<std::vector<RuntimeFunction>> read_runtime_functions(
    const std::uint8_t* image,
    std::size_t size);
std::optional<std::size_t> find_runtime_function(
    const std::vector<RuntimeFunction>& functions,
    std::uint32_t rva);
std::optional<std::uint8_t> read_rbp_prolog_size(
    const std::uint8_t* image,
    std::size_t size,
    const RuntimeFunction& function);
bool is_leaf_function(
    const std::uint8_t* image,
    std::size_t size,
    const RuntimeFunction& function);

}
