#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "syscall/pe_image.hpp"

namespace syscall {

bool is_clean_stub(std::span<const std::uint8_t> code);

std::optional<std::uint32_t> resolve_ssn(
    std::span<const std::uint8_t> image,
    const std::vector<pe::Export>& exports,
    std::string_view name);

std::optional<std::uint32_t> resolve_ssn(
    std::span<const std::uint8_t> image,
    const std::vector<pe::Export>& exports,
    std::size_t index);

}
