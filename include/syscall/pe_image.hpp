#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "syscall/pe_types.hpp"

namespace syscall::pe {

struct Export {
    std::uint32_t rva;
    std::string_view name;
};

std::optional<std::size_t> read_nt_offset(const std::uint8_t* image, std::size_t size);
std::optional<std::uint32_t> read_export_directory_rva(const std::uint8_t* image, std::size_t size);
std::optional<std::size_t> read_image_size(const std::uint8_t* image, std::size_t size);
std::optional<std::vector<SectionHeader>> read_sections(
    const std::uint8_t* image,
    std::size_t size);
std::optional<std::vector<Export>> read_exports(const std::uint8_t* image, std::size_t size);
std::optional<std::size_t> find_export(
    const std::vector<Export>& exports,
    std::string_view name);
std::optional<std::size_t> find_export_hashed(
    const std::vector<Export>& exports,
    std::uint64_t hash);

}
