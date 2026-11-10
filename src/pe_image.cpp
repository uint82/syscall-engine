#include "syscall/pe_image.hpp"

#include "pe_reader.hpp"
#include "syscall/hash.hpp"
#include "syscall/pe_types.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>

namespace syscall::pe {
namespace {

struct ParsedHeaders {
    std::size_t nt_offset;
    NtHeaders64 headers;
};

template <typename T>
std::optional<T> read_array_element(
    const std::uint8_t* image,
    std::size_t size,
    std::uint32_t array_rva,
    std::uint32_t index) {
    const auto offset = static_cast<std::size_t>(array_rva) +
                        static_cast<std::size_t>(index) * sizeof(T);
    return read_struct<T>(image, size, offset);
}

std::optional<std::string_view> read_c_string(
    const std::uint8_t* image,
    std::size_t size,
    std::uint32_t rva) {
    if (rva >= size) {
        return std::nullopt;
    }
    const auto* begin = reinterpret_cast<const char*>(image + rva);
    const auto* end = static_cast<const char*>(std::memchr(begin, '\0', size - rva));
    if (end == nullptr) {
        return std::nullopt;
    }
    return std::string_view(begin, static_cast<std::size_t>(end - begin));
}

std::optional<ParsedHeaders> parse_headers(const std::uint8_t* image, std::size_t size) {
    const auto nt_offset = read_nt_offset(image, size);
    if (!nt_offset.has_value()) {
        return std::nullopt;
    }
    const auto nt = read_struct<NtHeaders64>(image, size, *nt_offset);
    if (!nt.has_value() || nt->signature != kNtSignature) {
        return std::nullopt;
    }
    if (nt->optional.magic != kPe32PlusMagic) {
        return std::nullopt;
    }
    return ParsedHeaders{*nt_offset, *nt};
}

std::optional<OptionalHeader64> read_optional_header(
    const std::uint8_t* image,
    std::size_t size) {
    const auto parsed = parse_headers(image, size);
    if (!parsed.has_value()) {
        return std::nullopt;
    }
    return parsed->headers.optional;
}

std::optional<ExportDirectory> read_export_directory(
    const std::uint8_t* image,
    std::size_t size) {
    const auto rva = read_export_directory_rva(image, size);
    if (!rva.has_value()) {
        return std::nullopt;
    }
    return read_struct<ExportDirectory>(image, size, *rva);
}

std::optional<Export> read_export(
    const std::uint8_t* image,
    std::size_t size,
    const ExportDirectory& directory,
    std::uint32_t index) {
    const auto name_rva =
        read_array_element<std::uint32_t>(image, size, directory.names_rva, index);
    const auto ordinal =
        read_array_element<std::uint16_t>(image, size, directory.ordinals_rva, index);
    if (!name_rva.has_value() || !ordinal.has_value()) {
        return std::nullopt;
    }
    if (*ordinal >= directory.function_count) {
        return std::nullopt;
    }
    // TODO: skip forwarded exports whose RVA falls inside the export directory.
    const auto function_rva = read_array_element<std::uint32_t>(
        image, size, directory.functions_rva, *ordinal);
    if (!function_rva.has_value()) {
        return std::nullopt;
    }
    const auto name = read_c_string(image, size, *name_rva);
    if (!name.has_value()) {
        return std::nullopt;
    }
    return Export{*function_rva, *name};
}

template <typename Matcher>
std::optional<std::size_t> find_export_if(
    const std::vector<Export>& exports,
    Matcher matches) {
    const auto match = std::find_if(exports.begin(), exports.end(), matches);
    if (match == exports.end()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(exports.begin(), match));
}

}

std::optional<std::size_t> read_nt_offset(const std::uint8_t* image, std::size_t size) {
    if (image == nullptr) {
        return std::nullopt;
    }
    const auto dos = read_struct<DosHeader>(image, size, 0);
    if (!dos.has_value() || dos->signature != kDosSignature || dos->nt_offset < 0) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(dos->nt_offset);
}

std::optional<DataDirectory> read_data_directory(
    const std::uint8_t* image,
    std::size_t size,
    std::size_t index) {
    const auto optional = read_optional_header(image, size);
    if (!optional.has_value() || index >= optional->rva_count) {
        return std::nullopt;
    }
    return optional->directories[index];
}

std::optional<std::uint32_t> read_export_directory_rva(
    const std::uint8_t* image,
    std::size_t size) {
    const auto directory = read_data_directory(image, size, kExportDirectoryIndex);
    if (!directory.has_value()) {
        return std::nullopt;
    }
    return directory->rva;
}

std::optional<std::size_t> read_image_size(const std::uint8_t* image, std::size_t size) {
    const auto optional = read_optional_header(image, size);
    if (!optional.has_value()) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(optional->image_size);
}

std::optional<std::vector<SectionHeader>> read_sections(
    const std::uint8_t* image,
    std::size_t size) {
    const auto parsed = parse_headers(image, size);
    if (!parsed.has_value()) {
        return std::nullopt;
    }

    // The section table follows the optional header. SizeOfOptionalHeader
    // gives the header size.
    const std::size_t table = parsed->nt_offset + offsetof(NtHeaders64, optional) +
                              parsed->headers.file_header.optional_header_size;
    std::vector<SectionHeader> sections;
    sections.reserve(parsed->headers.file_header.section_count);
    for (std::uint16_t index = 0; index < parsed->headers.file_header.section_count;
         ++index) {
        const auto section = read_struct<SectionHeader>(
            image, size, table + static_cast<std::size_t>(index) * sizeof(SectionHeader));
        if (!section.has_value()) {
            return std::nullopt;
        }
        sections.push_back(*section);
    }
    return sections;
}

std::optional<std::vector<Export>> read_exports(
    const std::uint8_t* image,
    std::size_t size) {
    const auto directory = read_export_directory(image, size);
    if (!directory.has_value()) {
        return std::nullopt;
    }

    std::vector<Export> exports;
    exports.reserve(directory->name_count);
    for (std::uint32_t index = 0; index < directory->name_count; ++index) {
        const auto entry = read_export(image, size, *directory, index);
        if (!entry.has_value()) {
            return std::nullopt;
        }
        exports.push_back(*entry);
    }

    std::sort(exports.begin(), exports.end(),
              [](const Export& left, const Export& right) {
                  return left.rva < right.rva;
              });
    return exports;
}

std::optional<std::size_t> find_export(
    const std::vector<Export>& exports,
    std::string_view name) {
    return find_export_if(
        exports, [name](const Export& entry) { return entry.name == name; });
}

std::optional<std::size_t> find_export_hashed(
    const std::vector<Export>& exports,
    std::uint64_t hash) {
    return find_export_if(
        exports, [hash](const Export& entry) { return fnv1a(entry.name) == hash; });
}

}
