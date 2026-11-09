#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace support {

struct SectionSpec {
    std::string name;
    std::uint32_t characteristics;
    std::vector<std::uint8_t> data;
};

struct Layout {
    std::vector<std::uint8_t> bytes;
    std::uint32_t nt_offset = 0;
    std::uint32_t export_rva = 0;
    std::uint32_t functions_rva = 0;
    std::uint32_t names_rva = 0;
    std::uint32_t ordinals_rva = 0;
    std::vector<std::uint32_t> stub_rvas;
    std::vector<std::uint32_t> name_rvas;
    std::vector<std::uint32_t> section_rvas;
};

class ImageBuilder {
public:
    static constexpr std::uint32_t kDefaultNtOffset = 0x80;
    static constexpr std::uint32_t kStubStride = 16;

    ImageBuilder& add_clean_export(std::string name, std::uint32_t ssn);
    ImageBuilder& add_hooked_export(std::string name);
    ImageBuilder& add_section(SectionSpec section);
    ImageBuilder& with_nt_offset(std::uint32_t offset);
    ImageBuilder& with_image_size(std::uint32_t size);
    Layout build() const;

private:
    struct Entry {
        std::string name;
        std::optional<std::uint32_t> ssn;
    };

    void write_name_strings(
        std::vector<std::uint8_t>& bytes,
        const std::vector<std::uint32_t>& name_offsets) const;
    void write_stubs(std::vector<std::uint8_t>& bytes, const Layout& layout) const;
    void write_section_data(std::vector<std::uint8_t>& bytes, const Layout& layout) const;

    std::vector<Entry> entries_;
    std::vector<SectionSpec> sections_;
    std::uint32_t nt_offset_ = kDefaultNtOffset;
    std::optional<std::uint32_t> image_size_;
};

void write_u16_at(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value);
void write_u32_at(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value);

}
