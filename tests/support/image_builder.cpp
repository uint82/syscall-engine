#include "image_builder.hpp"

#include "syscall/pe_types.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <utility>

namespace support {
namespace {

using syscall::pe::DosHeader;
using syscall::pe::ExportDirectory;
using syscall::pe::FileHeader;
using syscall::pe::NtHeaders64;
using syscall::pe::OptionalHeader64;
using syscall::pe::SectionHeader;

constexpr std::size_t kStubBytes = 12;
constexpr std::uint32_t kSectionAlignment = 16;

std::array<std::uint8_t, kStubBytes> make_clean_stub(std::uint32_t ssn) {
    std::array<std::uint8_t, kStubBytes> stub{};
    stub[0] = 0x4C;
    stub[1] = 0x8B;
    stub[2] = 0xD1;
    stub[3] = 0xB8;
    std::memcpy(stub.data() + 4, &ssn, sizeof(ssn));
    stub[8] = 0x0F;
    stub[9] = 0x05;
    stub[10] = 0xC3;
    stub[11] = 0xCC;
    return stub;
}

std::array<std::uint8_t, kStubBytes> make_hooked_stub() {
    std::array<std::uint8_t, kStubBytes> stub{};
    stub.fill(0x90);
    stub[0] = 0xE9;
    return stub;
}

std::uint32_t align_up(std::uint32_t value, std::uint32_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

void write_dos_header(std::vector<std::uint8_t>& bytes, std::uint32_t nt_offset) {
    write_u16_at(bytes, 0, syscall::pe::kDosSignature);
    write_u32_at(bytes, offsetof(DosHeader, nt_offset), nt_offset);
}

void write_file_header(
    std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::uint16_t section_count) {
    write_u16_at(bytes, offset + offsetof(FileHeader, machine), syscall::pe::kAmd64Machine);
    write_u16_at(bytes, offset + offsetof(FileHeader, section_count), section_count);
    write_u16_at(bytes, offset + offsetof(FileHeader, optional_header_size),
                 sizeof(OptionalHeader64));
}

void write_optional_header(
    std::vector<std::uint8_t>& bytes,
    std::size_t offset,
    std::uint32_t image_size,
    std::uint32_t export_rva) {
    write_u16_at(bytes, offset + offsetof(OptionalHeader64, magic),
                 syscall::pe::kPe32PlusMagic);
    write_u32_at(bytes, offset + offsetof(OptionalHeader64, image_size), image_size);
    write_u32_at(bytes, offset + offsetof(OptionalHeader64, rva_count),
                 syscall::pe::kDataDirectoryCount);
    const std::size_t directories = offset + offsetof(OptionalHeader64, directories);
    write_u32_at(bytes, directories, export_rva);
    write_u32_at(bytes, directories + sizeof(std::uint32_t), sizeof(ExportDirectory));
}

void write_nt_headers(
    std::vector<std::uint8_t>& bytes,
    const Layout& layout,
    std::uint32_t image_size,
    std::uint16_t section_count) {
    write_u32_at(bytes, layout.nt_offset, syscall::pe::kNtSignature);
    const std::size_t file_header = layout.nt_offset + sizeof(std::uint32_t);
    write_file_header(bytes, file_header, section_count);
    const std::size_t optional = file_header + sizeof(FileHeader);
    write_optional_header(bytes, optional, image_size, layout.export_rva);
}

void write_export_directory(
    std::vector<std::uint8_t>& bytes,
    const Layout& layout,
    std::uint32_t count) {
    const std::size_t offset = layout.export_rva;
    write_u32_at(bytes, offset + offsetof(ExportDirectory, function_count), count);
    write_u32_at(bytes, offset + offsetof(ExportDirectory, name_count), count);
    write_u32_at(bytes, offset + offsetof(ExportDirectory, functions_rva),
                 layout.functions_rva);
    write_u32_at(bytes, offset + offsetof(ExportDirectory, names_rva), layout.names_rva);
    write_u32_at(bytes, offset + offsetof(ExportDirectory, ordinals_rva),
                 layout.ordinals_rva);
}

void write_export_tables(
    std::vector<std::uint8_t>& bytes,
    const Layout& layout,
    const std::vector<std::uint32_t>& name_offsets) {
    for (std::uint32_t index = 0; index < name_offsets.size(); ++index) {
        write_u32_at(bytes, layout.names_rva + index * sizeof(std::uint32_t),
                     name_offsets[index]);
        write_u16_at(bytes, layout.ordinals_rva + index * sizeof(std::uint16_t),
                     static_cast<std::uint16_t>(index));
        write_u32_at(bytes, layout.functions_rva + index * sizeof(std::uint32_t),
                     layout.stub_rvas[index]);
    }
}

void write_section_table(
    std::vector<std::uint8_t>& bytes,
    const Layout& layout,
    const std::vector<SectionSpec>& sections) {
    std::size_t offset = layout.nt_offset + sizeof(NtHeaders64);
    for (std::size_t index = 0; index < sections.size(); ++index) {
        SectionHeader header{};
        const auto& spec = sections[index];
        std::memcpy(header.name, spec.name.data(),
                    std::min(spec.name.size(), sizeof(header.name)));
        header.virtual_size = static_cast<std::uint32_t>(spec.data.size());
        header.virtual_address = layout.section_rvas[index];
        header.raw_size = static_cast<std::uint32_t>(spec.data.size());
        header.characteristics = spec.characteristics;
        std::memcpy(bytes.data() + offset, &header, sizeof(header));
        offset += sizeof(header);
    }
}

} // namespace

void write_u16_at(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

void write_u32_at(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint32_t value) {
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

bool patch_data_directory(
    std::vector<std::uint8_t>& bytes,
    const Layout& layout,
    std::size_t index,
    std::uint32_t rva,
    std::uint32_t size) {
    const std::size_t optional =
        layout.nt_offset + sizeof(std::uint32_t) + sizeof(syscall::pe::FileHeader);
    const std::size_t directory =
        optional + offsetof(syscall::pe::OptionalHeader64, directories) +
        index * sizeof(syscall::pe::DataDirectory);
    if (index >= syscall::pe::kDataDirectoryCount || directory > bytes.size() ||
        bytes.size() - directory < sizeof(syscall::pe::DataDirectory)) {
        return false;
    }
    write_u32_at(bytes, directory, rva);
    write_u32_at(bytes, directory + sizeof(std::uint32_t), size);
    return true;
}

ImageBuilder& ImageBuilder::add_clean_export(std::string name, std::uint32_t ssn) {
    entries_.push_back({std::move(name), ssn});
    return *this;
}

ImageBuilder& ImageBuilder::add_hooked_export(std::string name) {
    entries_.push_back({std::move(name), std::nullopt});
    return *this;
}

ImageBuilder& ImageBuilder::add_section(SectionSpec section) {
    sections_.push_back(std::move(section));
    return *this;
}

ImageBuilder& ImageBuilder::with_nt_offset(std::uint32_t offset) {
    nt_offset_ = offset;
    return *this;
}

ImageBuilder& ImageBuilder::with_image_size(std::uint32_t size) {
    image_size_ = size;
    return *this;
}

Layout ImageBuilder::build() const {
    Layout layout;
    layout.nt_offset = nt_offset_;

    const auto section_count = static_cast<std::uint32_t>(sections_.size());
    const std::size_t section_table = nt_offset_ + sizeof(NtHeaders64);
    layout.export_rva =
        static_cast<std::uint32_t>(section_table) +
        section_count * static_cast<std::uint32_t>(sizeof(SectionHeader));
    layout.functions_rva =
        layout.export_rva + static_cast<std::uint32_t>(sizeof(ExportDirectory));

    const auto count = static_cast<std::uint32_t>(entries_.size());
    layout.names_rva =
        layout.functions_rva + count * static_cast<std::uint32_t>(sizeof(std::uint32_t));
    layout.ordinals_rva =
        layout.names_rva + count * static_cast<std::uint32_t>(sizeof(std::uint32_t));

    std::uint32_t cursor =
        layout.ordinals_rva + count * static_cast<std::uint32_t>(sizeof(std::uint16_t));
    std::vector<std::uint32_t> name_offsets;
    name_offsets.reserve(entries_.size());
    for (const auto& entry : entries_) {
        name_offsets.push_back(cursor);
        cursor += static_cast<std::uint32_t>(entry.name.size() + 1);
    }

    layout.stub_rvas.reserve(entries_.size());
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        layout.stub_rvas.push_back(cursor);
        cursor += kStubStride;
    }

    layout.section_rvas.reserve(sections_.size());
    for (const auto& section : sections_) {
        cursor = align_up(cursor, kSectionAlignment);
        layout.section_rvas.push_back(cursor);
        cursor += static_cast<std::uint32_t>(section.data.size());
    }

    const std::uint32_t total = std::max(image_size_.value_or(cursor), cursor);
    layout.bytes.assign(total, 0);

    write_dos_header(layout.bytes, nt_offset_);
    write_nt_headers(layout.bytes, layout, total,
                     static_cast<std::uint16_t>(sections_.size()));
    write_section_table(layout.bytes, layout, sections_);
    write_export_directory(layout.bytes, layout, count);
    write_export_tables(layout.bytes, layout, name_offsets);
    write_name_strings(layout.bytes, name_offsets);
    write_stubs(layout.bytes, layout);
    write_section_data(layout.bytes, layout);

    layout.name_rvas = name_offsets;
    return layout;
}

void ImageBuilder::write_name_strings(
    std::vector<std::uint8_t>& bytes,
    const std::vector<std::uint32_t>& name_offsets) const {
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        const auto& name = entries_[index].name;
        std::memcpy(bytes.data() + name_offsets[index], name.c_str(), name.size() + 1);
    }
}

void ImageBuilder::write_stubs(std::vector<std::uint8_t>& bytes, const Layout& layout) const {
    for (std::size_t index = 0; index < entries_.size(); ++index) {
        const auto stub = entries_[index].ssn.has_value()
                              ? make_clean_stub(*entries_[index].ssn)
                              : make_hooked_stub();
        std::memcpy(bytes.data() + layout.stub_rvas[index], stub.data(), stub.size());
    }
}

void ImageBuilder::write_section_data(
    std::vector<std::uint8_t>& bytes,
    const Layout& layout) const {
    for (std::size_t index = 0; index < sections_.size(); ++index) {
        const auto& data = sections_[index].data;
        if (data.empty()) {
            continue;
        }
        std::memcpy(bytes.data() + layout.section_rvas[index], data.data(), data.size());
    }
}

} // namespace support
