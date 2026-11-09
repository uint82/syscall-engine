#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>

namespace syscall::pe {

inline constexpr std::uint16_t kDosSignature = 0x5A4D;
inline constexpr std::uint32_t kNtSignature = 0x00004550;
inline constexpr std::uint16_t kPe32PlusMagic = 0x020B;
inline constexpr std::uint16_t kAmd64Machine = 0x8664;
inline constexpr std::size_t kExportDirectoryIndex = 0;
inline constexpr std::size_t kDataDirectoryCount = 16;
inline constexpr std::uint32_t kSectionExecute = 0x20000000;

static_assert(std::endian::native == std::endian::little);

struct DosHeader {
    std::uint16_t signature;
    std::uint8_t reserved[58];
    std::int32_t nt_offset;
};

static_assert(sizeof(DosHeader) == 64);
static_assert(offsetof(DosHeader, nt_offset) == 60);

struct FileHeader {
    std::uint16_t machine;
    std::uint16_t section_count;
    std::uint32_t timestamp;
    std::uint32_t symbol_table_offset;
    std::uint32_t symbol_count;
    std::uint16_t optional_header_size;
    std::uint16_t characteristics;
};

static_assert(sizeof(FileHeader) == 20);

struct DataDirectory {
    std::uint32_t rva;
    std::uint32_t size;
};

static_assert(sizeof(DataDirectory) == 8);

struct OptionalHeader64 {
    std::uint16_t magic;
    std::uint8_t linker_major;
    std::uint8_t linker_minor;
    std::uint32_t code_size;
    std::uint32_t initialized_data_size;
    std::uint32_t uninitialized_data_size;
    std::uint32_t entry_point_rva;
    std::uint32_t code_rva;
    std::uint64_t image_base;
    std::uint32_t section_alignment;
    std::uint32_t file_alignment;
    std::uint16_t os_major;
    std::uint16_t os_minor;
    std::uint16_t image_major;
    std::uint16_t image_minor;
    std::uint16_t subsystem_major;
    std::uint16_t subsystem_minor;
    std::uint32_t win32_version;
    std::uint32_t image_size;
    std::uint32_t headers_size;
    std::uint32_t checksum;
    std::uint16_t subsystem;
    std::uint16_t dll_characteristics;
    std::uint64_t stack_reserve;
    std::uint64_t stack_commit;
    std::uint64_t heap_reserve;
    std::uint64_t heap_commit;
    std::uint32_t loader_flags;
    std::uint32_t rva_count;
    DataDirectory directories[kDataDirectoryCount];
};

static_assert(sizeof(OptionalHeader64) == 240);
static_assert(offsetof(OptionalHeader64, rva_count) == 108);
static_assert(offsetof(OptionalHeader64, directories) == 112);

struct NtHeaders64 {
    std::uint32_t signature;
    FileHeader file_header;
    OptionalHeader64 optional;
};

static_assert(sizeof(NtHeaders64) == 264);

struct ExportDirectory {
    std::uint32_t characteristics;
    std::uint32_t timestamp;
    std::uint16_t major_version;
    std::uint16_t minor_version;
    std::uint32_t name_rva;
    std::uint32_t base_ordinal;
    std::uint32_t function_count;
    std::uint32_t name_count;
    std::uint32_t functions_rva;
    std::uint32_t names_rva;
    std::uint32_t ordinals_rva;
};

static_assert(sizeof(ExportDirectory) == 40);

struct SectionHeader {
    char name[8];
    std::uint32_t virtual_size;
    std::uint32_t virtual_address;
    std::uint32_t raw_size;
    std::uint32_t raw_offset;
    std::uint32_t relocation_offset;
    std::uint32_t line_offset;
    std::uint16_t relocation_count;
    std::uint16_t line_count;
    std::uint32_t characteristics;
};

static_assert(sizeof(SectionHeader) == 40);

}
