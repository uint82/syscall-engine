#include "image_builder.hpp"
#include "test_harness.hpp"

#include "syscall/hash.hpp"
#include "syscall/pe_image.hpp"
#include "syscall/pe_types.hpp"

#include <cstddef>
#include <cstring>

namespace {

support::ImageBuilder two_export_builder() {
    support::ImageBuilder builder;
    builder.add_clean_export("NtAlpha", 10);
    builder.add_clean_export("NtBeta", 11);
    return builder;
}

std::size_t optional_header_offset(const support::Layout& layout) {
    return layout.nt_offset + sizeof(std::uint32_t) + sizeof(syscall::pe::FileHeader);
}

}

SC_TEST_CASE("read_nt_offset returns the configured offset") {
    const auto layout = two_export_builder().build();
    const auto offset = syscall::pe::read_nt_offset(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(offset.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(layout.nt_offset), *offset);
}

SC_TEST_CASE("read_nt_offset rejects an invalid dos signature") {
    auto layout = two_export_builder().build();
    layout.bytes[0] = 0x00;
    SC_REQUIRE(!syscall::pe::read_nt_offset(layout.bytes.data(), layout.bytes.size()).has_value());
}

SC_TEST_CASE("read_nt_offset rejects an empty image") {
    SC_REQUIRE(!syscall::pe::read_nt_offset(nullptr, 0).has_value());
}

SC_TEST_CASE("read_export_directory_rva returns the configured rva") {
    const auto layout = two_export_builder().build();
    const auto rva =
        syscall::pe::read_export_directory_rva(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(rva.has_value());
    SC_REQUIRE_EQ(layout.export_rva, *rva);
}

SC_TEST_CASE("read_export_directory_rva rejects a corrupted nt signature") {
    auto layout = two_export_builder().build();
    support::write_u32_at(layout.bytes, layout.nt_offset, 0);
    SC_REQUIRE(
        !syscall::pe::read_export_directory_rva(layout.bytes.data(), layout.bytes.size())
             .has_value());
}

SC_TEST_CASE("read_export_directory_rva rejects a non pe32 plus image") {
    auto layout = two_export_builder().build();
    support::write_u16_at(layout.bytes, optional_header_offset(layout), 0x010B);
    SC_REQUIRE(
        !syscall::pe::read_export_directory_rva(layout.bytes.data(), layout.bytes.size())
             .has_value());
}

SC_TEST_CASE("read_export_directory_rva rejects a missing directory entry") {
    auto layout = two_export_builder().build();
    const auto offset = optional_header_offset(layout) +
                        offsetof(syscall::pe::OptionalHeader64, rva_count);
    support::write_u32_at(layout.bytes, offset, 0);
    SC_REQUIRE(
        !syscall::pe::read_export_directory_rva(layout.bytes.data(), layout.bytes.size())
             .has_value());
}

SC_TEST_CASE("read_image_size returns the configured image size") {
    support::ImageBuilder builder;
    builder.add_clean_export("NtAlpha", 10).with_image_size(0x5000);
    const auto layout = builder.build();
    const auto size = syscall::pe::read_image_size(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(size.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(0x5000), *size);
}

SC_TEST_CASE("read_exports returns entries sorted by rva") {
    const auto layout = two_export_builder().build();
    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(exports.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(2), exports->size());
    SC_REQUIRE((*exports)[0].name == "NtAlpha");
    SC_REQUIRE((*exports)[1].name == "NtBeta");
    SC_REQUIRE_EQ(layout.stub_rvas[0], (*exports)[0].rva);
    SC_REQUIRE_EQ(layout.stub_rvas[1], (*exports)[1].rva);
}

SC_TEST_CASE("read_exports accepts an image without exports") {
    const support::ImageBuilder builder;
    const auto layout = builder.build();
    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(exports.has_value());
    SC_REQUIRE(exports->empty());
}

SC_TEST_CASE("read_exports rejects an ordinal outside the function table") {
    auto layout = two_export_builder().build();
    support::write_u16_at(layout.bytes, layout.ordinals_rva, 0xFFFF);
    SC_REQUIRE(!syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size()).has_value());
}

SC_TEST_CASE("read_exports rejects an unterminated name") {
    auto layout = two_export_builder().build();
    std::memset(layout.bytes.data() + layout.name_rvas[0], 0x41,
                layout.bytes.size() - layout.name_rvas[0]);
    SC_REQUIRE(!syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size()).has_value());
}

SC_TEST_CASE("read_exports rejects a truncated export directory") {
    auto layout = two_export_builder().build();
    layout.bytes.resize(layout.export_rva + 10);
    SC_REQUIRE(!syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size()).has_value());
}

SC_TEST_CASE("read_sections returns the configured sections") {
    support::ImageBuilder builder;
    builder.add_section({"code", syscall::pe::kSectionExecute, {0x90, 0x90}});
    const auto layout = builder.build();

    const auto sections = syscall::pe::read_sections(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(sections.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(1), sections->size());
    SC_REQUIRE_EQ(layout.section_rvas[0], (*sections)[0].virtual_address);
    SC_REQUIRE_EQ(static_cast<std::uint32_t>(2), (*sections)[0].virtual_size);
    SC_REQUIRE_EQ(syscall::pe::kSectionExecute, (*sections)[0].characteristics);
}

SC_TEST_CASE("read_sections accepts an image without sections") {
    const support::ImageBuilder builder;
    const auto layout = builder.build();

    const auto sections = syscall::pe::read_sections(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(sections.has_value());
    SC_REQUIRE(sections->empty());
}

SC_TEST_CASE("read_sections rejects a truncated section table") {
    support::ImageBuilder builder;
    builder.add_section({"code", syscall::pe::kSectionExecute, {0x90}});
    auto layout = builder.build();
    layout.bytes.resize(layout.nt_offset + sizeof(syscall::pe::NtHeaders64) + 10);

    SC_REQUIRE(!syscall::pe::read_sections(layout.bytes.data(), layout.bytes.size()).has_value());
}

SC_TEST_CASE("find_export returns the index of a known name") {
    const auto layout = two_export_builder().build();
    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(exports.has_value());

    const auto index = syscall::pe::find_export(*exports, "NtBeta");
    SC_REQUIRE(index.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(1), *index);
}

SC_TEST_CASE("find_export returns nothing for an unknown name") {
    const auto layout = two_export_builder().build();
    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(exports.has_value());
    SC_REQUIRE(!syscall::pe::find_export(*exports, "NtMissing").has_value());
}

SC_TEST_CASE("find_export returns nothing for an empty list") {
    const std::vector<syscall::pe::Export> exports;
    SC_REQUIRE(!syscall::pe::find_export(exports, "NtAlpha").has_value());
}

SC_TEST_CASE("find_export_hashed returns the index of a known name") {
    const auto layout = two_export_builder().build();
    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(exports.has_value());

    const auto index = syscall::pe::find_export_hashed(*exports, SC_HASH("NtBeta"));
    SC_REQUIRE(index.has_value());
    SC_REQUIRE_EQ(static_cast<std::size_t>(1), *index);
}

SC_TEST_CASE("find_export_hashed returns nothing for an unknown name") {
    const auto layout = two_export_builder().build();
    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(exports.has_value());
    SC_REQUIRE(!syscall::pe::find_export_hashed(*exports, SC_HASH("NtMissing")).has_value());
}

SC_TEST_CASE("find_export_hashed is case sensitive") {
    const auto layout = two_export_builder().build();
    const auto exports = syscall::pe::read_exports(layout.bytes.data(), layout.bytes.size());
    SC_REQUIRE(exports.has_value());
    SC_REQUIRE(!syscall::pe::find_export_hashed(*exports, SC_HASH("ntbeta")).has_value());
}
