#include "syscall/engine.hpp"

#include "syscall/gadget_finder.hpp"
#include "syscall/ssn_resolver.hpp"
#include "syscall/stub_layout.hpp"
#include "syscall/trampoline.hpp"

#include <windows.h>

#include <bit>
#include <span>
#include <string_view>
#include <utility>

namespace syscall {
namespace {

constexpr std::size_t kTrampolineRegionSize = 0x10000;
constexpr std::size_t kHeaderWindow = 0x1000;
constexpr std::size_t kMaxTrampolines = kTrampolineRegionSize / kTrampolineStride;

static_assert(sizeof(void*) == 8);

}

Engine::~Engine() {
    fresh::unmap_ntdll(fresh_api_, fresh_view_);
    if (trampolines_ != nullptr) {
        VirtualFree(trampolines_, 0, MEM_RELEASE);
    }
}

Status Engine::init(Mode mode) {
    if (live_image_ != nullptr) {
        return record(Status::kAlreadyInitialized);
    }
    if (!load_live_image()) {
        return record(Status::kLiveImageUnavailable);
    }
    if (!load_exports(live_image_, live_size_)) {
        return record(Status::kExportTableUnavailable);
    }
    select_resolution_image();
    if (mode == Mode::kIndirect && !prepare_gadget()) {
        return record(Status::kGadgetNotFound);
    }
    mode_ = mode;
    if (!allocate_trampolines()) {
        return record(Status::kTrampolineAllocationFailed);
    }
    return record(Status::kOk);
}

ImageSource Engine::source() const {
    return source_;
}

Status Engine::last_error() const {
    return last_error_;
}

void* Engine::resolve(const char* name) {
    if (name == nullptr) {
        record(Status::kInvalidArgument);
        return nullptr;
    }
    if (exports_.empty()) {
        record(Status::kNotInitialized);
        return nullptr;
    }
    const auto index = pe::find_export(exports_, name);
    if (!index.has_value()) {
        record(Status::kUnknownExport);
        return nullptr;
    }
    return emit_stub(lookup_ssn(*index));
}

void* Engine::resolve(std::uint64_t hash) {
    if (exports_.empty()) {
        record(Status::kNotInitialized);
        return nullptr;
    }
    const auto index = pe::find_export_hashed(exports_, hash);
    if (!index.has_value()) {
        record(Status::kUnknownExport);
        return nullptr;
    }
    return emit_stub(lookup_ssn(*index));
}

Status Engine::commit() {
    if (trampolines_ == nullptr) {
        return record(Status::kNotInitialized);
    }
    if (is_committed_) {
        return record(Status::kAlreadyCommitted);
    }
    DWORD previous = 0;
    if (VirtualProtect(trampolines_, kTrampolineRegionSize, PAGE_EXECUTE_READ, &previous) == 0) {
        return record(Status::kProtectionFailed);
    }
    is_committed_ = true;
    return record(Status::kOk);
}

Status Engine::record(Status status) {
    last_error_ = status;
    return status;
}

bool Engine::load_live_image() {
    const auto module = GetModuleHandleA("ntdll.dll");
    if (module == nullptr) {
        return false;
    }
    live_image_ = reinterpret_cast<const std::uint8_t*>(module);
    const auto image_size = pe::read_image_size(live_image_, kHeaderWindow);
    if (!image_size.has_value()) {
        return false;
    }
    live_size_ = *image_size;
    return true;
}

bool Engine::load_exports(const std::uint8_t* image, std::size_t size) {
    auto exports = pe::read_exports(image, size);
    if (!exports.has_value()) {
        return false;
    }
    exports_ = std::move(*exports);
    return true;
}

fresh::Api Engine::resolve_fresh_api() const {
    return {
        export_address("NtOpenSection"),
        export_address("NtMapViewOfSection"),
        export_address("NtClose"),
        export_address("NtUnmapViewOfSection"),
    };
}

void* Engine::export_address(std::string_view name) const {
    const auto index = pe::find_export(exports_, name);
    if (!index.has_value()) {
        return nullptr;
    }
    return const_cast<std::uint8_t*>(live_image_ + exports_[*index].rva);
}

void Engine::select_resolution_image() {
    fresh_api_ = resolve_fresh_api();
    fresh_view_ = fresh::map_ntdll(fresh_api_);
    if (fresh_view_.bytes != nullptr && load_exports(fresh_view_.bytes, fresh_view_.size)) {
        ssn_image_ = fresh_view_.bytes;
        ssn_size_ = fresh_view_.size;
        source_ = ImageSource::kFresh;
        return;
    }
    fresh::unmap_ntdll(fresh_api_, fresh_view_);
    ssn_image_ = live_image_;
    ssn_size_ = live_size_;
    source_ = ImageSource::kLive;
}

bool Engine::prepare_gadget() {
    const auto sections = pe::read_sections(live_image_, live_size_);
    if (!sections.has_value()) {
        return false;
    }
    const auto gadget = find_syscall_gadget(
        std::span<const std::uint8_t>(live_image_, live_size_), *sections);
    if (!gadget.has_value()) {
        return false;
    }
    gadget_rva_ = *gadget;
    return true;
}

bool Engine::allocate_trampolines() {
    trampolines_ = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, kTrampolineRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    return trampolines_ != nullptr;
}

std::optional<std::uint32_t> Engine::lookup_ssn(std::size_t index) const {
    return resolve_ssn(
        std::span<const std::uint8_t>(ssn_image_, ssn_size_), exports_, index);
}

void* Engine::emit_stub(std::optional<std::uint32_t> ssn) {
    if (trampolines_ == nullptr) {
        record(Status::kNotInitialized);
        return nullptr;
    }
    if (is_committed_) {
        record(Status::kAlreadyCommitted);
        return nullptr;
    }
    if (!ssn.has_value()) {
        record(Status::kNoSyscallNumber);
        return nullptr;
    }
    if (trampoline_count_ >= kMaxTrampolines) {
        record(Status::kTrampolineExhausted);
        return nullptr;
    }

    auto slot = std::span<std::uint8_t>(
        trampolines_ + trampoline_count_ * kTrampolineStride, kTrampolineStride);
    if (!write_stub(slot, *ssn)) {
        record(Status::kStubWriteFailed);
        return nullptr;
    }
    ++trampoline_count_;
    record(Status::kOk);
    return slot.data();
}

bool Engine::write_stub(std::span<std::uint8_t> slot, std::uint32_t ssn) {
    if (mode_ == Mode::kIndirect) {
        const auto gadget = std::bit_cast<std::uint64_t>(live_image_ + gadget_rva_);
        return write_indirect_stub(slot, ssn, gadget);
    }
    return write_direct_stub(slot, ssn);
}

}
