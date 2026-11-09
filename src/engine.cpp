#include "syscall/engine.hpp"

#include "syscall/gadget_finder.hpp"
#include "syscall/ssn_resolver.hpp"
#include "syscall/stub_layout.hpp"
#include "syscall/trampoline.hpp"

#include <windows.h>

#include <bit>
#include <span>
#include <utility>

namespace syscall {
namespace {

constexpr std::size_t kTrampolineRegionSize = 0x10000;
constexpr std::size_t kHeaderWindow = 0x1000;
constexpr std::size_t kMaxTrampolines = kTrampolineRegionSize / kTrampolineStride;

static_assert(sizeof(void*) == 8);

std::optional<std::uint32_t> find_gadget(std::span<const std::uint8_t> image) {
    const auto sections = pe::read_sections(image.data(), image.size());
    if (!sections.has_value()) {
        return std::nullopt;
    }
    return find_syscall_gadget(image, *sections);
}

}

Engine::~Engine() {
    if (trampolines_ != nullptr) {
        VirtualFree(trampolines_, 0, MEM_RELEASE);
    }
}

bool Engine::init(Mode mode) {
    const auto module = GetModuleHandleA("ntdll.dll");
    if (module == nullptr) {
        return false;
    }
    image_ = reinterpret_cast<const std::uint8_t*>(module);

    const auto image_size = pe::read_image_size(image_, kHeaderWindow);
    if (!image_size.has_value()) {
        return false;
    }
    image_size_ = *image_size;

    auto exports = pe::read_exports(image_, image_size_);
    if (!exports.has_value()) {
        return false;
    }
    exports_ = std::move(*exports);

    const auto image = std::span<const std::uint8_t>(image_, image_size_);
    if (mode == Mode::kIndirect) {
        const auto gadget = find_gadget(image);
        if (!gadget.has_value()) {
            return false;
        }
        gadget_rva_ = *gadget;
    }
    mode_ = mode;

    trampolines_ = static_cast<std::uint8_t*>(
        VirtualAlloc(nullptr, kTrampolineRegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    return trampolines_ != nullptr;
}

bool Engine::write_stub(std::span<std::uint8_t> slot, std::uint32_t ssn) {
    if (mode_ == Mode::kIndirect) {
        const auto gadget = std::bit_cast<std::uint64_t>(image_ + gadget_rva_);
        return write_indirect_stub(slot, ssn, gadget);
    }
    return write_direct_stub(slot, ssn);
}

void* Engine::resolve(const char* name) {
    if (trampolines_ == nullptr || is_committed_ || name == nullptr) {
        return nullptr;
    }
    if (trampoline_count_ >= kMaxTrampolines) {
        return nullptr;
    }

    const auto ssn = resolve_ssn(
        std::span<const std::uint8_t>(image_, image_size_), exports_, name);
    if (!ssn.has_value()) {
        return nullptr;
    }

    auto slot = std::span<std::uint8_t>(
        trampolines_ + trampoline_count_ * kTrampolineStride, kTrampolineStride);
    if (!write_stub(slot, *ssn)) {
        return nullptr;
    }
    ++trampoline_count_;
    return slot.data();
}

bool Engine::commit() {
    if (trampolines_ == nullptr || is_committed_) {
        return false;
    }
    DWORD previous = 0;
    if (VirtualProtect(trampolines_, kTrampolineRegionSize, PAGE_EXECUTE_READ, &previous) == 0) {
        return false;
    }
    is_committed_ = true;
    return true;
}

}
