#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "syscall/fresh_ntdll.hpp"
#include "syscall/gadget_finder.hpp"
#include "syscall/pe_image.hpp"
#include "syscall/status.hpp"

namespace syscall {

enum class Mode {
    kDirect,
    kIndirect,
    kIndirectSpoofed,
    kIndirectUnwindSpoofed,
};

enum class ImageSource {
    kLive,
    kFresh,
};

class Engine {
public:
    Engine() = default;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine(Engine&&) = delete;
    Engine& operator=(Engine&&) = delete;
    ~Engine();

    Status init(Mode mode = Mode::kDirect);
    ImageSource source() const;
    Mode mode() const;
    Status last_error() const;
    void* resolve(const char* name);
    void* resolve(std::uint64_t hash);
    Status commit();

    template <typename Fn>
    Fn get(const char* name) {
        return reinterpret_cast<Fn>(resolve(name));
    }

    template <typename Fn>
    Fn get(std::uint64_t hash) {
        return reinterpret_cast<Fn>(resolve(hash));
    }

private:
    Status record(Status status);
    bool load_live_image();
    void select_resolution_image();
    bool load_exports(const std::uint8_t* image, std::size_t size);
    fresh::Api resolve_fresh_api() const;
    void* export_address(std::string_view name) const;
    Mode resolve_mode(Mode requested);
    bool prepare_syscall_gadget();
    bool prepare_spoof_gadgets();
    bool prepare_unwind_gadgets();
    bool allocate_trampolines();
    std::optional<std::uint32_t> lookup_ssn(std::size_t index) const;
    void* emit_stub(std::size_t index);
    bool write_stub(std::span<std::uint8_t> slot, std::uint32_t ssn);

    Mode mode_ = Mode::kDirect;
    ImageSource source_ = ImageSource::kLive;
    const std::uint8_t* live_image_ = nullptr;
    std::size_t live_size_ = 0;
    const std::uint8_t* ssn_image_ = nullptr;
    std::size_t ssn_size_ = 0;
    fresh::Api fresh_api_{};
    fresh::MappedImage fresh_view_{};
    std::vector<pe::Export> exports_;
    std::vector<void*> stub_cache_;
    std::uint8_t* trampolines_ = nullptr;
    std::size_t trampoline_count_ = 0;
    std::uint32_t gadget_rva_ = 0;
    SpoofGadgets spoof_gadgets_{};
    UnwindSpoofGadgets unwind_gadgets_{};
    bool is_committed_ = false;
    Status last_error_ = Status::kOk;
};

}
