#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "syscall/pe_image.hpp"

namespace syscall {

enum class Mode {
    kDirect,
    kIndirect,
};

class Engine {
public:
    Engine() = default;
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    Engine(Engine&&) = delete;
    Engine& operator=(Engine&&) = delete;
    ~Engine();

    bool init(Mode mode = Mode::kDirect);
    void* resolve(const char* name);
    bool commit();

    template <typename Fn>
    Fn get(const char* name) {
        return reinterpret_cast<Fn>(resolve(name));
    }

private:
    bool write_stub(std::span<std::uint8_t> slot, std::uint32_t ssn);

    Mode mode_ = Mode::kDirect;
    const std::uint8_t* image_ = nullptr;
    std::size_t image_size_ = 0;
    std::vector<pe::Export> exports_;
    std::uint8_t* trampolines_ = nullptr;
    std::size_t trampoline_count_ = 0;
    std::uint32_t gadget_rva_ = 0;
    bool is_committed_ = false;
};

}
