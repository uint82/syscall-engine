#pragma once

#include <cstddef>
#include <cstdint>

namespace syscall::fresh {

struct Api {
    void* open_section = nullptr;
    void* map_view = nullptr;
    void* close = nullptr;
    void* unmap_view = nullptr;
};

struct MappedImage {
    const std::uint8_t* bytes = nullptr;
    std::size_t size = 0;
    void* view = nullptr;
};

MappedImage map_ntdll(const Api& api);
void unmap_ntdll(const Api& api, MappedImage& image);

}
