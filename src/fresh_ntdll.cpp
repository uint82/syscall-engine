#include "syscall/fresh_ntdll.hpp"

#include <windows.h>
#include <winternl.h>

#include <iterator>

namespace syscall::fresh {
namespace {

using NtOpenSectionFn = LONG(NTAPI*)(HANDLE*, ACCESS_MASK, POBJECT_ATTRIBUTES);
using NtMapViewOfSectionFn = LONG(NTAPI*)(HANDLE, HANDLE, void**, std::uintptr_t, std::size_t,
                                          void*, std::size_t*, unsigned long, unsigned long,
                                          unsigned long);
using NtCloseFn = LONG(NTAPI*)(HANDLE);
using NtUnmapViewOfSectionFn = LONG(NTAPI*)(HANDLE, void*);

constexpr ACCESS_MASK kSectionMapRead = 0x0004;
constexpr unsigned long kViewUnmap = 2;
constexpr wchar_t kKnownDllsNtdll[] = L"\\KnownDlls\\ntdll.dll";

// KnownDlls exposes the section the loader mapped. Hooks patch the process's
// view, not the section, so this view stays clean.
HANDLE open_known_dlls_section(const Api& api) {
    UNICODE_STRING name{};
    name.Buffer = const_cast<wchar_t*>(kKnownDllsNtdll);
    name.Length = static_cast<USHORT>((std::size(kKnownDllsNtdll) - 1) * sizeof(wchar_t));
    name.MaximumLength = static_cast<USHORT>(name.Length + sizeof(wchar_t));

    OBJECT_ATTRIBUTES attributes{};
    attributes.Length = static_cast<ULONG>(sizeof(attributes));
    attributes.ObjectName = &name;
    attributes.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE section = nullptr;
    const LONG status = reinterpret_cast<NtOpenSectionFn>(api.open_section)(
        &section, kSectionMapRead, &attributes);
    return status >= 0 ? section : nullptr;
}

MappedImage map_view(HANDLE section, const Api& api) {
    void* view = nullptr;
    std::size_t view_size = 0;
    const LONG status = reinterpret_cast<NtMapViewOfSectionFn>(api.map_view)(
        section, GetCurrentProcess(), &view, 0, 0, nullptr, &view_size, kViewUnmap, 0,
        PAGE_READONLY);
    if (status < 0) {
        return {};
    }
    return {static_cast<const std::uint8_t*>(view), view_size, view};
}

bool is_api_complete(const Api& api) {
    return api.open_section != nullptr && api.map_view != nullptr &&
           api.close != nullptr && api.unmap_view != nullptr;
}

}

MappedImage map_ntdll(const Api& api) {
    if (!is_api_complete(api)) {
        return {};
    }
    const HANDLE section = open_known_dlls_section(api);
    if (section == nullptr) {
        return {};
    }
    auto image = map_view(section, api);
    reinterpret_cast<NtCloseFn>(api.close)(section);
    return image;
}

void unmap_ntdll(const Api& api, MappedImage& image) {
    if (image.view != nullptr && api.unmap_view != nullptr) {
        reinterpret_cast<NtUnmapViewOfSectionFn>(api.unmap_view)(GetCurrentProcess(), image.view);
    }
    image = {};
}

}
