#include "syscall/unwind.hpp"

#include "pe_reader.hpp"
#include "syscall/pe_image.hpp"
#include "syscall/pe_types.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>

namespace syscall::unwind {
namespace {

inline constexpr std::uint8_t kVersionMask = 0x07;
inline constexpr std::uint8_t kUnwindVersion = 1;
inline constexpr std::uint8_t kChainedFlag = 0x20;
inline constexpr std::uint8_t kFrameRegisterMask = 0x0F;
inline constexpr std::uint8_t kFrameOffsetShift = 4;
inline constexpr std::uint8_t kRbpRegister = 5;
inline constexpr std::uint8_t kOperationMask = 0x0F;
inline constexpr std::uint8_t kOperationInfoShift = 4;
inline constexpr std::size_t kUnwindCodeSize = 2;

inline constexpr std::uint8_t kPushNonvol = 0;
inline constexpr std::uint8_t kAllocLarge = 1;
inline constexpr std::uint8_t kAllocSmall = 2;
inline constexpr std::uint8_t kSetFpreg = 3;
inline constexpr std::uint8_t kSaveNonvol = 4;
inline constexpr std::uint8_t kSaveNonvolFar = 5;
inline constexpr std::uint8_t kSaveXmm128 = 8;
inline constexpr std::uint8_t kSaveXmm128Far = 9;
inline constexpr std::uint8_t kPushMachframe = 10;

struct UnwindHeader {
    std::uint8_t version_flags;
    std::uint8_t prolog_size;
    std::uint8_t code_count;
    std::uint8_t frame_info;
};

static_assert(sizeof(UnwindHeader) == 4);

struct UnwindCode {
    std::uint8_t offset;
    std::uint8_t operation;
    std::uint8_t info;
};

bool has_overlaps(const std::vector<RuntimeFunction>& functions) {
    for (std::size_t index = 1; index < functions.size(); ++index) {
        if (functions[index].begin_rva < functions[index - 1].end_rva) {
            return true;
        }
    }
    return false;
}

std::optional<std::size_t> extra_slots(std::uint8_t operation, std::uint8_t info) {
    switch (operation) {
    case kPushNonvol:
    case kAllocSmall:
    case kSetFpreg:
        return 0;
    case kAllocLarge:
        if (info == 0) {
            return 1;
        }
        if (info == 1) {
            return 2;
        }
        return std::nullopt;
    case kSaveNonvol:
    case kSaveXmm128:
        return 1;
    case kSaveNonvolFar:
    case kSaveXmm128Far:
        return 2;
    case kPushMachframe:
        return info <= 1 ? std::optional<std::size_t>(0) : std::nullopt;
    default:
        // Unknown operations hide operands in extra slots, so every slot after
        // one of them is a guess.
        return std::nullopt;
    }
}

std::optional<UnwindCode> read_unwind_code(
    const std::uint8_t* image,
    std::size_t size,
    std::uint32_t unwind_info_rva,
    std::size_t slot) {
    const auto offset = static_cast<std::size_t>(unwind_info_rva) +
                        sizeof(UnwindHeader) + slot * kUnwindCodeSize;
    if (offset > size || size - offset < kUnwindCodeSize) {
        return std::nullopt;
    }
    const auto operation = image[offset + 1];
    return UnwindCode{
        image[offset],
        static_cast<std::uint8_t>(operation & kOperationMask),
        static_cast<std::uint8_t>(operation >> kOperationInfoShift)};
}

struct PrologScan {
    bool accept(const UnwindCode& code) {
        switch (code.operation) {
        case kPushNonvol:
            return accept_push(code);
        case kSetFpreg:
            return accept_frame(code);
        case kAllocLarge:
        case kAllocSmall:
            accept_alloc(code.offset);
            return true;
        case kPushMachframe:
            return false;
        case kSaveNonvol:
        case kSaveNonvolFar:
            return code.info != kRbpRegister;
        default:
            return true;
        }
    }

    bool valid(std::uint8_t prolog_size) const {
        if (!push_offset.has_value() || !frame_offset.has_value() ||
            *push_offset >= *frame_offset) {
            return false;
        }
        if (lowest_alloc_offset.has_value() && *lowest_alloc_offset <= *frame_offset) {
            return false;
        }
        return prolog_size > *frame_offset;
    }

private:
    bool accept_push(const UnwindCode& code) {
        if (code.info != kRbpRegister || push_offset.has_value()) {
            return false;
        }
        push_offset = code.offset;
        return true;
    }

    bool accept_frame(const UnwindCode& code) {
        if (code.info != 0 || frame_offset.has_value()) {
            return false;
        }
        frame_offset = code.offset;
        return true;
    }

    void accept_alloc(std::uint8_t offset) {
        if (!lowest_alloc_offset.has_value() || offset < *lowest_alloc_offset) {
            lowest_alloc_offset = offset;
        }
    }

    std::optional<std::uint8_t> push_offset;
    std::optional<std::uint8_t> frame_offset;
    std::optional<std::uint8_t> lowest_alloc_offset;
};

bool has_rbp_prolog(
    const std::uint8_t* image,
    std::size_t size,
    std::uint32_t unwind_info_rva,
    const UnwindHeader& header) {
    PrologScan scan;
    std::size_t slot = 0;
    while (slot < header.code_count) {
        const auto code = read_unwind_code(image, size, unwind_info_rva, slot);
        if (!code.has_value()) {
            return false;
        }
        const auto extra = extra_slots(code->operation, code->info);
        if (!extra.has_value() || slot + 1 + *extra > header.code_count) {
            return false;
        }
        if (!scan.accept(*code)) {
            return false;
        }
        slot += 1 + *extra;
    }
    return scan.valid(header.prolog_size);
}

}

std::optional<std::vector<RuntimeFunction>> read_runtime_functions(
    const std::uint8_t* image,
    std::size_t size) {
    const auto directory = pe::read_data_directory(image, size, pe::kExceptionDirectoryIndex);
    if (!directory.has_value()) {
        return std::nullopt;
    }
    if (directory->rva == 0 || directory->size == 0) {
        return std::vector<RuntimeFunction>{};
    }
    if (directory->rva >= size || directory->size % sizeof(RuntimeFunction) != 0) {
        return std::nullopt;
    }
    const auto count = directory->size / sizeof(RuntimeFunction);
    if (count > (size - directory->rva) / sizeof(RuntimeFunction)) {
        return std::nullopt;
    }

    std::vector<RuntimeFunction> functions;
    functions.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        const auto offset = static_cast<std::size_t>(directory->rva) +
                            index * sizeof(RuntimeFunction);
        const auto function = pe::read_struct<RuntimeFunction>(image, size, offset);
        if (!function.has_value() || function->begin_rva >= function->end_rva ||
            function->end_rva > size || function->unwind_info_rva == 0) {
            return std::nullopt;
        }
        const auto unwind_rva = static_cast<std::size_t>(function->unwind_info_rva);
        if (unwind_rva > size || size - unwind_rva < sizeof(UnwindHeader)) {
            return std::nullopt;
        }
        functions.push_back(*function);
    }

    std::sort(functions.begin(), functions.end(),
              [](const RuntimeFunction& left, const RuntimeFunction& right) {
                  return left.begin_rva < right.begin_rva;
              });
    if (has_overlaps(functions)) {
        return std::nullopt;
    }
    return functions;
}

std::optional<std::size_t> find_runtime_function(
    const std::vector<RuntimeFunction>& functions,
    std::uint32_t rva) {
    const auto next = std::upper_bound(
        functions.begin(), functions.end(), rva,
        [](std::uint32_t value, const RuntimeFunction& function) {
            return value < function.begin_rva;
        });
    if (next == functions.begin()) {
        return std::nullopt;
    }
    const auto match = std::prev(next);
    if (rva >= match->end_rva) {
        return std::nullopt;
    }
    return static_cast<std::size_t>(std::distance(functions.begin(), match));
}

std::optional<std::uint8_t> read_rbp_prolog_size(
    const std::uint8_t* image,
    std::size_t size,
    const RuntimeFunction& function) {
    const auto header =
        pe::read_struct<UnwindHeader>(image, size, function.unwind_info_rva);
    if (!header.has_value()) {
        return std::nullopt;
    }
    if ((header->version_flags & kVersionMask) != kUnwindVersion ||
        (header->version_flags & kChainedFlag) != 0) {
        return std::nullopt;
    }
    if ((header->frame_info & kFrameRegisterMask) != kRbpRegister ||
        (header->frame_info >> kFrameOffsetShift) != 0) {
        return std::nullopt;
    }
    if (!has_rbp_prolog(image, size, function.unwind_info_rva, *header)) {
        return std::nullopt;
    }
    return header->prolog_size;
}

}
