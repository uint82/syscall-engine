cmake_minimum_required(VERSION 3.20)

project(syscall_engine LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

function(syscall_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive-)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endfunction()

add_library(syscall_core
    src/pe_image.cpp
    src/ssn_resolver.cpp
    src/trampoline.cpp
    src/gadget_finder.cpp
)
target_include_directories(syscall_core PUBLIC include)
syscall_enable_warnings(syscall_core)

if(WIN32)
    add_library(syscall_windows STATIC
        src/engine.cpp
        src/fresh_ntdll.cpp
    )
    target_link_libraries(syscall_windows PUBLIC syscall_core)
    syscall_enable_warnings(syscall_windows)

    add_executable(syscall_loader src/main.cpp)
    target_link_libraries(syscall_loader PRIVATE syscall_windows)
    syscall_enable_warnings(syscall_loader)
endif()

option(SYSCALL_BUILD_TESTS "Build native unit tests" ON)

if(SYSCALL_BUILD_TESTS AND NOT CMAKE_CROSSCOMPILING)
    enable_testing()
    add_executable(syscall_tests
        tests/test_main.cpp
        tests/support/image_builder.cpp
        tests/test_pe_image.cpp
        tests/test_ssn_resolver.cpp
        tests/test_trampoline.cpp
        tests/test_gadget_finder.cpp
    )
    target_include_directories(syscall_tests PRIVATE tests/support)
    target_link_libraries(syscall_tests PRIVATE syscall_core)
    syscall_enable_warnings(syscall_tests)
    add_test(NAME syscall_tests COMMAND syscall_tests)
endif()

if(WIN32 AND SYSCALL_BUILD_TESTS)
    add_executable(syscall_windows_tests
        tests/test_main.cpp
        tests/windows/test_engine.cpp
    )
    target_include_directories(syscall_windows_tests PRIVATE tests/support)
    target_link_libraries(syscall_windows_tests PRIVATE syscall_windows)
    syscall_enable_warnings(syscall_windows_tests)
    if(NOT CMAKE_CROSSCOMPILING)
        add_test(NAME syscall_windows_tests COMMAND syscall_windows_tests)
    endif()
endif()
