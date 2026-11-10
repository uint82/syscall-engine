cmake_minimum_required(VERSION 3.20)

project(syscall_package_consumer LANGUAGES CXX)

find_package(syscall-engine 0.3 REQUIRED)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE syscall::core)

if(WIN32)
    target_link_libraries(consumer PRIVATE syscall::windows)
endif()
