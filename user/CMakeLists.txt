cmake_minimum_required(VERSION 3.10.0)
project(ebpf-file-access-filter VERSION 0.1.0 LANGUAGES C CXX)

set(KERNEL_GENERATED_INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../build/include"
)

if (NOT KERNEL_GENERATED_INCLUDE_DIR)
    message(FATAL_ERROR
        "Directory not found: ${KERNEL_GENERATED_INCLUDE_DIR}.\n"
        "Check whether you have built the kernel component."
    )
endif()

set(FAF_SKEL_HEADER
    "${KERNEL_GENERATED_INCLUDE_DIR}/faf/skel.h"
)

set(INCLUDE_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/../include"
)

if(NOT EXISTS "${FAF_SKEL_HEADER}")
    message(FATAL_ERROR
        "Generated skel header not found: ${FAF_SKEL_HEADER}\n"
        "Check whether you have built the kernel component."
    )
endif()

add_executable(faf-loader
    loader/src/main.c
)

target_include_directories(faf-loader
    PRIVATE
        "${KERNEL_GENERATED_INCLUDE_DIR}"
        "${INCLUDE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/shared"
)

target_link_libraries(faf-loader
    PRIVATE
        bpf
        elf
        z
)

include(CTest)
enable_testing()
