cmake_minimum_required(VERSION 3.10)

project(babysniff
    VERSION 0.1
    DESCRIPTION "A simple sniffer written from scratch without any libraries"
    LANGUAGES C
)

file(GLOB babysniff_srcs RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "src/*.c"
    "src/bpf/*.c"
    "src/platform/shared/*.c"
    "src/proto/*.c"
    "src/proto/dns/*.c"
    "src/proto/dns/sections/*.c"
    "src/proto/dns/sections/rdata/*.c"
    "src/types/*.c"
)

# Conditionally include compatibility sources for Windows
if (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    list(APPEND babysniff_srcs 
        "src/compat/getopt_compat.c"
        "src/compat/string_compat.c"
        "src/compat/time_compat.c"
    )
endif()

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    file(GLOB babysniff_srcs_platform RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/platform/linux/*.c")
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    file(GLOB babysniff_srcs_platform RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/platform/bsd/*.c")
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    file(GLOB babysniff_srcs_platform RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/platform/windows/*.c")
endif()

add_executable(babysniff ${babysniff_srcs} ${babysniff_srcs_platform})

target_include_directories(babysniff PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/compat
    ${PROJECT_SOURCE_DIR}/src/proto
    ${PROJECT_SOURCE_DIR}/src/proto/dns
    ${PROJECT_SOURCE_DIR}/src/proto/dns/sections
    ${PROJECT_SOURCE_DIR}/src/proto/dns/sections/rdata
    ${PROJECT_SOURCE_DIR}/src/types
)

target_compile_definitions(babysniff PRIVATE _GNU_SOURCE=1)

if (${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    target_compile_definitions(babysniff PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS)
    target_link_libraries(babysniff PRIVATE ws2_32 iphlpapi)
    target_compile_options(babysniff PRIVATE /W4 /std:c17)
else()
    target_compile_options(babysniff PRIVATE -W -Wall -Wextra -std=c17 -pedantic -ggdb3 -O0)
endif()
#target_link_options(babysniff ...)

set_target_properties(babysniff
    PROPERTIES
        C_STANDARD 17
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
