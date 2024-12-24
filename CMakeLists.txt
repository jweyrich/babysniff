cmake_minimum_required(VERSION 3.10)

project(babysniff
    VERSION 0.1
    DESCRIPTION "A simple sniffer written from scratch without any libraries"
    LANGUAGES C
)

file(GLOB babysniff_srcs RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "src/*.c"
    "src/compat/*.c"
    "src/proto/*.c"
    "src/proto/dns/*.c"
    "src/types/*.c"
)

if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    file(GLOB babysniff_srcs_platform RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/platform/linux/*.c")
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    file(GLOB babysniff_srcs_platform RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} "src/platform/bsd/*.c")
endif()

add_executable(babysniff ${babysniff_srcs} ${babysniff_srcs_platform})

target_include_directories(babysniff PRIVATE
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/compat
    ${PROJECT_SOURCE_DIR}/src/proto
    ${PROJECT_SOURCE_DIR}/src/proto/dns
    ${PROJECT_SOURCE_DIR}/src/types
)

target_compile_definitions(babysniff PRIVATE _GNU_SOURCE=1)
target_compile_options(babysniff PRIVATE -W -Wall -Wextra -std=c17 -pedantic -ggdb3 -O0)
#target_link_options(babysniff ...)

set_target_properties(babysniff
    PROPERTIES
        C_STANDARD 17
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
