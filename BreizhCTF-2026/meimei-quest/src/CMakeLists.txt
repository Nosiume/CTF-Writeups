cmake_minimum_required(VERSION 3.15...4.1)

project(
    meimei_quest
    VERSION 1.0
    LANGUAGES C
)

include_directories(src)

file(GLOB SOURCES src/*.c)

add_executable(meimei_quest ${SOURCES})

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(meimei_quest PRIVATE
        -O0
        -g
        -fno-stack-protector
    )
endif()
