cmake_minimum_required(VERSION 3.15...4.1)

project(
    good_soldier
    VERSION 1.0
    LANGUAGES C
)

include_directories(src)

file(GLOB SOURCES src/*.c)

add_executable(good_soldier ${SOURCES})

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  target_compile_options(good_soldier PRIVATE
    -O0
    -g
    -fstack-protector-strong
    -fstack-reuse=none
    -fno-pie
  )
  target_link_options(good_soldier PRIVATE
    -no-pie
  )
endif()

set_property(TARGET good_soldier PROPERTY POSITION_INDEPENDENT_CODE FALSE)
