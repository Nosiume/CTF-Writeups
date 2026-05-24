cmake_minimum_required(VERSION 3.10)
project(cool_compress)

file(GLOB_RECURSE sources src/*.c)

add_library(cool_compress SHARED ${sources})

set_target_properties(cool_compress PROPERTIES PREFIX "")
target_include_directories(cool_compress PUBLIC src/)
target_include_directories(cool_compress PUBLIC /usr/include/python3.13)
