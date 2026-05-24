cmake_minimum_required(VERSION 3.10)
project(speeeeeed)

file(GLOB_RECURSE sources src/*.c)

add_executable(speeeeeed ${sources})
target_include_directories(speeeeeed PUBLIC src/)

# This binary is meant to behave like a pwnable challenge.
target_compile_options(speeeeeed PRIVATE
    -fno-stack-protector
)
