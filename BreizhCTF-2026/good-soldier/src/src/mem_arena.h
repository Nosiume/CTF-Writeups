#ifndef MEM_ARENA_H
#define MEM_ARENA_H

#include <stddef.h>
#include <stdlib.h>

// Let's define some practical size headers !
#define Kb(n) (n << 10)
#define Mb(n) (n << 20)
#define Gb(n) (n << 30)

enum mem_arena_errcode {
    SUCCESS,
    BAD_SIZE,
    NO_MEMORY_LEFT,
    FAILED_ALLOCATION
};

typedef struct {
    void* base;
    size_t cursor;
    size_t capacity;
} mem_arena;


int arena_init(mem_arena* arena, size_t capacity);
void* arena_alloc(mem_arena* arena, size_t sz);
int arena_destroy(mem_arena*);

#endif
