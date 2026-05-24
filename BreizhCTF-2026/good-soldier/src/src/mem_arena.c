#include "mem_arena.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/*
 * Initializes an arena allocator of size "capacity"
 * See definition of mem_arena struct in mem_alloc.h
 */
int 
arena_init(mem_arena* arena, size_t capacity) {
    assert( arena != NULL );
    assert( capacity != 0 );
    
    // Allocate arena memory
    arena->base = malloc(capacity);
    if ( !arena->base ) {
        printf("[MEM_ARENA] Error : %s\n", strerror(errno));
        return FAILED_ALLOCATION;
    }

    arena->cursor = 0;
    arena->capacity = capacity;
    return SUCCESS;
}

/*
 * Allocates a chunk of size "sz" from the given arena
 */
void*
arena_alloc(mem_arena* arena, size_t sz) {
    assert( arena != NULL );
    assert( sz > 0 );

    size_t left = arena->capacity - arena->cursor;
    assert( left >= sz );

    void* alloc = arena->base + arena->cursor;
    arena->cursor += sz;
    return alloc;
}

/*
 * Destroys an arena by freeing it's allocated memory block
 * Leaves struct data untouched
 */
int
arena_destroy(mem_arena* arena) {
    assert( arena != NULL );
    free(arena->base);
    return SUCCESS;
}
