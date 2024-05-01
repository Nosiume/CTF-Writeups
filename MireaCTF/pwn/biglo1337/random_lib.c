#include <stdlib.h>

void setseed(int seed) {
    srand(seed);
}

int generate() {
    return rand() & 0xff;
}
