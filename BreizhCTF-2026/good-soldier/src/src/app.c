#include "game.h"
#include <stdio.h>
#include <time.h>

int main(int argc, char** argv) {
    setvbuf(stdin, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    srand(time(NULL));
    game_start();
    return 0;
}
