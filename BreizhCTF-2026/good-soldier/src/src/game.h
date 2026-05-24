#ifndef GAME_H
#define GAME_H

#include "mem_arena.h"

#define PLAYER_FULL_HEALTH 100


typedef struct {
    int health;
    char name[32];
} player_t;

typedef int (*enemy_attack_func)();

typedef struct {
    char* design;
    int health;
    enemy_attack_func attacks[5];
} enemy_t;

typedef struct {
    char review[256];
    mem_arena arena;
    player_t* player;
    enemy_t* enemy;
} game_ctx;

// Attack functions

int enemy_finisher();
int quarter_attack();
int failed_attack();
int heals_attack ();
int whatthehell_attack();

// Generic attack trigger

int enemy_random_attack(enemy_t*);

// Game loop
static void init_game_ctx(game_ctx*);
static void game_instance();
void game_start();

#endif
