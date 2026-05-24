#include "game.h"
#include "mem_arena.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>

char* enemy_models[3] = {
    "res/grim_reaper.txt",
    "res/monster.txt",
    "res/zombie.txt"
};

enemy_attack_func attack_funcs[5] = {
    enemy_finisher,
    quarter_attack,
    failed_attack,
    heals_attack,
    whatthehell_attack
};

// Little attack options
int 
enemy_finisher() {
    puts("This is not your day... The enemy hits you with a finisher !");
    return PLAYER_FULL_HEALTH; 
}

int
quarter_attack() {
    puts("The enemy slashes at you and manages to do some damage !");
    return PLAYER_FULL_HEALTH / 4;
}

int
failed_attack() {
    puts("The enemy misses you. You look at your body and no damage has been done !");
    return 0;
}

int
heals_attack () {
    puts("Huh ?? The enemy got confused and healed you i guess");
    return - PLAYER_FULL_HEALTH / 4;
}

int whatthehell_attack() {
    void *p = dlsym(RTLD_NEXT, "puts");
    printf("The enemy picks up a notebook and throws it at you !! It doesn't really hurt but there's confidential information in it : %p\n", p);
    return 0;
}

// GAME

static void 
init_game_ctx(game_ctx* ctx) {
    arena_init(&ctx->arena, Mb(1));

    // Player
    ctx->player = arena_alloc(&ctx->arena, sizeof(player_t));
    ctx->player->health = PLAYER_FULL_HEALTH;
    strncpy(ctx->player->name, "Player 1", 32);

    // Enemy
    ctx->enemy = arena_alloc(&ctx->arena, sizeof(enemy_t));
    ctx->enemy->health = PLAYER_FULL_HEALTH;
    for(int i = 0 ; i < 5 ; i++) {
        ctx->enemy->attacks[i] = attack_funcs[i];
    }
    
    char* model = enemy_models[rand() % 3];
    ctx->enemy->design = arena_alloc(&ctx->arena, 4096);
    FILE* fp = fopen(model, "r");
    if(fp != NULL) {
        size_t end = fread(ctx->enemy->design, 1, 4096, fp);
        ctx->enemy->design[end] = 0;
        fclose(fp);
    }
}

static void
game_instance() {
    game_ctx ctx; 

    puts("[+] Starting game ... ");
    sleep(1);
    
    // Setup game context 
    init_game_ctx(&ctx);    

    puts("What is your name, soldier ? ");
    printf("> ");
    fgets(ctx.player->name, 32, stdin);
    ctx.player->name[strcspn(ctx.player->name, "\n")] = '\0';
    printf("Welcome, %s !\n", ctx.player->name);


    while (ctx.enemy->health > 0 && ctx.player->health > 0) {
        puts(ctx.enemy->design);
        printf("[ENEMY STATS] : %d HEALTH\n", ctx.enemy->health);
        printf("[%s STATS] : %d HEALTH\n", ctx.player->name, ctx.player->health);

        puts("What do you want to do ?");
        puts("[1] : Attack");
        puts("[2] : Flee");

        char c = 'a';
        while (!(c == '1' || c == '2')) {
            printf("> ");
            scanf("%c%*c", &c);
        }

        if (c == '1') {
            printf("You attack the enemy and makes him lose %d HP !!\n", PLAYER_FULL_HEALTH/4);
            ctx.enemy->health -= PLAYER_FULL_HEALTH/4;
        } else {
            printf("You flee... Perhaps you weren't a good soldier after all :/\n");
            break;
        }

        // Enemy attacks
        enemy_attack_func func = ctx.enemy->attacks[rand() % 5];
        int damage = func();
        ctx.player->health -= damage;

        puts("Press enter to continue...");
        scanf("%*c");
    }

    if(ctx.player->health > 0 && ctx.enemy->health <= 0) {
        puts("You win !! The villagers thank you for defending them, brave soldier.");
    } else {
        puts("You lose... Your bravery will not be forgotten soldier..."); 
    }

    sleep(1);

    puts("Leave a review of this game for us please :D");
    printf("> ");

    // whoopsie :))))
    fgets(ctx.review, 512, stdin);

    char* signature = arena_alloc(&ctx.arena, 32);
    printf("Signature : ");
    fgets(signature, 32, stdin);

    // Free memory
    // TODO: check if we can bypass invalid chunk check
    arena_destroy(&ctx.arena);
}

void game_start() {
    char buf[4096];
    FILE* fp = fopen("./res/ascii_knight.txt", "r");
    if(fp != NULL) {
        fread(buf, sizeof(buf), 1, fp); 
        fclose(fp);
        puts(buf); 
    }

    puts("Welcome to Good Soldier !! The game where you play a soldier who is so brave");
    puts("he never hesitates to jump into the arena and fight evil monsters :O");

    while(1) {
        game_instance();

        puts("Do you want to continue (y/n) ?");

        char c;
        if(scanf("%c%*c", &c) == 1) {
            if (c == 'y' || c == 'Y') {
                continue;
            }
        }

        break;
    }
}
