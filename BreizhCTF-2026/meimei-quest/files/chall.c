#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

char baobao_phone_number[15];

void step3();

void generate_phone_number() {
    for(size_t i = 0 ; i < 5 ; i++) {
         baobao_phone_number[i*3] = '0' + (rand() % 10); 
         baobao_phone_number[i*3 + 1] = '0' + (rand() % 10); 
         baobao_phone_number[i*3 + 2] = ' ';
    }
    baobao_phone_number[14] = '\0';
}

void print_file(const char* path) {
    char buf[4096];
    FILE* fp = fopen(path, "r");
    if(fp == NULL) {
        puts("ILLUSTRATION IS MISSING !!! If this happens on the remote, please contact the admins");
        return;
    }

    fread(buf, 1, 4096, fp);
    fclose(fp);
    puts(buf);
}

void step1() {
    print_file("res/meimei.txt");

    puts("Huh... Hello :)))"); 
    puts("This is a bit embarassing but I got stuck in this pack of fries and I need someone to help me get out of here !!");
    puts("I need you to bring me to my friend uncle bao bao so he can save me from this evil...");
    puts("");
    printf("But first, we need to get his phone number ! I heard it's at %p... Could you get it for me pleaaaase ?\n", baobao_phone_number);
    puts("I will FORMAT your answer in a *helpful* way ;) ;) (wink)");

    char answer[512];
    printf("> ");
    fgets(answer, sizeof(answer), stdin);

    printf("[YOU] : ");
    printf(answer);

    puts("So did you find out what his phone number was ?"); 
    printf("> ");

    fgets(answer, sizeof(answer), stdin);
    if (strncmp(answer, baobao_phone_number, sizeof(baobao_phone_number) - 1) != 0) {
        puts("I tried to call but it seems you got it wrong :("); 
        exit(0);
    }

    puts("THANK YOUUUUU !!! I will call and pass you the phone...");
}

void step2() {
    print_file("res/baobao.txt");

    puts("[Bao Bao] Hi ! Who's calling ?");
    puts("[YOU]: Huh it's a complicated situation but your friend mei mei got stuck in a bag of fries again....");
    printf("[Bao Bao] I see... I know exactly what to do ! You need to jump to %p, I believe it's only 40 bytes away :))\n", step3);

    char buf[32];
    printf("> ");
    fgets(buf, 48, stdin);

    puts("[Bao Bao] Let's see if you know how to jump ...");
}

void step3() {
    puts("+======================================================================+");
    puts("|                           SECRET PANEL                               |");
    puts("|                      [ AUTHORIZED PAWS ONLY ]                        |");
    puts("|                                                                      |");
    puts("|          /\\_/\\\\                                      /\\_/\\\\          |");
    puts("|         ( o.o )                                    ( -.- )           |");
    puts("|          > ^ <                                      > ^ <            |");
    puts("|         MEIMEI                                 UNCLE BAO BAO         |");
    puts("|                                                                      |");
    puts("|          >>> whisker-auth ................. [  OK  ]                 |");
    puts("|          >>> stealth-purr mode ............ [ ON  ]                  |");
    puts("|          >>> snack vault lock ............. [ARMED]                  |");
    puts("|                                                                      |");
    puts("|                 CLASSIFIED FELINE INTERFACE v9.9                     |");
    puts("+======================================================================+");

    void (*alloc)() = mmap(
            NULL, 
            0x1000, 
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_PRIVATE, 
            -1, 0);

    puts("Welcome to this secret panel where your input data will be interpreted as shellcode !");
    printf("command> ");

    read(0, alloc, 32);
    alloc();
}

int main(int argc, char** argv) {
    setvbuf(stdin, NULL, _IOLBF, 0);
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);

    srand((size_t)main);
    generate_phone_number();
    
    step1();
    step2();

    puts("[Bao Bao] You need to lookup a tutorial for how to jump man...");

    return 0;
}
