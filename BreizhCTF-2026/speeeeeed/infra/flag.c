#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    seteuid(0);
    setegid(0);

    char flag[128];
    FILE* fp = fopen("./flag.txt", "r");
    if (fp == NULL) {
        perror("Something went wrong, flag not found or unreadable. Contact admins ");
        return -1;
    }

    fgets(flag, sizeof(flag), fp);
    printf("GG WP !!! Flag : %s\n", flag);
    return 0;
}

