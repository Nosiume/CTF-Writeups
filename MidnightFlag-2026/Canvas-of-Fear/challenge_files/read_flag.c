#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    FILE *fp;
    char ch;
    
    fp = fopen("/flag.txt", "r");
    if (fp == NULL) {
        perror("Error opening file");
        return 1;
    }
    
    while ((ch = fgetc(fp)) != EOF) {
        putchar(ch);
    }
    
    fclose(fp);
    return 0;
}

