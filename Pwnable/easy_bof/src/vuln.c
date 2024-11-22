#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void get_flag() {
    system("cat /flag");
}

void vuln() {
    char buffer[64];
    printf("Enter some text: ");
    gets(buffer); 
}

int main() {
    setvbuf (stdin, 0, 2, 0); 
    setvbuf (stdout, 0, 2, 0);
    setvbuf (stderr, 0, 2, 0);

    printf("eaaaaaaaaaaaasy bof\n");
    vuln();
    return 0;
}

