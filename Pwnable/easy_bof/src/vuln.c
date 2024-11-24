#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void get_flag() {
    system("/bin/bash");
}

void initialize() {
    setvbuf (stdin, 0, 2, 0); 
    setvbuf (stdout, 0, 2, 0);
    setvbuf (stderr, 0, 2, 0);
}

void vuln() {
    char buffer[64];
    initialize();

    printf("Enter some text: ");
    gets(buffer); 
}

int main() {

    printf("eaaaaaaaaaaaasy bof\n");
    vuln();
    return 0;
}

