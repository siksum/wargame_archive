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
    printf("eaaaaaaaaaaaasy bof\n");
    vuln();
    return 0;
}

