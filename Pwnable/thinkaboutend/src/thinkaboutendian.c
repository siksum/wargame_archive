
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#define FLAG_SIZE 0x40

void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}

void initialize() {
    setvbuf (stdin, 0, 2, 0); setvbuf (stdout, 0, 2, 0);
    setvbuf (stderr, 0, 2, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}


int main(int argc, char *argv[]) {
    int fd;
    char flag[100] = {0,};

    initialize();

    fd = open ("./flag", O_RDONLY);
    read(fd, flag, FLAG_SIZE);
    close(fd);
    // read flag
    // flag = (char *)malloc(FLAG_SIZE);
    // fd = open("./flag", O_RDONLY);
    // read(fd, flag, FLAG_SIZE);
    // close(fd);

    // char* flag = "HACK{h4ck1ng1550000d1f1cu1t}";

    printf("Input: ");

    unsigned char arr[9];
    scanf("%8s", arr);
    printf("arr  | 0x%x  0x%x  0x%x  0x%x  0x%x  0x%x  0x%x  0x%x |\n", arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7]);

    unsigned int * int_arr = (unsigned int *)arr;

    printf("arr  | 0x%x  0x%x |\n", int_arr[0], int_arr[1]);
    printf("\n");

    if(int_arr[0] == 0x7661696b && int_arr[1] == 0x5e5e3331){
        puts("감사합니다^^*");
        puts(flag);
    }
    else{
        puts("ㅠㅠ 다시 시도하세요~~");
    }

    return 0;
}