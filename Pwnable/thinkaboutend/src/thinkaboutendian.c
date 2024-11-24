
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

unsigned int swap_endian(unsigned int val) {
    return ((val >> 24) & 0xff) |
           ((val << 8) & 0xff0000) |
           ((val >> 8) & 0xff00) |
           ((val << 24) & 0xff000000);
}

// ... existing code ...

int main(int argc, char *argv[]) {
    int fd;
    char flag[100] = {0,};

    initialize();

    fd = open ("./flag", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open flag file");
        exit(-1);
    }
    if (read(fd, flag, FLAG_SIZE) < 0) {
        perror("Failed to read flag file");
        close(fd);
        exit(-1);
    }
    close(fd);

    printf("Input: ");
    fflush(stdout);  // Ensure the prompt is sent immediately

    char input_buf[256] = {0};  // 충분히 큰 입력 버퍼
    unsigned char arr[9] = {0};  // 실제 사용할 8바이트 + NULL

    fgets(input_buf, sizeof(input_buf), stdin);
    strncpy(arr, input_buf, 8);  // 입력에서 8바이트만 복사
    printf("arr  | 0x%x  0x%x  0x%x  0x%x  0x%x  0x%x  0x%x  0x%x |\n", 
           arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7]);
    fflush(stdout);

    unsigned int int_arr[2] = {0};
    memcpy(int_arr, arr, sizeof(int_arr));
    
    printf("arr  | 0x%x  0x%x |\n", int_arr[0], int_arr[1]);
    printf("\n");
    fflush(stdout);

    if(int_arr[0] == 0x7661696b && int_arr[1] == 0x5e5e3331){
        puts("감사합니다^^*");
        puts(flag);
    }
    else{
        puts("ㅠㅠ 다시 시도하세요~~");
    }

    return 0;
}