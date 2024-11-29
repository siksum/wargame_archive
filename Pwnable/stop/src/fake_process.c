#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>


void initialize() {
    setvbuf (stdin, 0, 2, 0); 
    setvbuf (stdout, 0, 2, 0);
    setvbuf (stderr, 0, 2, 0);
}


void create_flag() {
    // 로그 출력
    printf("Attempting to create flag file...\n");

    FILE *file = fopen("/tmp/flag.txt", "w");
    if (file) {
        fprintf(file, "HACK{5T0P_Pr0ce55}\n");
        fclose(file);
        printf("Flag created at /tmp/flag.txt\n");
    } else {
        perror("Failed to create /tmp/flag.txt");
    }
}

int main() {
    initialize();

    printf("Fake process running...\n");

    while (1) {
        // flag 파일 생성
        create_flag();

        // 5초 대기 후 파일 삭제
        sleep(2);
        if (remove("/tmp/flag.txt") == 0) {
            printf("Flag removed from /tmp/flag.txt\n");
        } else {
            perror("Failed to remove /tmp/flag.txt");
        }

        // 다시 5초 대기
        sleep(8);
    }

    return 0;
}
