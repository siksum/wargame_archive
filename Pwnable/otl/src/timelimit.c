#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <time.h>

int main() {
    char answer[256];
    char correct_answer[256];
    char flag[256];

    // answer.txt 파일에서 정답을 읽어옴
    FILE *file = fopen("answer.txt", "r");
    if (file == NULL) {
        perror("Error opening answer file");
        return 1;
    }
    fgets(correct_answer, sizeof(correct_answer), file);
    fclose(file);
    correct_answer[strcspn(correct_answer, "\n")] = '\0'; // 개행 문자 제거

    printf("You have 1 seconds to find the flag!\n");
    fflush(stdout);  // 즉시 출력

    printf("What is the secret answer? "); // 질문 메시지 출력
    fflush(stdout);  // 즉시 출력

    // 타이머를 시작
    time_t start_time = time(NULL);
    while (1) {
        // 3초가 지나면 종료
        if (difftime(time(NULL), start_time) >= 1) {
            printf("\nTime's up!\n");
            return 0;
        }

        // 사용자 입력 확인
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(STDIN_FILENO, &fds);
        struct timeval timeout;
        timeout.tv_sec = 1; // 짧은 대기 시간을 사용
        timeout.tv_usec = 0;

        int result = select(STDIN_FILENO + 1, &fds, NULL, NULL, &timeout);
        if (result == -1) {
            perror("Error during select");
            return 1;
        } else if (FD_ISSET(STDIN_FILENO, &fds)) {
            if (fgets(answer, sizeof(answer), stdin) != NULL) {
                answer[strcspn(answer, "\n")] = '\0'; // 개행 문자 제거
                if (strcmp(answer, correct_answer) == 0) {
                    // flag.txt 파일에서 플래그를 읽어옴
                    file = fopen("flag.txt", "r");
                    if (file == NULL) {
                        perror("Error opening flag file");
                        return 1;
                    }
                    fgets(flag, sizeof(flag), file);
                    fclose(file);

                    printf("Congratulations! You found the flag: %s\n", flag);
                    return 0;
                }
                printf("Wrong answer. Try again!\n");
            }
        }
    }
    return 0;
}