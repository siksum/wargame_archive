#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int filter(const char* cmd) {
    int r = 0;
    r += strstr(cmd, "flag") != NULL;  
    r += strstr(cmd, "sh") != NULL;    
    r += strstr(cmd, "tmp") != NULL;   
    r += strchr(cmd, '&') != NULL;    
    r += strchr(cmd, ';') != NULL;      
    return r;
}

int main(int argc, char* argv[], char** envp) {
    if (argc < 2) {
        printf("Usage: My Cat wants <command>\n");
        return 1;
    }

    unsetenv("LD_PRELOAD");
    putenv("PATH=/LookingForSTH?");

    if (filter(argv[1])) {
        printf("Filtered command detected! Operation not permitted.\n");
        return 0;
    }
    
    setreuid(geteuid(), geteuid());

    char* args[] = {"/bin/sh", "-c", argv[1], NULL};
    execve("/bin/sh", args, envp);

    return 0;
}