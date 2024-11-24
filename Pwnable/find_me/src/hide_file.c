#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>

typedef struct dirent *(*orig_readdir_type)(DIR *);

struct dirent *readdir(DIR *dirp) {
    static orig_readdir_type orig_readdir = NULL;
    if (!orig_readdir) {
        orig_readdir = (orig_readdir_type)dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *entry;
    while ((entry = orig_readdir(dirp)) != NULL) {
        // 숨길 파일 이름
        if (strstr(entry->d_name, "find_me.txt") != NULL) {
            continue; 
        }
        return entry;
    }
    return NULL;
}