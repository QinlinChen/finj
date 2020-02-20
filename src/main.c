#include "config.h"
#include "sys.h"
#include "hook/hook.h"

int main(int argc, char *argv[])
{
    char *s = malloc(10);
    if (!s) {
        openat(AT_FDCWD, "tmp.c", O_RDWR);
        return 0;
    }
    s[0] = 'w';
    s[1] = '\0';
    printf("%s\n", s);
    return 0;
}
