#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>

static char *rt_path;     /* Path to runtime libraries         */
static int cc_argc;       /* Param count, including argv0      */
static char **cc_argv;    /* Parameters passed to the real CC  */

char *mystrdup(const char *s)
{
    assert(s);
    char *ret = (char *)malloc((strlen(s) + 1) * sizeof(char));
    assert(ret);
    strcpy(ret, s);
    return ret;
}

char *get_dir(char *path)
{
    char *slash = strrchr(path, '/');
    if (!slash) {
        return NULL;
    }

    *slash = '\0';
    char *dir = mystrdup(path);
    *slash = '/';
    return dir;
}

char *make_message(const char *fmt, ...)
{
    int size = 0;
    char *buf = NULL;
    va_list ap;

    va_start(ap, fmt);
    size = vsnprintf(buf, size, fmt, ap);
    va_end(ap);

    if (size < 0)
        return NULL;
    
    size++;
    buf = malloc(size);
    if (buf == NULL)
        return NULL;
    
    va_start(ap, fmt);
    size = vsnprintf(buf, size, fmt, ap);
    if (size < 0) {
        free(buf);
        return NULL;
    }
    va_end(ap);

    return buf;
}

void find_rt(char *cmd)
{
    char *dir = get_dir(cmd);
    if (dir) {
        char *tmp = make_message("%s/libfinjpass.so", dir);
        if (access(tmp, R_OK) == 0) {
            rt_path = dir;
            free(tmp);
            return;
        }
        free(tmp);
        free(dir);
    }

    fprintf(stderr, "Unable to find 'libfinjpass.so'.\n");
}

void edit_args(int argc, char *argv[])
{
    cc_argc = 1;
    cc_argv = malloc((argc + 32) * sizeof(char *));

    char *name = strrchr(argv[0], '/');
    if (!name)
        name = argv[0];
    else
        name++;
    
    if (!strcmp(name, "finj-clang++"))
        cc_argv[0] = "clang++";
    else
        cc_argv[0] = "clang";

    cc_argv[cc_argc++] = "-Xclang";
    cc_argv[cc_argc++] = "-load";
    cc_argv[cc_argc++] = "-Xclang";
    cc_argv[cc_argc++] = make_message("%s/libfinjpass.so", rt_path);

    cc_argv[cc_argc++] = "-Qunused-arguments";

    int x_set = 0, maybe_linking = 1, bit_mode = 0;

    /* Detect stray -v calls from ./configure scripts. */
    if (argc == 1 && !strcmp(argv[1], "-v"))
        maybe_linking = 0;

    while (--argc) {
        char *cur = *(++argv);

        if (!strcmp(cur, "-m32"))
            bit_mode = 32;
        if (!strcmp(cur, "-m64"))
            bit_mode = 64;

        if (!strcmp(cur, "-x"))
            x_set = 1;

        if (!strcmp(cur, "-c") || !strcmp(cur, "-S") || !strcmp(cur, "-E"))
            maybe_linking = 0;

        if (!strcmp(cur, "-shared"))
            maybe_linking = 0;

        if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined"))
            continue;

        cc_argv[cc_argc++] = cur;
    }

    if (maybe_linking) {
        if (x_set) {
            cc_argv[cc_argc++] = "-x";
            cc_argv[cc_argc++] = "none";
        }

        // switch (bit_mode) {
        // case 0:
        //     cc_argv[cc_argc++] = make_message("%s/afl-llvm-rt.o", rt_path);
        //     break;
        // case 32:
        //     cc_argv[cc_argc++] = make_message("%s/afl-llvm-rt-32.o", rt_path);
        //     if (access(cc_argv[cc_argc - 1], R_OK)) {
        //         fprintf(stderr, "-m32 is not supported by your compiler");
        //         exit(1);
        //     }
        //     break;
        // case 64:
        //     cc_argv[cc_argc++] = make_message("%s/afl-llvm-rt-64.o", rt_path);
        //     if (access(cc_argv[cc_argc - 1], R_OK)) {
        //         fprintf(stderr, "-m64 is not supported by your compiler");
        //         exit(1);
        //     }
        //     break;
        // }
    }

    cc_argv[cc_argc] = NULL;
}

int main(int argc, char** argv)
{
    find_rt(argv[0]);

    edit_args(argc, argv);

    execvp(cc_argv[0], cc_argv);

    fprintf(stderr, "Fail to execute %s", cc_argv[0]);
    return 1;
}