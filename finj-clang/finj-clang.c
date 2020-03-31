#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>

#define FINJ_LLVM_PASS_LIB  "libfinj-llvm-pass.so"
#define FINJ_LLVM_RT_LIB    "libfinj-llvm-rt.a"

#define die(fmt, ...) \
    do { \
        fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
        fflush(stderr); \
        exit(EXIT_FAILURE); \
    } while(0)

char *mystrdup(const char *s)
{
    assert(s);
    char *ret = (char *)malloc((strlen(s) + 1) * sizeof(char));
    if (ret == NULL)
        die("malloc error");
    strcpy(ret, s);
    return ret;
}

char *alloc_printf(const char *fmt, ...)
{
    int size = 0;
    char *buf = NULL;
    va_list ap;

    va_start(ap, fmt);
    size = vsnprintf(buf, size, fmt, ap);
    va_end(ap);

    if (size < 0)
        die("vsnprintf error");

    size++;
    buf = malloc(size);
    if (buf == NULL)
        die("malloc error");

    va_start(ap, fmt);
    size = vsnprintf(buf, size, fmt, ap);
    if (size < 0) {
        free(buf);
        die("vsnprintf error");
    }
    va_end(ap);

    return buf;
}

char *dup_dir(char *path)
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

/* Return the path of FINJ_LLVM_RT_LIB and FINJ_LLVM_PASS_LIB */
const char *find_lib_path(char *cmd)
{
    /* First try the directory where the cmd is built. */
    char *dir = dup_dir(cmd);
    if (dir) {
        char *tmp = alloc_printf("%s/" FINJ_LLVM_RT_LIB, dir);
        if (access(tmp, R_OK) == 0) {
            free(tmp);
            return dir;
        }
        free(tmp);
        free(dir);
    }

    /* Try the directory where the cmd is installed. */
    const char *tmp = FINJ_LIB_PATH "/" FINJ_LLVM_RT_LIB;
    if (access(tmp, R_OK) == 0)
        return FINJ_LIB_PATH;

    die("Unable to find " FINJ_LLVM_RT_LIB);
}

int edit_args(char *cc_argv[], size_t len,
              int argc, char *argv[], const char *lib_path)
{
    if ((int)len - argc < 16)
        die("Lack spaces to store cc_argv.");

    /* Choose between clang or clang++. */
    char *cmd = strrchr(argv[0], '/');
    if (!cmd)
        cmd = argv[0];
    else
        cmd++;
    if (!strcmp(cmd, "finj-clang++"))
        cc_argv[0] = "clang++";
    else
        cc_argv[0] = "clang";

    int cc_argc = 1;
    int x_set = 0, maybe_linking = 1, bit_mode = 0;

    /* Set arguments to load pass lib. */
    cc_argv[cc_argc++] = "-Xclang";
    cc_argv[cc_argc++] = "-load";
    cc_argv[cc_argc++] = "-Xclang";
    cc_argv[cc_argc++] = alloc_printf("%s/" FINJ_LLVM_PASS_LIB, lib_path);

    cc_argv[cc_argc++] = "-Qunused-arguments";

    /* Detect stray -v calls from ./configure scripts. */
    if (argc > 1 && !strcmp(argv[1], "-v"))
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

        if (!strcmp(cur, "-Wl,-z,defs") || !strcmp(cur, "-Wl,--no-undefined"))
            continue;

        cc_argv[cc_argc++] = cur;
    }

    if (maybe_linking) {
        if (x_set) {
            cc_argv[cc_argc++] = "-x";
            cc_argv[cc_argc++] = "none";
        }

        if (bit_mode != 0) {
            // TODO: support it.
            die("-m32 and -m64 is not supported.");
        }

        cc_argv[cc_argc++] = alloc_printf("%s/" FINJ_LLVM_RT_LIB, lib_path);

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
    return cc_argc;
}

int main(int argc, char** argv)
{
    if (argc < 2) {
        die("This is a clang wrapper for finj's instrumentation. It serves as a\n"
            "drop-in replacement for clang, letting you recompile third-party\n"
            "code with the required runtime instrumentation. A common use pattern\n"
            "would be one of the following:\n\n"

            "  CC=finj-clang ./configure\n"
            "  CXX=finj-clang++ ./configure\n");
    }

    size_t len = argc + 32;
    char **cc_argv = malloc(len * sizeof(cc_argv[0]));
    assert(cc_argv);

    edit_args(cc_argv, len, argc, argv, find_lib_path(argv[0]));

    execvp(cc_argv[0], cc_argv);
    die("Fail to execute %s", cc_argv[0]);
}