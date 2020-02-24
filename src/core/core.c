#include "../config.h"
#include "../sys.h"

#include <sys/wait.h>
#include <sys/mman.h>

#include "log.h"
#include "utils.h"
#include "sched.h"

#define SNAPSHOT_PROC 0
#define ORIGINAL_PROC 1

static int fork_snapshot();
static void init_snapshot();
static void init_monitor(pid_t pid);
static void snapshot_exit(int status);
static void monitor_exit(int status);
static void synchronize_with_snapshot();
static void synchronize_with_monitor();
static void monitor_loop(pid_t pid);

static void init_fds_info(pid_t pid);
static void unmap_shared_memory();
static void log_unmapped_areas();

int checkpoint(const char *funcname, const char *file,
               const char *caller, int line)
{
    if (is_during_test()) {
        /* Determine whether to terminate the test. */
        if (is_time_to_exit_test()) {
            log_debug("(snapshot)Exit from %s[%s:%s:%d]",
                      funcname, file, caller, line);
            snapshot_exit(EXIT_SUCCESS);
        }
        return 0;
    }

    if (!is_time_to_enter_test())
        return 0;

    /* Otherwise, we fork a snapshot and begin test. */
    int id;

    if ((id = fork_snapshot()) < 0) {
        log_unix_error("Fail to snapshot"); /* Will initialize log automatically */
        return 0;   /* Ignore snapshot error and continue. */
    }

    /* Original process: continue. */
    if (id == ORIGINAL_PROC)
        return 0;

    /* Snapshot process: fork a monitor and prepare test environment. */
    init_snapshot();
    log_debug("(snapshot)Enter from %s[%s:%s:%d]", funcname, file, caller, line);
    return 1;
}

/* Create a snapshot. */
static int fork_snapshot()
{
    pid_t pid;

    if ((pid = fork()) < 0)
        return -1;

    if (pid != 0) {
        setpgid(pid, pid);
        return ORIGINAL_PROC;
    }

    setpgid(getpid(), 0);   /* Avoid signals from the parent process group. */
    return SNAPSHOT_PROC;
}

static void init_snapshot()
{
    /* Note: we can only use log() with exit() followed before the
       monitor is initialized. That is say, we can only log() before
       the snapshot is going to terminate. */
    unmap_shared_memory();

    pid_t pid;
    if ((pid = fork()) < 0) {
        log_unix_error("Fail to fork a monitor");
        snapshot_exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        init_monitor(pid);
        synchronize_with_snapshot(pid);
        monitor_loop(pid);
        monitor_exit(EXIT_SUCCESS);
    }

    set_during_test(1);
    synchronize_with_monitor();
}

static void init_monitor(pid_t pid)
{
    close_all_fds(NULL);
    init_fds_info(pid);
    log_unmapped_areas();
}

static void snapshot_exit(int status)
{
    close_all_fds(NULL); /* Prevent flush streams. */
    _exit(status);       /* Prevent intrigue handlers registered in atexit(). */
}

static void monitor_exit(int status)
{
    _exit(status);
}

static void synchronize_with_monitor()
{
    if (ptrace_traceme() != 0) {
        log_unix_error("ptrace_traceme error");
        snapshot_exit(EXIT_FAILURE);
    }
    raise(SIGTRAP);
}

static void synchronize_with_snapshot(pid_t pid)
{
    int status;

    if (waitpid(pid, &status, 0) == -1) {
        log_unix_error("Fails to wait the snapshot to raise SIGTRAP");
        monitor_exit(EXIT_FAILURE);
    }
    if (WIFEXITED(status)) {
        /* The child early exited for some errors. */
        log_warn("Snapshot early exited for some errors.");
        monitor_exit(EXIT_FAILURE);
    }
    if (!WIFSTOPPED(status)) {
        /* The child is killed by some unexpected events. */
        log_error("Got some unexpected events during synchronization.");
        monitor_exit(EXIT_FAILURE);
    }
    /* Set PTRACE_O_EXITKILL so that monitor make child exit by exit itself. */
    if (ptrace_setoptions(pid, PTRACE_O_EXITKILL) != 0) {
        log_unix_error("ptrace_setoptions error");
        monitor_exit(EXIT_FAILURE);
    }
    log_info("(monitor)Trace (%d)", (int)pid);
    if (ptrace_syscall(pid, 0) != 0) {
        log_unix_error("ptrace_syscall error");
        monitor_exit(EXIT_FAILURE);
    }
}

/* Define context for syscall and signal handlers */
struct context {
    pid_t pid;

    /* Prepared for syscall handlers. */
    struct user_regs_struct regs;

    /* Set by syscall handlers to indicate which return value to fake
       when returning SYSCALL_FAKE. */
    int fake_retval;

    /* Inform signal handler which signal causes the stop. Signal handler
       can reset this field to tell the monitor whether to suppress the
       signal. */
    int signum;
};

/* Define results for syscall handlers. */
enum {
    SYSCALL_CONT,
    SYSCALL_TERM,
    SYSCALL_FAKE,
};

/* Define macros to manipulate struct user_regs_struct. */
#define SYSCALL_NUM(regs) ((regs)->orig_rax)
#define SYSCALL_NAME(regs) (syscall_name(SYSCALL_NUM(regs)))
#define SYSCALL_RET(regs) ((regs)->rax)
#define SYSCALL_ARG1(regs) ((regs)->rdi)
#define SYSCALL_ARG2(regs) ((regs)->rsi)
#define SYSCALL_ARG3(regs) ((regs)->rdx)
#define SYSCALL_ARG4(regs) ((regs)->r10)
#define SYSCALL_ARG5(regs) ((regs)->r8)
#define SYSCALL_ARG6(regs) ((regs)->r9)

static void log_syscall_handler_result(int result, struct context *ctx);
static int handle_enter_syscall(struct context *ctx);
static void handle_exit_syscall(struct context *ctx);
static void handle_signal(struct context *ctx);

static void monitor_loop(pid_t pid)
{
    int status, on_enter, result;
    struct context ctx;

    on_enter = 0;
    result = SYSCALL_CONT;
    ctx.pid = pid;

    /* Trace the child's syscalls and signals. */
    do {
        if (waitpid(pid, &status, 0) == -1) {
            log_unix_error("(monitor)waitpid error");
            monitor_exit(EXIT_FAILURE);
        }
        if (WIFSTOPPED(status)) {
            if (WSTOPSIG(status) == SIGTRAP) {
                /* Handle syscall. */
                if (ptrace_getregs(pid, &ctx.regs) != 0) {
                    log_unix_error("ptrace_getregs error");
                    monitor_exit(EXIT_FAILURE);
                }
                on_enter ^= 1;
                if (on_enter) {
                    result = handle_enter_syscall(&ctx);
                    assert(result == SYSCALL_TERM || result == SYSCALL_FAKE ||
                           result == SYSCALL_CONT);
                    log_syscall_handler_result(result, &ctx);
                    if (result == SYSCALL_TERM)
                        monitor_exit(EXIT_SUCCESS);
                    if (result == SYSCALL_FAKE) {
                        SYSCALL_NUM(&ctx.regs) = -1;
                        if (ptrace_setregs(pid, &ctx.regs) != 0) {
                            log_unix_error("ptrace_setregs error");
                            monitor_exit(EXIT_FAILURE);
                        }
                    }
                } else {
                    handle_exit_syscall(&ctx);
                    if (result == SYSCALL_FAKE) {
                        SYSCALL_RET(&ctx.regs) = ctx.fake_retval;
                        if (ptrace_setregs(pid, &ctx.regs) != 0) {
                            log_unix_error("ptrace_setregs error");
                            monitor_exit(EXIT_FAILURE);
                        }
                    }
                }
                if (ptrace_syscall(pid, 0) != 0) {
                    log_unix_error("Ptrace syscall error");
                    monitor_exit(EXIT_FAILURE);
                }
            } else {
                /* Handle signal. */
                ctx.signum = WSTOPSIG(status);
                log_warn("(monitor)See signal %s", signum_to_str(ctx.signum));
                handle_signal(&ctx);
                if (ptrace_syscall(pid, ctx.signum) != 0) {
                    log_unix_error("Ptrace syscall error");
                    monitor_exit(EXIT_FAILURE);
                }
            }
        }
        else if (WIFEXITED(status)) {
            log_info("(monitor)Snapshot exit with %d", WEXITSTATUS(status));
        }
        else if (WIFSIGNALED(status)) {
            log_warn("(monitor)Snapshot killed by sig %s",
                     signum_to_str(WTERMSIG(status)));
        }
        else if (WIFCONTINUED(status)) {
            log_warn("(monitor)Snapshot continued");
        }
        else {
            log_error("(monitor)Unexpected wait status");
            monitor_exit(EXIT_FAILURE);
        }
    } while(!WIFEXITED(status) && !WIFSIGNALED(status));
}

static void log_syscall_handler_result(int result, struct context *ctx)
{
    if (result == SYSCALL_CONT) {
        log_info("(monitor)leak syscall %s", SYSCALL_NAME(&ctx->regs));
    } else if (result == SYSCALL_TERM) {
        log_info("(monitor)intercept syscall %s", SYSCALL_NAME(&ctx->regs));
    } else if (result == SYSCALL_FAKE) {
        log_info("(monitor)fake syscall %s", SYSCALL_NAME(&ctx->regs));
    }
}

static int in_side_effect_list(int syscall_num);
static int on_enter_open(struct context *ctx);
static int on_enter_openat(struct context *ctx);
static void on_exit_open(struct context *ctx);
static void on_exit_openat(struct context *ctx);
static void on_exit_close(struct context *ctx);
static int on_enter_read(struct context *ctx);
static int on_enter_lseek(struct context *ctx);
static int on_enter_write(struct context *ctx);

static int handle_enter_syscall(struct context *ctx)
{
    int syscall_num = SYSCALL_NUM(&ctx->regs);

    /* Roughly filter syscalls without side effects. */
    if (!in_side_effect_list(syscall_num))
        return SYSCALL_CONT;

    /* Futher determine whether the syscall has side effects. */
    switch (syscall_num) {
    case SYS_open: return on_enter_open(ctx);
    case SYS_openat: return on_enter_openat(ctx);
    case SYS_read: return on_enter_read(ctx);
    case SYS_lseek: return on_enter_lseek(ctx);
    case SYS_write: return on_enter_write(ctx);
    default:
        return SYSCALL_TERM;
    }
}

static void handle_exit_syscall(struct context *ctx)
{
    switch (SYSCALL_NUM(&ctx->regs)) {
    case SYS_open: on_exit_open(ctx); break;
    case SYS_openat: on_exit_openat(ctx); break;
    case SYS_close: on_exit_close(ctx); break;
    default: /* Do nothing. */
        break;
    }
}

/* Define syscalls with side effects and map it with some macro function. */
#define MAP_SYSCALL_WITH_SIDE_EFFECTS(f) \
    f(read) f(write) f(open) f(openat) f(lseek) \
    f(ioctl) f(pread64) f(pwrite64) f(readv) f(writev) f(preadv) f(pwritev) \
    f(mmap) f(munmap) f(mremap) f(msync) \
    f(shmat) f(shmctl) f(shmdt) \
    f(sendfile) \
    f(connect) f(accept) f(accept4) f(listen) \
    f(sendto) f(recvfrom) f(sendmsg) f(recvmsg) f(sendmmsg) f(recvmmsg) \
    f(clone) f(fork) f(vfork) /* We don't plan to intercept the cloned child process. */ \
    f(kill) f(tkill) f(tgkill) \
    f(semop) f(semctl) \
    f(msgget) f(msgsnd) f(msgrcv) f(msgctl) \
    f(fcntl) f(flock) f(fsync) f(fdatasync) f(sync) f(syncfs) \
    f(truncate) f(ftruncate) \
    f(rename) f(renameat) f(renameat2) \
    f(mkdir) f(rmdir) f(mkdirat) \
    f(creat) f(link) f(linkat) f(unlink) f(unlinkat) f(symlink) f(symlinkat) \
    f(chmod) f(fchmod) f(fchmodat) \
    f(chown) f(fchown) f(lchown) f(fchownat) \
    f(setrlimit) f(settimeofday) \
    f(mknod) f(mknodat) \
    f(mount) f(umount2) \
    f(setxattr) f(lsetxattr) f(fsetxattr) f(removexattr) f(lremovexattr) f(fremovexattr) \
    f(inotify_init) f(inotify_init1) f(inotify_add_watch) f(inotify_rm_watch) \
    /* NOTE: I am not so familiar with syscalls below. */ \
    f(futimesat) f(fallocate) \
    f(ioperm) f(iopl) \

#define SYSCALL_ADD_PREFIX(name)  SYS_##name,

static int side_effect_list[] = {
    MAP_SYSCALL_WITH_SIDE_EFFECTS(SYSCALL_ADD_PREFIX)
};

static int in_side_effect_list(int syscall_num)
{
    return find_in_array(syscall_num, side_effect_list, ARRAY_LEN(side_effect_list)) != -1;
}

/* In order to avoid the snapshot generating side effects and make it
   run as long as possible, let us define legal io syscall sequence that
   the snapshot can execute on a file (or devices, etc.).

   First, there are four kinds of abstract io syscalls: 'o', 'c', 'w',
   and 'r'.
     - The 'o' indicates open syscalls such as open(), openat().
     - The 'c' indicates close syscalls such as close().
     - The 'r' indicates io syscalls which don't modify files (but may
       modify file-related data in the kernel) such as read() and lseek().
     - The 'w' indicates write syscalls which literally modify files such
       as write() and thus cause side effects. However, here we will virtually
       execute this operation by ptrace.

   Now let's define legal io syscall sequence for different kinds of files.
   A legal io syscall sequence is a sequence of the four abstract io syscalls.
   Here, we use regular expressions to express the legal sequence.
     - Files inhereted from the parent ---- "w*c?"
     - Files opened by the snapshot
         - log file ----------------------- "o(r|w)*c?"
         - with O_CREAT ------------------- ""
         - without O_CREAT
           - reg/dir ---------------------- "or*w*c?"
           - not reg/dir ------------------ "ow*c?"

   The data structures and syscall handlers below are implemented to avoid
   the snapshot generating illegal io syscall sequences as defined above. */

/* Based on the legal io syscall sequence defined above, if we focus only
   on 'r' and 'w' operations and discard 'o' and 'c' operations, we can
   define four authorities for 'r' and 'w' operations:
     - EMPTY: any io syscalls are forbidden.
     - ANY: any io syscalls can be done.
     - W_STAR: the legal syscall sequence for a file is 'w*'.
     - R_STAR_W_STAR: the legal syscall sequence for a file is 'r*w*'.

   Now we assign these authorities to different kind of files:
     - Inhereted from the parent ---- (W_STAR)
     - Opened by the snapshot
         - log file ----------------- (ANY)
         - with O_CREAT ------------- (EMPTY)
         - without O_CREAT
           - reg/dir ---------------- (R_STAR_W_STAR)
           - not reg/dir ------------ (W_STAR)

   We use 'fd_info' below to record authorities for fds. It will set
   authorities of all fds that inherited from parent as W_STAR on
   initialization and privoid methods for monitor to change the authority
   of fds after seeing the snapshot do any io operations on it. */

#ifndef OPEN_MAX
#define OPEN_MAX 1024
#endif /* OPEN_MAX */

enum {
    AUTH_EMPTY = 0,
    AUTH_ANY,
    AUTH_W_STAR,
    AUTH_R_STAR_W_STAR
};

struct {
    int auth[OPEN_MAX];
    int can_r[OPEN_MAX];
} fds_info;

static void fds_info_check_fd(int fd)
{
    if (fd < 0 || fd >= OPEN_MAX) {
        log_error("fds_info_check_fd: invalid fd %d", fd);
        monitor_exit(EXIT_FAILURE);
    }
}

static int fds_info_get_auth(int fd)
{
    fds_info_check_fd(fd);
    return fds_info.auth[fd];
}

static void fds_info_set_auth(int fd, int auth)
{
    fds_info_check_fd(fd);
    fds_info.auth[fd] = auth;
}

static int fds_info_get_can_r(int fd)
{
    fds_info_check_fd(fd);
    return fds_info.can_r[fd];
}

static void fds_info_set_can_r(int fd, int can_r)
{
    fds_info_check_fd(fd);
    fds_info.can_r[fd] = can_r;
}

static void fds_info_reset_fd(int fd)
{
    fds_info_check_fd(fd);
    fds_info.auth[fd] = AUTH_EMPTY;
    fds_info.can_r[fd] = 1;
}

static void set_auth_of_inherited_fd(int fd)
{
    fds_info_set_auth(fd, AUTH_W_STAR);
}

static void init_fds_info(pid_t pid)
{
    for (int i = 0; i < OPEN_MAX; ++i)
        fds_info_reset_fd(i);

    if (proc_traverse_fds(pid, set_auth_of_inherited_fd) != 0) {
        log_unix_error("proc_traverse_fds error");
        monitor_exit(EXIT_FAILURE);
    }
}

/* Below are handlers of abstract io syscalls as we defined. They will
   be called by concrete io syscall handlers such as open(), read(),
   lseek(), and write().

   On seeing 'o' syscalls, if the file can be opened (e.g, the O_CREAT
   flag is not set), monitor will assign the authority for opened fds
   according to our definition.

   On seeing 'c' syscalls, monitor will clear the authority infomation
   for the closed fd.

   On seeing 'r' and 'w' syscalls, monitor will determine whether to
   intercept this syscall according to the authority of the fd. Monitor
   will also forbid a R_STAR_W_STAR fd reading after seeing it do a 'w'
   syscall. */

static int is_reg_or_dir(int dirfd, const char *filename)
{
    struct stat sbuf;
    if (fstatat(dirfd, filename, &sbuf, 0) != 0) {
        if (errno != ENOENT)    /* Ignore ENOENT */
            log_unix_error("stat %s error", filename);
        monitor_exit(EXIT_FAILURE);
    }
    return (S_ISREG(sbuf.st_mode) || S_ISDIR(sbuf.st_mode));
}

static int set_auth_on_exit_o;

static int on_enter_o(int dirfd, const char *filename, int flags)
{
    set_auth_on_exit_o = AUTH_EMPTY;

    if (filename && strcmp(filename, LOG_FILE) == 0) {
        set_auth_on_exit_o = AUTH_ANY;
        return SYSCALL_CONT;
    }

    if (flags & O_CREAT)
        return SYSCALL_TERM;

    if (is_reg_or_dir(dirfd, filename))
        set_auth_on_exit_o = AUTH_R_STAR_W_STAR;
    else
        set_auth_on_exit_o = AUTH_W_STAR;
    return SYSCALL_CONT;
}

static void on_exit_o(int ret_fd)
{
    if (ret_fd < 0)
        return;
    fds_info_set_auth(ret_fd, set_auth_on_exit_o);
}

static void on_exit_c(int ret, int fd)
{
    if (ret < 0)
        return;
    fds_info_reset_fd(fd);
}

static int on_enter_r(int fd)
{
    if (fds_info_get_auth(fd) == AUTH_ANY)
        return SYSCALL_CONT;

    if (fds_info_get_auth(fd) == AUTH_W_STAR)
        return SYSCALL_TERM;

    if (fds_info_get_auth(fd) == AUTH_R_STAR_W_STAR)
        return (fds_info_get_can_r(fd) ? SYSCALL_CONT : SYSCALL_TERM);

    return SYSCALL_TERM;
}

static int on_enter_w(int fd)
{
    if (fds_info_get_auth(fd) == AUTH_ANY)
        return SYSCALL_CONT;    /* It is safe to write log file. */

    if (fds_info_get_auth(fd) == AUTH_W_STAR)
        return SYSCALL_FAKE;

    if (fds_info_get_auth(fd) == AUTH_R_STAR_W_STAR) {
        fds_info_set_can_r(fd, 0);
        return SYSCALL_FAKE;
    }

    return SYSCALL_TERM;
}

/* Below are concrete syscall handlers. */

static int on_enter_open(struct context *ctx)
{
    const char *filename = (const char *)SYSCALL_ARG1(&ctx->regs);
    int flags = (int)SYSCALL_ARG2(&ctx->regs);
    return on_enter_o(AT_FDCWD, filename, flags);
}

static int on_enter_openat(struct context *ctx)
{
    int dirfd = (int)SYSCALL_ARG1(&ctx->regs);
    const char *filename = (const char *)SYSCALL_ARG2(&ctx->regs);
    int flags = (int)SYSCALL_ARG3(&ctx->regs);
    return on_enter_o(dirfd, filename, flags);
}

static void on_exit_open(struct context *ctx)
{
    on_exit_o((int)SYSCALL_RET(&ctx->regs));
}

static void on_exit_openat(struct context *ctx)
{
    on_exit_o((int)SYSCALL_RET(&ctx->regs));
}

static void on_exit_close(struct context *ctx)
{
    int fd = (int)SYSCALL_ARG1(&ctx->regs);
    on_exit_c((int)SYSCALL_RET(&ctx->regs), fd);
}

static int on_enter_lseek(struct context *ctx)
{
    int fd = (int)SYSCALL_ARG1(&ctx->regs);
    return on_enter_r(fd);
}

static int on_enter_read(struct context *ctx)
{
    int fd = (int)SYSCALL_ARG1(&ctx->regs);
    return on_enter_r(fd);
}

static int on_enter_write(struct context *ctx)
{
    int fd = (int)SYSCALL_ARG1(&ctx->regs);
    int result = on_enter_w(fd);

    if (result == SYSCALL_FAKE) {
        size_t bufsize = (size_t)SYSCALL_ARG3(&ctx->regs);
        ctx->fake_retval = bufsize;
    }

    return result;
}

/* Signal handlers are used to catch SIGSEGV signal, which is our test
   oracle. However, since we unmap shared memories in snapshot to avoid
   side effects, we should ignore the SIGSEGV signal caused by snapshot's
   access of these unmapped areas. */

static int in_unmapped_areas(void *addr);

static void handle_signal(struct context *ctx)
{
    if (ctx->signum == SIGSEGV) {
        siginfo_t siginfo;
        ptrace_getsiginfo(ctx->pid, &siginfo);
        if (in_unmapped_areas(siginfo.si_addr))
            return;
        log_fatal("(monitor)Catch SIGSEGV!");
    }
}

/* unmapped_areas: record unmapped areas. */

#define MAX_UNMAPPED_AREAS 64

struct area {
    void *begin;
    void *end;
};

struct {
    struct area areas[MAX_UNMAPPED_AREAS];
    int n_areas;
} unmapped_areas;

static void init_unmapped_areas()
{
    unmapped_areas.n_areas = 0;
}

static void unmapped_areas_add(void *begin, void *end)
{
    if (unmapped_areas.n_areas >= MAX_UNMAPPED_AREAS) {
        log_error("unmapped_areas_add error");
        snapshot_exit(EXIT_FAILURE);
    }
    unmapped_areas.areas[unmapped_areas.n_areas].begin = begin;
    unmapped_areas.areas[unmapped_areas.n_areas].end = end;
    unmapped_areas.n_areas++;
}

static int in_unmapped_areas(void *addr)
{
    for (int i = 0; i < unmapped_areas.n_areas; ++i)
        if (addr >= unmapped_areas.areas[i].begin &&
            addr < unmapped_areas.areas[i].end)
            return 1;
    return 0;
}

static void log_unmapped_areas()
{
    for (int i = 0; i < unmapped_areas.n_areas; ++i)
        log_info("unmap %p-%p", unmapped_areas.areas[i].begin,
                 unmapped_areas.areas[i].end);
}

static int memory_is_shared_and_writable(const char *perms)
{
    return (strchr(perms, 's') && strchr(perms, 'w'));
}

static void unmap_shared_memory()
{
    FILE *fp;
    char line[128], perms[8];
    void *mem_begin, *mem_end;

    init_unmapped_areas();

    if ((fp = fopen("/proc/self/maps", "r")) == NULL) {
        log_unix_error("fopen error");
        snapshot_exit(EXIT_FAILURE);
    }

    while (1) {
        char *ret = readline(fp, line, ARRAY_LEN(line));
        if (ret == (char *)-1) {
            log_unix_error("readline error");
            snapshot_exit(EXIT_FAILURE);
        }
        if (!ret)
            break;

        sscanf(line, "%p-%p %s", &mem_begin, &mem_end, perms);
        if (memory_is_shared_and_writable(perms)) {
            if (munmap(mem_begin, mem_end - mem_begin) == -1) {
                log_unix_error("munmap error");
                snapshot_exit(EXIT_FAILURE);
            }
            unmapped_areas_add(mem_begin, mem_end);
        }
    }
}