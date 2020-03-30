#include "finj/config.h"
#include "finj/sys.h"

#include <dirent.h>
#include <sys/wait.h>

#include "finj/utils.h"

/* ------------------------------------------------
 *                    signal
 * ------------------------------------------------ */

sigfunc_t signal_intr(int signum, sigfunc_t func)
{
    struct sigaction act, oact;

    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
#ifdef SA_INTERRUPT
    act.sa_flags |= SA_INTERRUPT;
#endif
    if (sigaction(signum, &act, &oact) < 0)
        return SIG_ERR;
    return oact.sa_handler;
}

#define MAP_SIGNAL(f) \
    f(HUP) f(INT) f(QUIT) f(ILL) f(TRAP) \
    f(ABRT) f(BUS) f(FPE) f(KILL) f(USR1) \
    f(SEGV) f(USR2) f(PIPE) f(ALRM) f(TERM) \
    f(STKFLT) f(CHLD) f(CONT) f(STOP) f(TSTP) \
    f(TTIN) f(TTOU) f(URG) f(XCPU) f(XFSZ) \
    f(VTALRM) f(PROF) f(WINCH) f(IO) f(PWR) \
    f(SYS)

#define SIGNAL_NAME_ENTRY(name) [SIG##name] = "SIG"#name,

const char *signum_to_str(int signum)
{
    static const char *signum_to_str_table[] = {
        MAP_SIGNAL(SIGNAL_NAME_ENTRY)
    };

    if (signum <= 0 || signum >= ARRAY_LEN(signum_to_str_table))
        return "UNKNOWN";
    return signum_to_str_table[signum];
}

/* ------------------------------------------------
 *                    ptrace
 * ------------------------------------------------ */

int ptrace_traceme()
{
    return ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

int ptrace_syscall(pid_t pid, int sig)
{
    return ptrace(PTRACE_SYSCALL, pid, NULL, sig);
}

int ptrace_setoptions(pid_t pid, int options)
{
    return ptrace(PTRACE_SETOPTIONS, pid, NULL, options);
}

int ptrace_getregs(pid_t pid, struct user_regs_struct *regs)
{
    return ptrace(PTRACE_GETREGS, pid, NULL, regs);
}

int ptrace_setregs(pid_t pid, struct user_regs_struct *regs)
{
    return ptrace(PTRACE_SETREGS, pid, NULL, regs);
}

int ptrace_getsiginfo(pid_t pid, siginfo_t *siginfo)
{
    return ptrace(PTRACE_GETSIGINFO, pid, NULL, siginfo);
}

/* ------------------------------------------------
 *                      io
 * ------------------------------------------------ */

char *readline(FILE *stream, char *buf, size_t size)
{
    char *ret_val, *find;

    if (((ret_val = fgets(buf, size, stream)) == NULL) && ferror(stream))
        return (char *)-1;

    if (ret_val) {
        if ((find = strchr(buf, '\n')) != NULL) {
            *find = '\0';
        } else {
            while (1) {
                char eat = fgetc(stream);
                if (eat == '\n' || eat == EOF)
                    break;
            }
        }
    }
    return ret_val;
}

int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
    struct flock lock;

    lock.l_type = type;     /* F_RDLCK, F_WRLCK, F_UNLCK */
    lock.l_start = offset;  /* byte offset, relative to l_whence */
    lock.l_whence = whence; /* SEEK_SET, SEEK_CUR, SEEK_END */
    lock.l_len = len;       /* #bytes (0 means to EOF) */

    return fcntl(fd, cmd, &lock);
}

#ifndef OPEN_MAX
#define OPEN_MAX 1024
#endif /* OPEN_MAX */

static int try_close_all_fds(int (*whitelist)(int))
{
    DIR *dir;
    struct dirent *ent;
    int fds[OPEN_MAX];
    int end = 0;

    if ((dir = opendir("/proc/self/fd")) == NULL)
        return -1;

    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        /* We shouldn't close fd during traversing directory entries because
           this will delete entries at the same time in this directory */
        if (end >= OPEN_MAX)
            break;
        fds[end++] = atoi(ent->d_name);
    }

    if (closedir(dir) == -1)
        return -1;

    for (int i = 0; i < end; ++i) {
        if (whitelist && whitelist(fds[i]))
            continue;
        close(fds[i]);
    }

    return 0;
}

static void force_close_all_fds(int (*whitelist)(int))
{
    for (int fd = 0; fd < 256; ++fd) {
        if (whitelist && whitelist(fd))
            continue;
        close(fd);
    }
}

void close_all_fds(int (*whitelist)(int))
{
    if (try_close_all_fds(whitelist) == -1)
        force_close_all_fds(whitelist);
}

int proc_fstat(pid_t pid, int fd, struct stat *buf)
{
    char file[64];
    snprintf(file, ARRAY_LEN(file), "/proc/%d/fd/%d", (int)pid, fd);
    return stat(file, buf);
}

int proc_fd_name(pid_t pid, int fd, char *buf, size_t size)
{
    char link[64];
    size_t len;

    snprintf(link, ARRAY_LEN(link), "/proc/%d/fd/%d", (int)pid, fd);
    if ((len = readlink(link, buf, size)) == -1) {
        buf[0] = '\0';
        return -1;
    }

    if (len >= size) {
        errno = EINVAL;
        buf[0] = '\0';
        return -1;
    }

    buf[len] = '\0';
    return len;
}

int proc_traverse_fds(pid_t pid, void (*handle)(int))
{
    char dirname[128];
    DIR *dir;
    struct dirent *ent;

    snprintf(dirname, ARRAY_LEN(dirname), "/proc/%d/fd", (int)pid);
    if ((dir = opendir(dirname)) == NULL)
        return -1;

    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        handle(atoi(ent->d_name));
    }

    if (closedir(dir) == -1)
        return -1;

    return 0;
}

/* ------------------------------------------------
 *                     misc
 * ------------------------------------------------ */

int detached_fork()
{
    pid_t pid = fork();

    if (pid != 0) { /* Parent: the original process. */
        if (wait(NULL) != pid)
            return -1;
        return 1;
    }

    if ((pid = fork()) != 0)    /* Child */
        _exit(EXIT_SUCCESS);;

    return 0; /* Grandchild: a snapshot process. */
}

int find_in_array(int val, int arr[], int size)
{
    for (int i = 0; i < size; ++i)
        if (val == arr[i])
            return i;
    return -1;
}

/* ------------------------------------------------
 *                     syscall
 * ------------------------------------------------ */

#define MAP_SYSCALL(f) \
    f(_sysctl) f(accept) f(accept4) f(access) f(acct) \
    f(add_key) f(adjtimex) f(afs_syscall) f(alarm) f(arch_prctl) \
    f(bind) f(bpf) f(brk) f(capget) f(capset) \
    f(chdir) f(chmod) f(chown) f(chroot) f(clock_adjtime) \
    f(clock_getres) f(clock_gettime) f(clock_nanosleep) f(clock_settime) f(clone) \
    f(close) f(connect) f(creat) f(create_module) f(delete_module) \
    f(dup) f(dup2) f(dup3) f(epoll_create) f(epoll_create1) \
    f(epoll_ctl) f(epoll_ctl_old) f(epoll_pwait) f(epoll_wait) f(epoll_wait_old) \
    f(eventfd) f(eventfd2) f(execve) f(execveat) f(exit) \
    f(exit_group) f(faccessat) f(fadvise64) f(fallocate) f(fanotify_init) \
    f(fanotify_mark) f(fchdir) f(fchmod) f(fchmodat) f(fchown) \
    f(fchownat) f(fcntl) f(fdatasync) f(fgetxattr) f(finit_module) \
    f(flistxattr) f(flock) f(fork) f(fremovexattr) f(fsetxattr) \
    f(fstat) f(fstatfs) f(fsync) f(ftruncate) f(futex) \
    f(futimesat) f(get_kernel_syms) f(get_mempolicy) f(get_robust_list) f(get_thread_area) \
    f(getcpu) f(getcwd) f(getdents) f(getdents64) f(getegid) \
    f(geteuid) f(getgid) f(getgroups) f(getitimer) f(getpeername) \
    f(getpgid) f(getpgrp) f(getpid) f(getpmsg) f(getppid) \
    f(getpriority) f(getrandom) f(getresgid) f(getresuid) f(getrlimit) \
    f(getrusage) f(getsid) f(getsockname) f(getsockopt) f(gettid) \
    f(gettimeofday) f(getuid) f(getxattr) f(init_module) f(inotify_add_watch) \
    f(inotify_init) f(inotify_init1) f(inotify_rm_watch) f(io_cancel) f(io_destroy) \
    f(io_getevents) f(io_setup) f(io_submit) f(ioctl) f(ioperm) \
    f(iopl) f(ioprio_get) f(ioprio_set) f(kcmp) f(kexec_file_load) \
    f(kexec_load) f(keyctl) f(kill) f(lchown) f(lgetxattr) \
    f(link) f(linkat) f(listen) f(listxattr) f(llistxattr) \
    f(lookup_dcookie) f(lremovexattr) f(lseek) f(lsetxattr) f(lstat) \
    f(madvise) f(mbind) f(membarrier) f(memfd_create) f(migrate_pages) \
    f(mincore) f(mkdir) f(mkdirat) f(mknod) f(mknodat) \
    f(mlock) f(mlock2) f(mlockall) f(mmap) f(modify_ldt) \
    f(mount) f(move_pages) f(mprotect) f(mq_getsetattr) f(mq_notify) \
    f(mq_open) f(mq_timedreceive) f(mq_timedsend) f(mq_unlink) f(mremap) \
    f(msgctl) f(msgget) f(msgrcv) f(msgsnd) f(msync) \
    f(munlock) f(munlockall) f(munmap) f(name_to_handle_at) f(nanosleep) \
    f(newfstatat) f(nfsservctl) f(open) f(open_by_handle_at) f(openat) \
    f(pause) f(perf_event_open) f(personality) f(pipe) f(pipe2) \
    f(pivot_root) f(poll) f(ppoll) f(prctl) f(pread64) \
    f(preadv) f(prlimit64) f(process_vm_readv) f(process_vm_writev) f(pselect6) \
    f(ptrace) f(putpmsg) f(pwrite64) f(pwritev) f(query_module) \
    f(quotactl) f(read) f(readahead) f(readlink) f(readlinkat) \
    f(readv) f(reboot) f(recvfrom) f(recvmmsg) f(recvmsg) \
    f(remap_file_pages) f(removexattr) f(rename) f(renameat) f(renameat2) \
    f(request_key) f(restart_syscall) f(rmdir) f(rt_sigaction) f(rt_sigpending) \
    f(rt_sigprocmask) f(rt_sigqueueinfo) f(rt_sigreturn) f(rt_sigsuspend) f(rt_sigtimedwait) \
    f(rt_tgsigqueueinfo) f(sched_get_priority_max) f(sched_get_priority_min) f(sched_getaffinity) f(sched_getattr) \
    f(sched_getparam) f(sched_getscheduler) f(sched_rr_get_interval) f(sched_setaffinity) f(sched_setattr) \
    f(sched_setparam) f(sched_setscheduler) f(sched_yield) f(seccomp) f(security) \
    f(select) f(semctl) f(semget) f(semop) f(semtimedop) \
    f(sendfile) f(sendmmsg) f(sendmsg) f(sendto) f(set_mempolicy) \
    f(set_robust_list) f(set_thread_area) f(set_tid_address) f(setdomainname) f(setfsgid) \
    f(setfsuid) f(setgid) f(setgroups) f(sethostname) f(setitimer) \
    f(setns) f(setpgid) f(setpriority) f(setregid) f(setresgid) \
    f(setresuid) f(setreuid) f(setrlimit) f(setsid) f(setsockopt) \
    f(settimeofday) f(setuid) f(setxattr) f(shmat) f(shmctl) \
    f(shmdt) f(shmget) f(shutdown) f(sigaltstack) f(signalfd) \
    f(signalfd4) f(socket) f(socketpair) f(splice) f(stat) \
    f(statfs) f(swapoff) f(swapon) f(symlink) f(symlinkat) \
    f(sync) f(sync_file_range) f(syncfs) f(sysfs) f(sysinfo) \
    f(syslog) f(tee) f(tgkill) f(time) f(timer_create) \
    f(timer_delete) f(timer_getoverrun) f(timer_gettime) f(timer_settime) f(timerfd_create) \
    f(timerfd_gettime) f(timerfd_settime) f(times) f(tkill) f(truncate) \
    f(tuxcall) f(umask) f(umount2) f(uname) f(unlink) \
    f(unlinkat) f(unshare) f(uselib) f(userfaultfd) f(ustat) \
    f(utime) f(utimensat) f(utimes) f(vfork) f(vhangup) \
    f(vmsplice) f(vserver) f(wait4) f(waitid) f(write) \
    f(writev)

#define SYSCALL_NAME_ENTRY(name) [SYS_##name] = #name,

const char *syscall_name(int syscall_num)
{
    static const char *syscall_name_table[] = {
        MAP_SYSCALL(SYSCALL_NAME_ENTRY)
    };

    if (syscall_num < 0 || syscall_num >= ARRAY_LEN(syscall_name_table))
        return "UNKNOWN";
    return syscall_name_table[syscall_num];
}
