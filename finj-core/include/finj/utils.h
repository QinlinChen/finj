#ifndef _FINJ_UTILS_H
#define _FINJ_UTILS_H

#include <stdio.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>

#define ARRAY_LEN(x)   (sizeof(x) / sizeof((x)[0]))
#define RAND_CHOOSE_FROM(x) ((x)[rand() % ARRAY_LEN(x)])

/* signal */
typedef void (*sigfunc_t)(int);
sigfunc_t signal_intr(int signum, sigfunc_t func);
const char *signum_to_str(int signum);

/* ptrace */
int ptrace_traceme();
int ptrace_syscall(pid_t pid, int sig);
int ptrace_setoptions(pid_t pid, int options);
int ptrace_getregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_setregs(pid_t pid, struct user_regs_struct *regs);
int ptrace_getsiginfo(pid_t pid, siginfo_t *siginfo);

/* io */
char *readline(FILE *stream, char *buf, size_t size);
int lock_reg(int fd, int cmd, int type, off_t offset, int whence, off_t len);

void close_all_fds(int (*whitelist)(int));
int proc_fstat(pid_t pid, int fd, struct stat *buf);
int proc_fd_name(pid_t pid, int fd, char *buf, size_t size);
int proc_traverse_fds(pid_t pid, void (*handle)(int));
int proc_mem_read(pid_t pid, long addr, char *buf, size_t size);
const char *proc_path_read(pid_t pid, const char *addr);

/* misc */
int find_in_array(int val, int arr[], int size);
const char *syscall_name(int syscall_num);

#endif /* _FINJ_UTILS_H */