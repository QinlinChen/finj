/* Generated by genhack.py */
#ifndef _FINJ_HOOK_H
#define _FINJ_HOOK_H

#include <dirent.h>

#ifndef open
int finj_open(const char *file, const char *caller, int line, const char * pathname, int flags, ...);
#define open(...) finj_open(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_open
#endif /* open */

#ifndef openat
int finj_openat(const char *file, const char *caller, int line, int dirfd, const char * pathname, int flags, ...);
#define openat(...) finj_openat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_openat
#endif /* openat */


#ifndef malloc
void * finj_malloc(const char *file, const char *caller, int line, size_t size);
#define malloc(...) finj_malloc(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_malloc
#endif /* malloc */

#ifndef calloc
void * finj_calloc(const char *file, const char *caller, int line, size_t nmemb, size_t size);
#define calloc(...) finj_calloc(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_calloc
#endif /* calloc */

#ifndef realloc
void * finj_realloc(const char *file, const char *caller, int line, void * ptr, size_t size);
#define realloc(...) finj_realloc(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_realloc
#endif /* realloc */

#ifndef mmap
void * finj_mmap(const char *file, const char *caller, int line, void * addr, size_t length, int prot, int flags, int fd, off_t offset);
#define mmap(...) finj_mmap(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_mmap
#endif /* mmap */

#ifndef fstat
int finj_fstat(const char *file, const char *caller, int line, int fd, struct stat * buf);
#define fstat(...) finj_fstat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fstat
#endif /* fstat */

#ifndef lstat
int finj_lstat(const char *file, const char *caller, int line, const char * pathname, struct stat * buf);
#define lstat(...) finj_lstat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_lstat
#endif /* lstat */

#ifndef fstatat
int finj_fstatat(const char *file, const char *caller, int line, int dirfd, const char * pathname, struct stat * buf, int flags);
#define fstatat(...) finj_fstatat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fstatat
#endif /* fstatat */

#ifndef creat
int finj_creat(const char *file, const char *caller, int line, const char * pathname, mode_t mode);
#define creat(...) finj_creat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_creat
#endif /* creat */

#ifndef lseek
off_t finj_lseek(const char *file, const char *caller, int line, int fd, off_t offset, int whence);
#define lseek(...) finj_lseek(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_lseek
#endif /* lseek */

#ifndef read
ssize_t finj_read(const char *file, const char *caller, int line, int fd, void * buf, size_t count);
#define read(...) finj_read(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_read
#endif /* read */

#ifndef write
ssize_t finj_write(const char *file, const char *caller, int line, int fd, const void * buf, size_t count);
#define write(...) finj_write(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_write
#endif /* write */

#ifndef close
int finj_close(const char *file, const char *caller, int line, int fd);
#define close(...) finj_close(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_close
#endif /* close */

#ifndef fopen
FILE * finj_fopen(const char *file, const char *caller, int line, const char * path, const char * mode);
#define fopen(...) finj_fopen(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fopen
#endif /* fopen */

#ifndef fdopen
FILE * finj_fdopen(const char *file, const char *caller, int line, int fd, const char * mode);
#define fdopen(...) finj_fdopen(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fdopen
#endif /* fdopen */

#ifndef freopen
FILE * finj_freopen(const char *file, const char *caller, int line, const char * path, const char * mode, FILE * stream);
#define freopen(...) finj_freopen(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_freopen
#endif /* freopen */

#ifndef rename
int finj_rename(const char *file, const char *caller, int line, const char * oldpath, const char * newpath);
#define rename(...) finj_rename(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_rename
#endif /* rename */

#ifndef renameat
int finj_renameat(const char *file, const char *caller, int line, int olddirfd, const char * oldpath, int newdirfd, const char * newpath);
#define renameat(...) finj_renameat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_renameat
#endif /* renameat */

#ifndef link
int finj_link(const char *file, const char *caller, int line, const char * oldpath, const char * newpath);
#define link(...) finj_link(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_link
#endif /* link */

#ifndef linkat
int finj_linkat(const char *file, const char *caller, int line, int olddirfd, const char * oldpath, int newdirfd, const char * newpath, int flags);
#define linkat(...) finj_linkat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_linkat
#endif /* linkat */

#ifndef unlink
int finj_unlink(const char *file, const char *caller, int line, const char * pathname);
#define unlink(...) finj_unlink(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_unlink
#endif /* unlink */

#ifndef unlinkat
int finj_unlinkat(const char *file, const char *caller, int line, int dirfd, const char * pathname, int flags);
#define unlinkat(...) finj_unlinkat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_unlinkat
#endif /* unlinkat */

#ifndef truncate
int finj_truncate(const char *file, const char *caller, int line, const char * path, off_t length);
#define truncate(...) finj_truncate(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_truncate
#endif /* truncate */

#ifndef ftruncate
int finj_ftruncate(const char *file, const char *caller, int line, int fd, off_t length);
#define ftruncate(...) finj_ftruncate(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_ftruncate
#endif /* ftruncate */

#ifndef remove
int finj_remove(const char *file, const char *caller, int line, const char * pathname);
#define remove(...) finj_remove(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_remove
#endif /* remove */

#ifndef symlink
int finj_symlink(const char *file, const char *caller, int line, const char * target, const char * linkpath);
#define symlink(...) finj_symlink(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_symlink
#endif /* symlink */

#ifndef symlinkat
int finj_symlinkat(const char *file, const char *caller, int line, const char * target, int newdirfd, const char * linkpath);
#define symlinkat(...) finj_symlinkat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_symlinkat
#endif /* symlinkat */

#ifndef opendir
DIR * finj_opendir(const char *file, const char *caller, int line, const char * name);
#define opendir(...) finj_opendir(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_opendir
#endif /* opendir */

#ifndef fdopendir
DIR * finj_fdopendir(const char *file, const char *caller, int line, int fd);
#define fdopendir(...) finj_fdopendir(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fdopendir
#endif /* fdopendir */

#ifndef mkdir
int finj_mkdir(const char *file, const char *caller, int line, const char * pathname, mode_t mode);
#define mkdir(...) finj_mkdir(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_mkdir
#endif /* mkdir */

#ifndef mkdirat
int finj_mkdirat(const char *file, const char *caller, int line, int dirfd, const char * pathname, mode_t mode);
#define mkdirat(...) finj_mkdirat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_mkdirat
#endif /* mkdirat */

#ifndef rmdir
int finj_rmdir(const char *file, const char *caller, int line, const char * pathname);
#define rmdir(...) finj_rmdir(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_rmdir
#endif /* rmdir */

#ifndef mkdtemp
char * finj_mkdtemp(const char *file, const char *caller, int line, char * template);
#define mkdtemp(...) finj_mkdtemp(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_mkdtemp
#endif /* mkdtemp */

#ifndef mkstemp
int finj_mkstemp(const char *file, const char *caller, int line, char * template);
#define mkstemp(...) finj_mkstemp(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_mkstemp
#endif /* mkstemp */

#ifndef mkfifo
int finj_mkfifo(const char *file, const char *caller, int line, const char * pathname, mode_t mode);
#define mkfifo(...) finj_mkfifo(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_mkfifo
#endif /* mkfifo */

#ifndef mkfifoat
int finj_mkfifoat(const char *file, const char *caller, int line, int dirfd, const char * pathname, mode_t mode);
#define mkfifoat(...) finj_mkfifoat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_mkfifoat
#endif /* mkfifoat */

#ifndef dup
int finj_dup(const char *file, const char *caller, int line, int oldfd);
#define dup(...) finj_dup(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_dup
#endif /* dup */

#ifndef dup2
int finj_dup2(const char *file, const char *caller, int line, int oldfd, int newfd);
#define dup2(...) finj_dup2(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_dup2
#endif /* dup2 */

#ifndef pread
ssize_t finj_pread(const char *file, const char *caller, int line, int fd, void * buf, size_t count, off_t offset);
#define pread(...) finj_pread(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_pread
#endif /* pread */

#ifndef pwrite
ssize_t finj_pwrite(const char *file, const char *caller, int line, int fd, const void * buf, size_t count, off_t offset);
#define pwrite(...) finj_pwrite(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_pwrite
#endif /* pwrite */

#ifndef chdir
int finj_chdir(const char *file, const char *caller, int line, const char * path);
#define chdir(...) finj_chdir(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_chdir
#endif /* chdir */

#ifndef fchdir
int finj_fchdir(const char *file, const char *caller, int line, int fd);
#define fchdir(...) finj_fchdir(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fchdir
#endif /* fchdir */

#ifndef chown
int finj_chown(const char *file, const char *caller, int line, const char * pathname, uid_t owner, gid_t group);
#define chown(...) finj_chown(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_chown
#endif /* chown */

#ifndef fchown
int finj_fchown(const char *file, const char *caller, int line, int fd, uid_t owner, gid_t group);
#define fchown(...) finj_fchown(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fchown
#endif /* fchown */

#ifndef lchown
int finj_lchown(const char *file, const char *caller, int line, const char * pathname, uid_t owner, gid_t group);
#define lchown(...) finj_lchown(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_lchown
#endif /* lchown */

#ifndef fchownat
int finj_fchownat(const char *file, const char *caller, int line, int dirfd, const char * pathname, uid_t owner, gid_t group, int flags);
#define fchownat(...) finj_fchownat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fchownat
#endif /* fchownat */

#ifndef chmod
int finj_chmod(const char *file, const char *caller, int line, const char * pathname, mode_t mode);
#define chmod(...) finj_chmod(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_chmod
#endif /* chmod */

#ifndef fchmod
int finj_fchmod(const char *file, const char *caller, int line, int fd, mode_t mode);
#define fchmod(...) finj_fchmod(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fchmod
#endif /* fchmod */

#ifndef fchmodat
int finj_fchmodat(const char *file, const char *caller, int line, int dirfd, const char * pathname, mode_t mode, int flags);
#define fchmodat(...) finj_fchmodat(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_fchmodat
#endif /* fchmodat */

#ifndef getgrnam
struct group * finj_getgrnam(const char *file, const char *caller, int line, const char * name);
#define getgrnam(...) finj_getgrnam(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_getgrnam
#endif /* getgrnam */

#ifndef getgrgid
struct group * finj_getgrgid(const char *file, const char *caller, int line, gid_t gid);
#define getgrgid(...) finj_getgrgid(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_getgrgid
#endif /* getgrgid */

#ifndef getpwnam
struct passwd * finj_getpwnam(const char *file, const char *caller, int line, const char * name);
#define getpwnam(...) finj_getpwnam(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_getpwnam
#endif /* getpwnam */

#ifndef getpwuid
struct passwd * finj_getpwuid(const char *file, const char *caller, int line, uid_t uid);
#define getpwuid(...) finj_getpwuid(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_getpwuid
#endif /* getpwuid */

#ifndef kill
int finj_kill(const char *file, const char *caller, int line, pid_t pid, int sig);
#define kill(...) finj_kill(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_kill
#endif /* kill */

#ifndef nice
int finj_nice(const char *file, const char *caller, int line, int inc);
#define nice(...) finj_nice(__FILE__, __func__, __LINE__, ##__VA_ARGS__)
#define HAVE_finj_nice
#endif /* nice */


#endif /* _FINJ_HOOK_H */