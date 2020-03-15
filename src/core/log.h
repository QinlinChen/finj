#ifndef _FINJ_LOG_H
#define _FINJ_LOG_H

#include <stdio.h>
#include <string.h>

#define LOG_FILE    "/tmp/finj.log"
#define LOG_LEVEL   LEVEL_INFO

enum {
    LEVEL_DEBUG, LEVEL_INFO, LEVEL_WARN, LEVEL_ERROR, LEVEL_FATAL
};

#define LEVEL_LT(lhs, rhs) ((lhs) < (rhs))

FILE *init_log();
FILE *get_logfp();
int get_logfd();
void set_log_identity(const char *new_identity);
void lock_logfile();
void unlock_logfile();
void log_without_lock(int level, const char *format, ...);

#define log_debug(format, ...) \
    do { \
        log_without_lock(LEVEL_DEBUG, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_info(format, ...) \
    do { \
        log_without_lock(LEVEL_INFO, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_warn(format, ...) \
    do { \
        log_without_lock(LEVEL_WARN, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_error(format, ...) \
    do { \
        log_without_lock(LEVEL_ERROR, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_fatal(format, ...) \
    do { \
        log_without_lock(LEVEL_FATAL, format "\n", ## __VA_ARGS__); \
    } while (0)

#define log_unix_error(format, ...) \
    do { \
        log_without_lock(LEVEL_ERROR, format ": %s\n", ## __VA_ARGS__, \
                         strerror(errno)); \
    } while (0)

#endif /* _FINJ_LOG_H */
