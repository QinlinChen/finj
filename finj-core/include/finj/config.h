#ifndef _FINJ_CONFIG_H
#define _FINJ_CONFIG_H

#ifndef OPEN_MAX
#define OPEN_MAX 1024
#endif /* OPEN_MAX */

#ifndef MAXLINE
#define MAXLINE 1024
#endif /* MAXLINE */

#ifndef MAXBUF
#define MAXBUF 1024
#endif /* MAXBUF */

#ifndef MAXNAME
#define MAXNAME 1024
#endif /* MAXNAME */

struct finj_config {
    char log_file[MAXNAME];
    int log_level;
    int replay_mode;
    int replay_id;
    int sched_prob;
};

extern struct finj_config config;

int load_config(const char *file);
int save_config(const char *file);

#endif /* _FINJ_CONFIG_H */