#include "finj/sys.h"

#include "finj/config.h"
#include "finj/log.h"
#include "finj/utils.h"

/* Default configures. */
struct finj_config config = {
    .log_file = "/tmp/finj.log",
    .log_level = LEVEL_ERROR,
    .replay_mode = 0,
    .replay_id = 0,
};

int load_config(const char *file)
{
    FILE *fp;
    char line[MAXLINE];
    char log_file[MAXNAME], log_level_buf[256];
    int log_level, replay_mode, replay_id;

    if ((fp = fopen(file, "r")) == NULL)
        return -1;

    char *ret = readline(fp, line, ARRAY_LEN(line));
    if (ret == (char *)-1)
        goto close_and_err_out;
    if (!ret)
        goto close_and_fmterr_out;
    if (sscanf(line, "%s %s %d %d",
               log_file, log_level_buf, &replay_mode, &replay_id) != 4)
        goto close_and_fmterr_out;

    log_level = str_to_level(log_level_buf);
    if (log_level == -1)
        goto close_and_fmterr_out;
    if (replay_mode != 0 && replay_mode != 1)
        goto close_and_fmterr_out;
    if (replay_id < 0)
        goto close_and_fmterr_out;

    strcpy(config.log_file, log_file);
    config.log_level = log_level;
    config.replay_mode = replay_mode;
    config.replay_id = replay_id;

    fclose(fp);
    return 0;

close_and_err_out:
    fclose(fp);
    return -1;
close_and_fmterr_out:
    fclose(fp);
    return -2;
}

int save_config(const char *file)
{
    FILE *fp;

    if ((fp = fopen(file, "w")) == NULL)
        return -1;

    fprintf(fp, "%s %s %d %d", config.log_file, level_to_str(config.log_level),
            config.replay_mode, config.replay_id);

    fclose(fp);
    return 0;
}
