#include "../config.h"
#include "../sys.h"

#include "sched.h"

static int _during_test = 0;
static int _time_to_hit_checkpoint = 0;

void set_during_test(int during_test)
{
    _during_test = during_test;
}

int is_during_test()
{
    return _during_test;
}

int is_time_to_enter_test()
{
    return 1;
}

int is_time_to_exit_test()
{
    if (++_time_to_hit_checkpoint > 2)
        return 1;
    return 0;
}

