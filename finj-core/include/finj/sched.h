#ifndef _FINJ_SCHED_H
#define _FINJ_SCHED_H

void set_during_test(int during_test);
int is_during_test();
int is_time_to_enter_test();
int is_time_to_exit_test();

#endif /* _FINJ_SCHED_H */