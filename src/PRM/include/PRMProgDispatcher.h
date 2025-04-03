#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_Dispatcher
#define FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_Dispatcher

#include "PRMProg.h"

static int PRM_PROG_Dispatcher(__u32 idx);

#define PROG_CASE_GENERATOR(idx) case idx: return PROG_##idx;

#define PROG_SWITCH_GENERATOR(dispatch) switch(dispatch){ \
                                            PROG_CASE_GENERATOR(0) \
                                            PROG_CASE_GENERATOR(1) \
                                            PROG_CASE_GENERATOR(2) \
                                            PROG_CASE_GENERATOR(3) \
                                            PROG_CASE_GENERATOR(4) \
                                            PROG_CASE_GENERATOR(5) \
                                            PROG_CASE_GENERATOR(6) \
                                            PROG_CASE_GENERATOR(7) \
                                            PROG_CASE_GENERATOR(8) \
                                            PROG_CASE_GENERATOR(9) \
                                            PROG_CASE_GENERATOR(10) \
                                            PROG_CASE_GENERATOR(11) \
                                            PROG_CASE_GENERATOR(12) \
                                            PROG_CASE_GENERATOR(13) \
                                            PROG_CASE_GENERATOR(14) \
                                            PROG_CASE_GENERATOR(15) \
                                            PROG_CASE_GENERATOR(16) \
                                            PROG_CASE_GENERATOR(17) \
                                            PROG_CASE_GENERATOR(18) \
                                            PROG_CASE_GENERATOR(19) \
                                            PROG_CASE_GENERATOR(20) \
                                            PROG_CASE_GENERATOR(21) \
                                            PROG_CASE_GENERATOR(22) \
                                            PROG_CASE_GENERATOR(23) \
                                            PROG_CASE_GENERATOR(24) \
                                            PROG_CASE_GENERATOR(25) \
                                            PROG_CASE_GENERATOR(26) \
                                            PROG_CASE_GENERATOR(27) \
                                            PROG_CASE_GENERATOR(28) \
                                            PROG_CASE_GENERATOR(29) \
                                            PROG_CASE_GENERATOR(30) \
                                            PROG_CASE_GENERATOR(31) \
                                        }

#endif