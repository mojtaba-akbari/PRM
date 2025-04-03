#include "../include/PRMProgDispatcher.h"
#include "PRMProgEntry.c"

static int PRM_PROG_Dispatcher(__u32 idx){
    PROG_SWITCH_GENERATOR(idx)

    return 0;
}
