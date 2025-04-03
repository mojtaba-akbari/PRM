#include "../include/PRMFilters.h"
#include "../include/conf/PRM.h"
#include "../include/PRMStructs.h"

static __u32 filter1(enum PRM_HOOK_ENUM hook, __u32 * pid, __u32 input)
{
    return input;
}
