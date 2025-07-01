#include "../include/PRMFilters.h"
#include "../include/conf/PRM.h"
#include "../include/PRMStructs.h"

static __u32 filter1(struct hooks_context_t * hook, __u32 input)
{
    return input;
}
