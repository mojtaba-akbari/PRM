#include "../include/PRMProgDispatcher.h"

static int PRM_PROG_Dispatcher(struct hooks_context_t *hook_ctx, const __u32 idx , enum DISPATCH_TYPE type){

    
    //PROG_SWITCH_GENERATOR(hook_ctx,idx)

    if(idx >= 0 && idx < PROG_Numbers){
        PROG_SWITCH_GENERATOR(hook_ctx, idx, type)
    }
    
    // Debug print removed to reduce instruction count

    RET_REJECT
}
