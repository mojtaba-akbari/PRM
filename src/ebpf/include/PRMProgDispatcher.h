#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_DISPATCHER
#define FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_DISPATCHER

#include "../conf/PRMProg.h"
#include "PRMProgStructs.h"

enum DISPATCH_TYPE{
    PROG,
    FINGER,
};

static int PRM_PROG_Dispatcher(struct hooks_context_t *hook_ctx, const __u32 idx , enum DISPATCH_TYPE type);

#define PROG_CASE_GENERATOR(hook_ctx,idx, type) case idx: \
                                                    if((hook_ctx->key.hook == prog_struct_tb_h.prog_struct_tb[idx]->hookForce || prog_struct_tb_h.prog_struct_tb[idx]->hookForce == NONE_CELL)){\
                                                        if(type == PROG) \
                                                            return prog_struct_tb_h.prog_struct_tb[idx]->prog(hook_ctx); \
                                                        else if(type == FINGER) \
                                                            return prog_struct_tb_h.prog_struct_tb[idx]->fingerprint(hook_ctx); \
                                                        else RET_REJECT \
                                                    } \
                                                    else RET_REJECT;

#define PROG_SWITCH_GENERATOR(hook_ctx,idx, type) switch(idx)   \
                                            { \
                                            PROG_CASE_GENERATOR(hook_ctx,0,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,1,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,2,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,3,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,4,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,5,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,6,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,7,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,8,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,9,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,10,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,11,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,12,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,13,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,14,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,15,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,16,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,17,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,18,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,19,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,20,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,21,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,22,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,23,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,24,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,25,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,26,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,27,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,28,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,29,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,30,type) \
                                            PROG_CASE_GENERATOR(hook_ctx,31,type) \
                                            default: \
                                                RET_REJECT \ 
                                            }

#endif