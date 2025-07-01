#include "../include/conf/PRM.h"
#include "../include/conf/PRMConfig.h"
#include "../include/PRMStructs.h"
#include "../include/PRMProgStructs.h"
#include "../include/PRMCacheService.h"
#include "../include/PRMVerifier.h"
#include "../include/PRMProgDispatcher.h"
#include "../include/PRMFilters.h"
#include "PRMStructs.c"
#include "PRMFilters.c"
#include "PRMProgEntry.c"
#include "PRMProgDispatcher.c"
#include "PRMCacheService.c"

// Mojtaba, Verifier //
static int PRMVerifier(struct hooks_context_t *hook_ctx){
    struct task_struct *task = (struct task_struct *) bpf_get_current_task_btf();
    struct task_struct *parent;
    struct task_struct *grandparent;
    
    char comm[TASK_COMM_LEN], p_comm[TASK_COMM_LEN], grand_p_comm[TASK_COMM_LEN]={0};

    if (!task) return 0;

    bpf_get_current_comm(comm, TASK_COMM_LEN);

    
    parent = task->real_parent;
    if (parent) {
        bpf_probe_read_kernel_str(p_comm, TASK_COMM_LEN, parent->comm);
    }

    grandparent = parent->real_parent;

    if (grandparent) {
        bpf_probe_read_kernel_str(grand_p_comm, TASK_COMM_LEN, grandparent->comm);
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("***Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} \n", hook_ctx->key.hook,hook_ctx->key.pid, comm, p_comm, grand_p_comm));

    struct process_relation *prm;
    __u32 _safeCounter_=0;
    int _redirectIndex_=-1;
    
    
    if(!hook_ctx) RET_REJECT // General Issue RETURN // 

    #pragma clang loop unroll(disable)
    for (__u32 i = 0; i < MAX_NUMBER_OF_RELATION; i++) {
        _safeCounter_=i;

        if(_redirectIndex_ > 0 && _safeCounter_ < _redirectIndex_) continue;

        prm = bpf_map_lookup_elem(&prm_map, &_safeCounter_);

        if(prm){

            if(prm->process[0] == '\0' || prm->parent[0] == '\0' || prm->grandparent[0] == '\0' || prm->action == NONE_ACTION) continue;

            if((prm->hookType != NONE_CELL) && (prm->hookType != hook_ctx->key.hook)){
                continue;
            } 

            if((prm->protectZone==1 && _redirectIndex_ >= 0) || (prm->protectZone==0 && _redirectIndex_ < 0))
            {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Check the relation : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));

                __u32 mixedUP=1;

                if(strcmp(prm->process,PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0) mixedUP &= (strcmp(comm, prm->process, MAX_RELATION_PROCESSNAME) ==0);
                
                if(mixedUP && (strcmp(prm->parent, PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0)) mixedUP &=  (strcmp(p_comm, prm->parent, MAX_RELATION_PROCESSNAME) ==0);

                if(mixedUP && (strcmp(prm->grandparent, PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0)) mixedUP &=  (strcmp(grand_p_comm, prm->grandparent, MAX_RELATION_PROCESSNAME) ==0);

                if(mixedUP)
                {
                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                    switch (prm->action)
                    {
                        case REJECT:
                            RET_REJECT
                        case ACCEPT:
                            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (ACCEPT) (Added to Cache) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                            
                            hook_ctx->key.crecord.direct_relation=_safeCounter_;
                            addLRUCache(&hook_ctx->key);
                            RET_ACCEPT
                        case DEBUG:
                            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (Debug Action) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                            RET_ACCEPT
                        case REDIRECT:
                            if(prm->redirectIndex < MAX_NUMBER_OF_RELATION && prm->redirectIndex >= _safeCounter_){
                                if(prm->redirectIndex == _safeCounter_){
                                    _redirectIndex_= -1;
                                    bpf_printk("end of zone");
                                    RET_ACCEPT
                                }
                                else{
                                    _redirectIndex_ = prm->redirectIndex;
                                    continue;
                                }
                            }
                            else {
                                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (Redirect Action - Wrong Zone - Wrong Redirect Index) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                                continue;
                            }
                            break;
                        case RETURN:
                            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (Return Action) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                            
                            if(
                                (hook_ctx->key.crecord.active_entries >= 0 && hook_ctx->key.crecord.active_entries < MAX_CACHE_ENTRIES)
                                && 
                                (prm->redirectIndex >=0 && prm->redirectIndex < PROG_Numbers)
                            ){
                                hook_ctx->key.crecord.direct_relation= _safeCounter_;
                                hook_ctx->key.crecord.is_valid_entries= 1;
                                hook_ctx->key.crecord.prog_tb_id=prm->redirectIndex;
                            }
                            else RET_ACCEPT

                            switch (PRM_PROG_Dispatcher(hook_ctx, prm->redirectIndex, PROG)) {
                                case 0:
                                    addLRUCache(&hook_ctx->key);
                                    RET_ACCEPT
                                case 1:
                                    RET_REJECT
                                default:
                                    RET_REJECT
                            }
                    }
                }
            }
        }
    }
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Unknown Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Not Matched any relations (Take it as White Process - Or Add Role) \n", hook_ctx->key.hook, hook_ctx->key.pid,comm, p_comm, grand_p_comm));

    addLRUCache(&hook_ctx->key);

    RET_ACCEPT
}

static int detectSyscallRelations(struct hooks_context_t *hook_ctx) {
    __u32 output=0;
    __u32 input=1;

    __INJECT_FILTERS__(hook_ctx,input,output)

    return (PRMVerifier(hook_ctx)&output);
}

static int entryStartPoint(struct hooks_context_t *hook_ctx){
    __u32 key=0;
    struct SelfPID *value= bpf_map_lookup_elem(&self_pids, &key);

    if (value && value->pid == hook_ctx->key.pid && value->magic==MAGIC_VALUE) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("Hook Received: Hook(%d)-PID(%d) Self-PID , Internal Hooks \n", hook_ctx->key.hook, hook_ctx->key.pid));
        return 0;
    } 

    if(!checkLRUCache(hook_ctx)) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("Hook Received: Hook(%d)-PID(%d) Matched with process white list \n", hook_ctx->key.hook, hook_ctx->key.pid));
        return 0;
    }

    if(detectSyscallRelations(hook_ctx)){
        return -EPERM;
    }

    return 0;
}

static int saveSelfPID(struct hooks_context_t * hook_ctx){
    __u32 key=0;
    
    struct SelfPID *value = bpf_map_lookup_elem(&self_pids, &key);
    
    if(value && value->pid == EMPTY && value->magic == EMPTY){
        struct SelfPID currentValue = {.pid=hook_ctx->key.pid,.magic=MAGIC_VALUE};

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("PRM verifier is setting up its PID : %d",hook_ctx->key.pid));
        
        bpf_map_update_elem(&self_pids, &key, &currentValue, BPF_ANY);

        struct prm_state *prm_state;
        __u32 key = 0;
        prm_state = bpf_map_lookup_elem(&prm_state_map, &key);
        if (!prm_state) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("PRM is loading up PID : %d",hook_ctx->key.pid));
            Load_PRM();
        }
        else if (prm_state->prm_state == UNLOADED){
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("PRM has been unloaded , PRM is loading up again PID : %d",hook_ctx->key.pid));
            Load_PRM();
        }

        return 0;
    }
    else if (value && value->pid == hook_ctx->key.pid && value->magic==MAGIC_VALUE) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("Hook Received: Hook(%d)-PID(%d) Self-PID , Internal Hooks \n", hook_ctx->key.hook, hook_ctx->key.pid));
        return 0;
    }
    else return -EPERM;
}