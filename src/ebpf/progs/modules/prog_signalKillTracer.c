/* PROG Module: signalKillTracer
 * Hook: TASK_KILL
 * Slot: 1
 *
 * Prevents killing the PRM process itself.
 * Checks containerized root and UID lineage patterns.
 */

static __u32 signalKillTracer_prog(struct hooks_context_t *hook_ctx){
    __u32 key=0;
    struct SelfPID *value= bpf_map_lookup_elem(&self_pids, &key);
    if(!value) RET_ACCEPT_FORCEFULLY
    
    struct task_struct * target_task = hook_ctx->args.task_kill.task; 
    struct task_struct * killer_task = hook_ctx->task;

    if(!killer_task) RET_ACCEPT_FORCEFULLY

    __u32 target_pid = BPF_CORE_READ(target_task, pid);
    __u32 caller_pid = hook_ctx->key.pid;

    if(value->pid != target_pid) 
    {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("ALLOWED: PID %d tried to kill PID %d (not a protected process)", caller_pid, target_pid));
        RET_ACCEPT_FORCEFULLY
    }
    
    if(is_containerized_root(killer_task)){
        RET_REJECT  
    }

    if(lineageUIDAnalizer(killer_task, &hook_ctx->key) > BASE){
        RET_REJECT
    }
    else{
        RET_ACCEPT
    }
}

static __u32 signalKillTracer_fingerprint(struct hooks_context_t *hook_ctx){
    RET_ACCEPT
}

__PROG_REGISTER__(signalKillTracer, TASK_KILL, signalKillTracer_prog, signalKillTracer_fingerprint)
