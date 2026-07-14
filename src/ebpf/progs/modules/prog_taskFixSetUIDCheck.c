/* PROG Module: taskFixSetUIDCheck
 * Hook: TASK_FIX_SETUID
 * Slot: 11
 *
 * Blocks setuid exploitation. Prevents UID/EUID/GID escalation to root
 * unless binary is from a trusted system directory.
 * Also detects container escape attempts.
 */

static __u32 taskFixSetUIDCheck_prog(struct hooks_context_t *hook_ctx){
    struct task_struct *task = hook_ctx->args.task_fix_set.task;
    struct cred *old_cred = hook_ctx->args.task_fix_set.old;
    struct cred *new_cred = hook_ctx->args.task_fix_set.new;
    int flags = hook_ctx->args.task_fix_set.flags;
    
    if (!task || !old_cred || !new_cred) RET_ACCEPT
    
    kuid_t old_uid = BPF_CORE_READ(old_cred, uid);
    kuid_t new_uid = BPF_CORE_READ(new_cred, uid);
    kuid_t old_euid = BPF_CORE_READ(old_cred, euid);
    kuid_t new_euid = BPF_CORE_READ(new_cred, euid);
    kgid_t old_gid = BPF_CORE_READ(old_cred, gid);
    kgid_t new_gid = BPF_CORE_READ(new_cred, gid);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("INSPECT: SetUID change: UID %d->%d, EUID %d->%d, GID %d->%d", old_uid.val, new_uid.val, old_euid.val, new_euid.val, old_gid.val, new_gid.val, flags));
    
    if (new_euid.val == 0 && old_euid.val != 0 && old_uid.val != 0) {
        struct execPath *ePath = getExecPath(task, createTaskUKey(task, &hook_ctx->taskUKey));
        if (ePath) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("INSPECT: Binary runs from trusted directory=%d", ePath->isValidDirectory));
            if (ePath->isValidDirectory == 1) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("ALLOWED: SetUID binary from a trusted system directory"));
                RET_ACCEPT
            }
        } else {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("WARNING: Could not determine binary path"));
        }
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: Process tried to gain root via seteuid(0) from EUID %d", old_euid.val));
        RET_REJECT
    }

    if (new_uid.val == 0 && old_uid.val != 0) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: Process tried to gain root via setuid(0) from UID %d", old_uid.val));
        RET_REJECT
    }
    
    if (new_gid.val == 0 && old_gid.val != 0) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: Process tried to gain root group via setgid(0) from GID %d", old_gid.val));
        RET_REJECT
    }
    
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
    }
    
    if (lineage_result > LOW_RISK) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: SetUID denied due to suspicious process ancestry (severity=%d)", lineage_result));
        RET_REJECT
    }
    
    if (new_uid.val == 0 && is_containerized_root(task)) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: Container process tried to escape to root"));
        RET_REJECT
    }
    
    FLAG_FOR_HASH(hook_ctx, old_uid.val, new_uid.val, lineage_result)
    RET_ACCEPT
}

static __u32 taskFixSetUIDCheck_fingerprint(struct hooks_context_t *hook_ctx){
    struct task_struct *task = hook_ctx->args.task_fix_set.task;
    struct cred *old_cred = hook_ctx->args.task_fix_set.old;
    struct cred *new_cred = hook_ctx->args.task_fix_set.new;
    int flags = hook_ctx->args.task_fix_set.flags;
    
    if (!task || !old_cred || !new_cred) RET_ACCEPT
    
    kuid_t old_uid = BPF_CORE_READ(old_cred, uid);
    kuid_t new_uid = BPF_CORE_READ(new_cred, uid);
    
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
    }
    
    FLAG_FOR_HASH(hook_ctx, old_uid.val, new_uid.val, lineage_result)
    RET_ACCEPT
}

__PROG_REGISTER__(taskFixSetUIDCheck, TASK_FIX_SETUID, taskFixSetUIDCheck_prog, taskFixSetUIDCheck_fingerprint)
