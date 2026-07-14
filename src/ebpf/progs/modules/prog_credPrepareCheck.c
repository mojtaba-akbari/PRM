/* PROG Module: credPrepareCheck
 * Hook: CRED_PREPARE
 * Slot: 9
 *
 * Blocks UID/GID escalation to root.
 * Uses UID lineage analysis to detect suspicious ancestry patterns.
 */

static __u32 credPrepareCheck_prog(struct hooks_context_t *hook_ctx){
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: Credential change detected"));
    
    struct cred *new_cred = hook_ctx->args.cred_prepare.new;
    struct cred *old_cred = hook_ctx->args.cred_prepare.old;
    int flags = hook_ctx->args.cred_prepare.flags;
    
    if (!new_cred || !old_cred) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("WARNING: Credential structures missing, allowing"));
        RET_ACCEPT
    }
    
    kuid_t old_uid = BPF_CORE_READ(old_cred, uid);
    kuid_t new_uid = BPF_CORE_READ(new_cred, uid);
    kgid_t old_gid = BPF_CORE_READ(old_cred, gid);
    kgid_t new_gid = BPF_CORE_READ(new_cred, gid);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: User ID changing from %d to %d, Group ID from %d to %d", old_uid.val, new_uid.val, old_gid.val, new_gid.val));
    
    if (new_uid.val == 0 && old_uid.val != 0) {
        FULLY_DEBUG(__DEBUG__,(NOTHING | LOWER),bpf_printk("BLOCKED: User %d tried to become root (privilege escalation)", old_uid.val));
        RET_REJECT
    }
    
    if (new_gid.val == 0 && old_gid.val != 0) {
        FULLY_DEBUG(__DEBUG__,(NOTHING | LOWER),bpf_printk("BLOCKED: Group %d tried to become root group (privilege escalation)", old_gid.val));
        RET_REJECT
    }
    
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0 && new_gid.val == 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("WARNING: Suspicious process ancestry pattern detected (severity=%d)", lineage_result));
    }
    
    if (lineage_result > LOW_RISK) {
        FULLY_DEBUG(__DEBUG__,(NOTHING | LOWER),bpf_printk("BLOCKED: Process ancestry indicates possible attack (severity=%d)", lineage_result));
        RET_REJECT
    }
    
    FLAG_FOR_HASH(hook_ctx, old_uid.val, new_uid.val, lineage_result)
    RET_ACCEPT
}

static __u32 credPrepareCheck_fingerprint(struct hooks_context_t *hook_ctx){
    struct cred *new_cred = hook_ctx->args.cred_prepare.new;
    struct cred *old_cred = hook_ctx->args.cred_prepare.old;
    int flags = hook_ctx->args.cred_prepare.flags;
    
    if (!new_cred || !old_cred) RET_ACCEPT
    
    kuid_t old_uid = BPF_CORE_READ(old_cred, uid);
    kuid_t new_uid = BPF_CORE_READ(new_cred, uid);
    
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
    }
    
    FLAG_FOR_HASH(hook_ctx, old_uid.val, new_uid.val, lineage_result)
    RET_ACCEPT
}

__PROG_REGISTER__(credPrepareCheck, CRED_PREPARE, credPrepareCheck_prog, credPrepareCheck_fingerprint)
