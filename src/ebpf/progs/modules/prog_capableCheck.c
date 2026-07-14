/* PROG Module: capableCheck
 * Hook: CAPABLE
 * Slot: 10
 *
 * Blocks dangerous capabilities (CAP_SETUID, CAP_SETGID, CAP_SETPCAP, CAP_SYS_ADMIN)
 * for non-root users. For root, checks UID lineage for suspicious patterns.
 */

static __u32 capableCheck_prog(struct hooks_context_t *hook_ctx){
    const struct cred *cred = hook_ctx->args.capable.cred;
    int cap = hook_ctx->args.capable.cap;
    unsigned int opts = hook_ctx->args.capable.opts;
    
    if (!cred) RET_ACCEPT
    
    kuid_t uid = BPF_CORE_READ(cred, uid);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("INSPECT: Capability check cap=%d for UID %d", cap, opts, uid.val));
    
    if (uid.val == 0) {
        int lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
        if (lineage_result > LOW_RISK) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Root process has suspicious ancestry, admin capability denied (severity=%d)", lineage_result));
            RET_REJECT
        }
        RET_ACCEPT
    }
    
    if (cap == 7) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Non-root user %d tried to use setuid capability", uid.val));
        RET_REJECT
    }
    
    if (cap == 6) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Non-root user %d tried to use setgid capability", uid.val));
        RET_REJECT
    }
    
    if (cap == 8) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Non-root user %d tried to transfer capabilities", uid.val));
        RET_REJECT
    }
    
    if (cap == 21) {
        int lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
        if (lineage_result > LOW_RISK) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Admin capability denied due to suspicious process ancestry (severity=%d)", lineage_result));
            RET_REJECT
        }
    }
    
    FLAG_FOR_HASH(hook_ctx, cap, opts, 0)
    RET_ACCEPT
}

static __u32 capableCheck_fingerprint(struct hooks_context_t *hook_ctx){
    const struct cred *cred = hook_ctx->args.capable.cred;
    int cap = hook_ctx->args.capable.cap;
    unsigned int opts = hook_ctx->args.capable.opts;
    
    if (!cred) RET_ACCEPT
    
    FLAG_FOR_HASH(hook_ctx, cap, opts, 0)
    RET_ACCEPT
}

__PROG_REGISTER__(capableCheck, CAPABLE, capableCheck_prog, capableCheck_fingerprint)
