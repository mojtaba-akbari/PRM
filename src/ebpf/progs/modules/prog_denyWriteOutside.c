/* PROG Module: denyWriteOutSideOfValidDirectories
 * Hook: INODE_CREATE
 * Slot: 2
 *
 * Blocks file creation outside directories listed in ValidateDirectory config.
 */

static __u32 denyWriteOutSideOfValidDirectories_prog(struct hooks_context_t *hook_ctx){
    struct dentry *cur = hook_ctx->args.inode_create.dentry;
    if(!cur) RET_REJECT

    __u32 path_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 400;
    struct empty_buffer *path_buf = char_memory_allocate(&path_key, NULL);
    if (!path_buf) {
        char_memory_delete(&path_key);
        RET_REJECT
    }

    char *dname;
    struct dentry *parent;
    struct dentry *first_after_root = NULL;
    struct dentry *prev = cur;
    
    for (int i = 0; i < MIN_ITR && cur; i++) {
        parent = BPF_CORE_READ(cur, d_parent);
        if (!parent || cur == parent) {
            first_after_root = prev;
            break;
        }
        prev = cur;
        cur = parent;
    }
    
    if (!first_after_root) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: File creation rejected, path too deep to verify"));
        char_memory_delete(&path_key);
        RET_REJECT
    }
    
    dname = BPF_CORE_READ(first_after_root, d_name.name);
    bpf_core_read_str(path_buf->_buff_, MAX_STR, dname);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: File creation requested in directory: %s", path_buf->_buff_));

    bool resCondition=0;
    checkValidElemConfigSTR(path_buf->_buff_,ValidateDirectory,resCondition=1;)
    if(resCondition){
        FLAG_FOR_HASH(hook_ctx, str_to_u32(path_buf->_buff_), 0, 0)
        char_memory_delete(&path_key);
        RET_ACCEPT
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: File creation denied in restricted directory '%s'",path_buf->_buff_));

    RET_REJECT 
}

static __u32 denyWriteOutSideOfValidDirectories_fingerprint(struct hooks_context_t *hook_ctx){
    struct dentry *cur = hook_ctx->args.inode_create.dentry;
    if(!cur) RET_REJECT

    __u64 path_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 401;
    struct empty_buffer *path_buf = char_memory_allocate(&path_key, NULL);
    if (!path_buf) RET_REJECT

    char *dname;
    struct dentry *parent;
    struct dentry *first_after_root = NULL;
    struct dentry *prev = cur;
    
    for (int i = 0; i < MIN_ITR && cur; i++) {
        parent = BPF_CORE_READ(cur, d_parent);
        if (!parent || cur == parent) {
            first_after_root = prev;
            break;
        }
        prev = cur;
        cur = parent;
    }
    
    if (!first_after_root) RET_REJECT
    
    dname = BPF_CORE_READ(first_after_root, d_name.name);
    bpf_core_read_str(path_buf->_buff_, MAX_STR, dname);

    FLAG_FOR_HASH(hook_ctx,str_to_u32(path_buf->_buff_),0,0)
    RET_ACCEPT
}

__PROG_REGISTER__(denyWriteOutSideOfValidDirectories, INODE_CREATE, denyWriteOutSideOfValidDirectories_prog, denyWriteOutSideOfValidDirectories_fingerprint)
