/* PROG Module: memoryProtectCheck
 * Hook: FILE_MPROTECT
 * Slot: 5
 *
 * Blocks mprotect(EXEC) on anonymous memory (code injection).
 * Blocks executable mmap from untrusted directories (MMAPFileAttached config).
 */

static __u32 memoryProtectCheck_prog(struct hooks_context_t * hook_ctx){
    struct task_struct *taskAskMMAP = bpf_get_current_task_btf();
    struct vm_area_struct *vma = hook_ctx->args.file_mprotect.vma;
    struct file *file = BPF_CORE_READ(vma, vm_file);
    __u8 lineage = 0;
    unsigned long reqprot = 0;

    __u32 path_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 200;
    struct empty_buffer *path_buf = char_memory_allocate(&path_key, NULL);
    if (!path_buf) {
        char_memory_delete(&path_key);
        RET_REJECT
    }

    bpf_probe_read(&reqprot, sizeof(reqprot), &hook_ctx->args.file_mprotect.reqprot);

    if (!file && (reqprot & PROT_EXEC)) {
        if (hook_ctx->key.pid != 0) {
            lineage = lineageUIDAnalizer(taskAskMMAP, &hook_ctx->key);
            if( lineage > BASE){
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Anonymous memory made executable (code injection attempt)!"));
                char_memory_delete(&path_key);
                RET_REJECT
            }
        }
    }
    else if (reqprot & PROT_EXEC)
    {
        struct dentry *cur = BPF_CORE_READ(file, f_path.dentry);;
        char *dname;
        struct dentry *parent;
        struct dentry *prv = cur;
        for (int i=0; i < MAX_DIR_ITR; i++) {

            dname = BPF_CORE_READ(cur, d_name.name);
            memset(path_buf->_buff_,'\0',MAX_STR);
            bpf_core_read_str(path_buf->_buff_, MAX_STR, dname);

            parent = BPF_CORE_READ(cur, d_parent);
            if(!parent || cur == parent) break;

            prv=cur;
            cur = parent;
        }

        if(!prv) prv = cur;
        dname = BPF_CORE_READ(prv, d_name.name);
        bpf_core_read_str(path_buf->_buff_, MAX_STR, dname);

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),
            bpf_printk("BLOCKED: Executable memory requested from untrusted directory '%s'",path_buf->_buff_));

        checkValidElemConfigForceSTRLen(path_buf->_buff_, MMAPFileAttached, RET_REJECT)
    }

    __u32 result = str_to_u32(path_buf->_buff_);
    char_memory_delete(&path_key);
    
    FLAG_FOR_HASH(hook_ctx, result, reqprot , lineage)
    RET_ACCEPT
}

static __u32 memoryProtectCheck_fingerprint(struct hooks_context_t * hook_ctx){
    struct task_struct *taskAskMMAP = bpf_get_current_task_btf();
    struct vm_area_struct *vma = hook_ctx->args.file_mprotect.vma;
    struct file *file = BPF_CORE_READ(vma, vm_file);
    __u8 lineage = 0;
    unsigned long reqprot = 0;

    __u64 path_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 201;
    struct empty_buffer *path_buf = char_memory_allocate(&path_key, NULL);
    if (!path_buf) {
        char_memory_delete(&path_key);
        RET_ACCEPT
    }

    bpf_probe_read(&reqprot, sizeof(reqprot), &hook_ctx->args.file_mprotect.reqprot);

    if (!file && (reqprot & PROT_EXEC)) {
        if (hook_ctx->key.pid != 0) {
            lineage = lineageUIDAnalizer(taskAskMMAP, &hook_ctx->key);
        }
    }
    else if (reqprot & PROT_EXEC)
    {
        struct dentry *cur = BPF_CORE_READ(file, f_path.dentry);;
        char *dname;
        struct dentry *parent;
        struct dentry *next = cur;
        for (int i=0; i < MAX_DIR_ITR; i++) {

            dname = BPF_CORE_READ(cur, d_name.name);
            memset(path_buf->_buff_,'\0',MAX_STR);
            bpf_core_read_str(path_buf->_buff_, MAX_STR, dname);

            parent = BPF_CORE_READ(cur, d_parent);
            if(!parent || cur == parent) break;

            next=cur;
            cur = parent;
        }

        if(!next) next = cur;
        dname = BPF_CORE_READ(next, d_name.name);
        bpf_core_read_str(path_buf->_buff_, MAX_STR, dname);
    }

    __u32 result = str_to_u32(path_buf->_buff_);
    char_memory_delete(&path_key);

    FLAG_FOR_HASH(hook_ctx,result, reqprot , lineage)
    RET_ACCEPT 
}

__PROG_REGISTER__(memoryProtectCheck, FILE_MPROTECT, memoryProtectCheck_prog, memoryProtectCheck_fingerprint)
