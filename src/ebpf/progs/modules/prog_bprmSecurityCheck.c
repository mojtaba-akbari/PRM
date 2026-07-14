/* PROG Module: bprmSecurityCheck
 * Hook: BPRM_SECURITY
 * Slot: 4
 *
 * Blocks execve from untrusted paths (/tmp, /dev/shm, etc.)
 * Blocks dangerous interpreters.
 * Detects memfd/anonymous execution attempts.
 */

static __u32 bprmSecurityCheck_prog(struct hooks_context_t *hook_ctx){
    struct linux_binprm *bprm = hook_ctx->args.bprm_check_security.bprm;
    if(!bprm) RET_REJECT

    __u32 filename_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid)+137;
    struct empty_buffer *filename_buf = char_memory_allocate(&filename_key, NULL);

    if (!filename_buf)
        RET_REJECT
    
    __u8 filevalid=0;
    const char *bprm_filename = BPF_CORE_READ(bprm, filename);
    int res = bpf_probe_read_str(filename_buf->_buff_, LARGE_STR, bprm_filename);
    if (res <= 0 || (res > 0 && res < 3))
    {
        FULLY_DEBUG(__DEBUG__,(NOTHING | LOWER),bpf_printk("BLOCKED: Program execution rejected (filename too short, suspicious)\n"));
        char_memory_delete(&filename_key);
        RET_REJECT
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: Program execution requested: %s\n", filename_buf->_buff_));

    checkValidElemConfigForceSTRLen(filename_buf->_buff_, BPRMDestination, RET_REJECT)

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file){
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("WARNING: Program has no file on disk (possibly running from memory)\n"));
        char_memory_delete(&filename_key);
        RET_ACCEPT
    }
    
    __u32 filepath_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 138;
    struct empty_buffer *filepath_buf = char_memory_allocate(&filepath_key, NULL);
    if (!filepath_buf) 
        RET_REJECT

    if (filepath_buf) {
        struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
        if (dentry) {
            const char *dname = BPF_CORE_READ(dentry, d_name.name);
            bpf_core_read_str(filepath_buf->_buff_, MAX_STR, dname);
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: Binary file on disk: %s\n", filepath_buf->_buff_));
        }
        char_memory_delete(&filepath_key);
    }

    filevalid=1;

    __u32 interpreter_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 139;
    struct empty_buffer *interpreter_buf = char_memory_allocate(&interpreter_key, NULL);
    if (!interpreter_buf) 
        RET_REJECT

    const char *interp = BPF_CORE_READ(bprm, interp);
    if (interp) {
        if (interpreter_buf) {
            if (bpf_probe_read_str(interpreter_buf->_buff_, LARGE_STR, interp) > 0) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: Interpreter used: %s\n", interpreter_buf->_buff_));
                checkValidElemConfigForceSTRLen(interpreter_buf->_buff_, BPRMInterpreter,RET_REJECT)
            }
        }
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("ALLOWED: Program execution passed all checks\n"));

    FLAG_FOR_HASH(hook_ctx, str_to_u32(filename_buf->_buff_), str_to_u32(interpreter_buf->_buff_), filevalid)

    char_memory_delete(&filename_key);
    char_memory_delete(&interpreter_key);

    RET_ACCEPT
}

static __u32 bprmSecurityCheck_fingerprint(struct hooks_context_t *hook_ctx){
    struct linux_binprm *bprm = hook_ctx->args.bprm_check_security.bprm;
    if(!bprm) RET_ACCEPT

    __u64 filename_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid)+136;
    __u64 interpreter_key = filename_key + 1;
    
    struct empty_buffer *filename_buf = char_memory_allocate(&filename_key, NULL);
    struct empty_buffer *interpreter_buf = char_memory_allocate(&interpreter_key, NULL);
    if (!filename_buf || !interpreter_buf) {
        char_memory_delete(&filename_key);
        char_memory_delete(&interpreter_key);
        RET_ACCEPT
    }
    
    __u8 filevalid=0;
    const char *bprm_filename = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_str(filename_buf->_buff_, MAX_STR, bprm_filename);

    struct file *file = BPF_CORE_READ(bprm, file);

    if (!file){
        filevalid=1;
    }

    const char *interp = BPF_CORE_READ(bprm, interp);
    bpf_probe_read_str(interpreter_buf->_buff_, MAX_STR, interp);

    FLAG_FOR_HASH(hook_ctx,str_to_u32(filename_buf->_buff_), str_to_u32(interpreter_buf->_buff_), filevalid)

    char_memory_delete(&filename_key);
    char_memory_delete(&interpreter_key);

    RET_ACCEPT
}

__PROG_REGISTER__(bprmSecurityCheck, BPRM_SECURITY, bprmSecurityCheck_prog, bprmSecurityCheck_fingerprint)
