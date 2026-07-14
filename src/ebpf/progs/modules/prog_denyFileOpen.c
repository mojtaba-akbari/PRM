/* PROG Module: denyFileOpen
 * Hook: FILE_OPEN
 * Slot: 7
 *
 * Restricts file access by directory and filename.
 * Blocks writes outside ValidateDirectory.
 * Blocks dangerous filenames from OpenFileDeny/OpenFileDenyAggressivly.
 */

static __u32 denyFileOpen_prog(struct hooks_context_t *hook_ctx){
    struct file *file = hook_ctx->args.file_open.file;
    if(!file) RET_REJECT

    struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
    if(!de) RET_REJECT

    const char *name_ptr = BPF_CORE_READ(de, d_name.name);
    if(!name_ptr) RET_REJECT

    __u64 module_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 549;
    struct empty_buffer *module_name_buf = char_memory_allocate(&module_key, NULL);
    if (!module_name_buf) {
        char_memory_delete(&module_key);
        RET_REJECT
    }

    bpf_core_read_str(module_name_buf->_buff_, MAX_STR, name_ptr);

    __u64 path_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 571;
    struct empty_buffer *full_path_buf = char_memory_allocate(&path_key, NULL);
    if (!full_path_buf) {
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        RET_REJECT
    }

    __u64 sb_name_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 573;
    struct empty_buffer *sb_name_buf = char_memory_allocate(&sb_name_key, NULL);
    if (!sb_name_buf) {
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        RET_REJECT
    }

    __u64 fs_type_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 574;
    struct empty_buffer *fs_type_buf = char_memory_allocate(&fs_type_key, NULL);
    if (!fs_type_buf) {
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_REJECT
    }

    bool is_kernel_fs=false;
    get_filesystem_info(file,sb_name_buf->_buff_,&is_kernel_fs,fs_type_buf->_buff_);

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("INSPECT: File system type: %s %s",sb_name_buf->_buff_,fs_type_buf->_buff_));

    struct dentry *cur = de;
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
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: File open rejected, path too deep to verify"));
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_REJECT
    }
    
    const char *dir_name = BPF_CORE_READ(first_after_root, d_name.name);
    if (dir_name) {
        bpf_core_read_str(full_path_buf->_buff_, MAX_STR, dir_name);
    }

    unsigned int f_flags = BPF_CORE_READ(file, f_flags);
    bool is_write = (f_flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND));
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("INSPECT: Opening file='%s' in dir='%s' (write=%d)", module_name_buf->_buff_, full_path_buf->_buff_, is_write));
    
    bool is_system_dir = false;
    bool is_aggresive = false;
    checkValidElemConfigSTR(full_path_buf->_buff_, BinaryHomeDirectory, is_system_dir=true;)
    checkValidElemConfigSTR(sb_name_buf->_buff_, BinaryHomeDirectory, is_system_dir=true;)
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("INSPECT: System directory=%d", is_system_dir));
    
    checkValidElemConfigSTR(module_name_buf->_buff_, OpenFileDenyAggressivly, is_aggresive=true;)
    if(is_aggresive && is_system_dir)
    {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: Opening this file is strictly forbidden"));
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_REJECT
    }

    if (is_system_dir && !is_write) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("ALLOWED: Reading from system directory"));
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_ACCEPT
    }
    
    bool access_allowed = false;
    checkValidElemConfigSTR(full_path_buf->_buff_, ValidateDirectory, access_allowed=true;)
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("INSPECT: Directory access allowed=%d", access_allowed));
    
    if (!access_allowed) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: File is outside allowed directories"));
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_REJECT
    }

    bool resCondition2=0;
    checkValidElemConfigForceSTRLen(module_name_buf->_buff_, OpenFileDeny, resCondition2=1;)
    if(resCondition2) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: File type is not allowed"));
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_REJECT
    }
    
    FLAG_FOR_HASH(hook_ctx, str_to_u32(module_name_buf->_buff_), str_to_u32(full_path_buf->_buff_), is_write)

    char_memory_delete(&path_key);
    char_memory_delete(&module_key);
    char_memory_delete(&sb_name_key);
    char_memory_delete(&fs_type_key);

    RET_ACCEPT
}

static __u32 denyFileOpen_fingerprint(struct hooks_context_t *hook_ctx){
    struct file *file = hook_ctx->args.file_open.file;
    if(!file) RET_ACCEPT

    struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
    if(!de) RET_ACCEPT

    const char *name_ptr = BPF_CORE_READ(de, d_name.name);
    if(!name_ptr) RET_ACCEPT

    __u64 module_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 501;
    struct empty_buffer *module_name_buf = char_memory_allocate(&module_key, NULL);
    if (!module_name_buf) {
        char_memory_delete(&module_key);
        RET_ACCEPT
    }

    bpf_core_read_str(module_name_buf->_buff_, MAX_STR, name_ptr);

    __u64 path_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 503;
    struct empty_buffer *full_path_buf = char_memory_allocate(&path_key, NULL);
    if (!full_path_buf) {
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        RET_ACCEPT
    }

    __u64 sb_name_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 573;
    struct empty_buffer *sb_name_buf = char_memory_allocate(&sb_name_key, NULL);
    if (!sb_name_buf) {
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        RET_REJECT
    }

    __u64 fs_type_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 574;
    struct empty_buffer *fs_type_buf = char_memory_allocate(&fs_type_key, NULL);
    if (!fs_type_buf) {
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_REJECT
    }

    bool is_kernel_fs=false;
    get_filesystem_info(file,sb_name_buf->_buff_,&is_kernel_fs,fs_type_buf->_buff_);

    struct dentry *cur = de;
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
    
    const char *dir_name = BPF_CORE_READ(first_after_root, d_name.name);
    if (dir_name) {
        bpf_core_read_str(full_path_buf->_buff_, MAX_STR, dir_name);
    }

    FLAG_FOR_HASH(hook_ctx, str_to_u32(module_name_buf->_buff_), str_to_u32(full_path_buf->_buff_), str_to_u32(sb_name_buf->_buff_))

    char_memory_delete(&module_key);
    char_memory_delete(&path_key);
    char_memory_delete(&sb_name_key);
    char_memory_delete(&fs_type_key);

    RET_ACCEPT
}

__PROG_REGISTER__(denyFileOpen, FILE_OPEN, denyFileOpen_prog, denyFileOpen_fingerprint)
