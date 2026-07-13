#include "../include/PRMProgEntry.h"
#include "PRMProgHelper.c"

/*
    Notice for Prog developers,
    Progs have three different result
    RET_ACCEPT
    RET_REJECT
    RET_ACCEPT_AND_CACHE(hook_ctx_ptr , var1 , var2 , var3)
    Some progs provide cache , however for some kind of Prog you have to cover at least 1 and at max 3 different unique variables
    Generally Progs are designed to be used in a way that they can be used in a chain , we do not add them to the cache however if you require cache
    Be aware of unique variables that you are going to use in your Prog , if you do not cover them , your Prog will not be cached or 
    Attackers will be able to make fake cache and bypass your Prog!
    First find your approach , then try to find a way to cache your Prog! because some of Prog do not need cacheing the other needs
    Try to as much as you can simplify Progs , both aspect of resource which you are using and your Prog complexity

    Use Macro 
*/





// TEST // ----> Good to copy and use it later for other Progs

static __u32 test_prog(struct hooks_context_t *hook_ctx){
    bpf_printk("___PROG___TEST__BRANCH___\n");
    RET_ACCEPT // Let it goes
}
static __u32 test_fingerprint(struct hooks_context_t *hook_ctx){
    RET_ACCEPT
}
__PROG_REGISTER__(test, NONE_CELL, test_prog, test_fingerprint)




// signalKillTracer //
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
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("ALLOWED: PID %d tried to kill PID %d (not a protected process)", caller_pid, target_pid));
        RET_ACCEPT_FORCEFULLY
    }
    
    if(is_containerized_root(killer_task)){ // KILL PRM from root containers
        RET_REJECT  
    }

    
    if(lineageUIDAnalizer(killer_task, &hook_ctx->key) > BASE){
        RET_REJECT
    }
    else{
        // No need to cache , becaue PRM framework goes down ....
        RET_ACCEPT
    }
}
static __u32 signalKillTracer_fingerprint(struct hooks_context_t *hook_ctx){
    RET_ACCEPT
}
__PROG_REGISTER__(signalKillTracer, TASK_KILL, signalKillTracer_prog, signalKillTracer_fingerprint)





// denyWriteOutSideOfValidDirectories //
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
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: File creation requested in directory: %s", path_buf->_buff_));


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
    
    bpf_printk("INSPECT: Fingerprint check for directory: %s", path_buf->_buff_);

    FLAG_FOR_HASH(hook_ctx,str_to_u32(path_buf->_buff_),0,0)
    RET_ACCEPT
}
__PROG_REGISTER__(denyWriteOutSideOfValidDirectories, INODE_CREATE, denyWriteOutSideOfValidDirectories_prog, denyWriteOutSideOfValidDirectories_fingerprint)




// denyMakeSocketToEndHost //
static __u32 denyMakeSocketToEndHost_prog(struct hooks_context_t *hook_ctx){
    struct sockaddr *address = hook_ctx->args.socket_connect.address;
    if(!address) RET_ACCEPT

    __u32 dest_ip = 0;
    __u16 dest_port = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(address, sa_family);

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: Outbound Family connection to %d", family));
    checkValidElemConfigNUMBER(family, SocketProtocolInvalid, RET_REJECT)

    if (family == AF_INET) {
        dest_ip = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);
        dest_port = BPF_CORE_READ((struct sockaddr_in *)address, sin_port);
        dest_port = (dest_port >> 8) | (dest_port << 8);

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: Outbound connection to %pI4 port %d", &dest_ip, dest_port));

        int len = sizeof(IPDestRules._holder_) / sizeof(IPDestRules._holder_[0]);
        for(int i = 0; i < len; i++) {
            if (ip_in_subnet(dest_ip, dest_port, IPDestRules._holder_[i])) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Outbound connection denied to port %d", dest_port));
                RET_REJECT
            }
        }
    }

    FLAG_FOR_HASH(hook_ctx, dest_ip, dest_port, family)
    RET_ACCEPT
}
static __u32 denyMakeSocketToEndHost_fingerprint(struct hooks_context_t *hook_ctx){
    struct sockaddr *address = hook_ctx->args.socket_connect.address;
    if(!address) RET_ACCEPT

    __u32 dest_ip = 0;
    __u16 dest_port = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(address, sa_family);

    if (family == AF_INET) {
        dest_ip = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);
        dest_port = BPF_CORE_READ((struct sockaddr_in *)address, sin_port);
        dest_port = (dest_port >> 8) | (dest_port<<8);
    }
    
    FLAG_FOR_HASH(hook_ctx, dest_ip, dest_port, family)
    RET_ACCEPT
}
__PROG_REGISTER__(denyMakeSocketToEndHost, SOCKET_CONNECT, denyMakeSocketToEndHost_prog, denyMakeSocketToEndHost_fingerprint)





// bprmSecurityCheck //
static __u32 bprmSecurityCheck_prog(struct hooks_context_t *hook_ctx){
    /*
        Running binaries directly from memory (memfd_create)

        Running scripts or loaders from temporary FS

        Exploit payloads using deleted or anonymous inodes

        BYO dynamic linkers or malicious interpreters

        *** for interpreter
            /lib64/ld-linux-x86-64.so.2
            /usr/bin/python
            /usr/bin/bash
            ....
        ***
    */
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
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Program execution rejected (filename too short, suspicious)\n"));
        char_memory_delete(&filename_key);
        RET_REJECT
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: Program execution requested: %s\n", filename_buf->_buff_));

    checkValidElemConfigForceSTRLen(filename_buf->_buff_, BPRMDestination, RET_REJECT)

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file){
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("WARNING: Program has no file on disk (possibly running from memory)\n"));
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
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: Binary file on disk: %s\n", filepath_buf->_buff_));
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
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: Interpreter used: %s\n", interpreter_buf->_buff_));
                checkValidElemConfigForceSTRLen(interpreter_buf->_buff_, BPRMInterpreter,RET_REJECT)
            }
        }
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("ALLOWED: Program execution passed all checks\n"));

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





// memoryProtectCheck //
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

    bpf_probe_read(&reqprot, sizeof(reqprot), &hook_ctx->args.file_mprotect.reqprot); // take care Mojtaba

    if (!file && (reqprot & PROT_EXEC)) {
        if (hook_ctx->key.pid != 0) {
            lineage = lineageUIDAnalizer(taskAskMMAP, &hook_ctx->key);
            if( lineage > BASE){ // JUST ROOT Valid Pattern
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
__PROG_REGISTER__(memoryProtectCheck, FILE_MPROTECT,&memoryProtectCheck_prog, &memoryProtectCheck_fingerprint)




// denyIncomeSocket //
static __u32 denyIncomeSocket_prog(struct hooks_context_t *hook_ctx){
    struct socket *sock = hook_ctx->args.socket_accept.sock;
    if(!sock) RET_ACCEPT

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if(!sk) RET_ACCEPT

    __u32 src_ip = 0;
    __u16 dst_port = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);

    checkValidElemConfigNUMBER(family, SocketProtocolInvalid, RET_REJECT)

    if (family == AF_INET) {
        // Source IP (remote client IP)
        src_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        dst_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: Incoming connection from %pI4 to port %d", &src_ip, dst_port));

        int len = sizeof(IPSrcRules._holder_) / sizeof(IPSrcRules._holder_[0]);
        for(int i = 0; i < len; i++) {
            if (ip_in_subnet(src_ip, dst_port, IPSrcRules._holder_[i])) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Incoming connection denied for port %d (not in allowed range)", dst_port));
                RET_REJECT
            }   
        }
    }

    FLAG_FOR_HASH(hook_ctx, src_ip, dst_port, family)
    RET_ACCEPT
}
static __u32 denyIncomeSocket_fingerprint(struct hooks_context_t *hook_ctx){
    struct socket *sock = hook_ctx->args.socket_accept.sock;
    if(!sock) RET_ACCEPT

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if(!sk) RET_ACCEPT

    __u32 src_ip = 0;
    __u16 dst_port = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family == AF_INET) {
        src_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        dst_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    }
    
    FLAG_FOR_HASH(hook_ctx, src_ip, dst_port, family)
    RET_ACCEPT
}
__PROG_REGISTER__(denyIncomeSocket, SOCKET_ACCEPT, denyIncomeSocket_prog, denyIncomeSocket_fingerprint)



// denyFileOpen //
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

    bpf_printk("INSPECT: File system type: %s %s",sb_name_buf->_buff_,fs_type_buf->_buff_);

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
        bpf_printk("BLOCKED: File open rejected, path too deep to verify");
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
    
    bpf_printk("INSPECT: Opening file='%s' in dir='%s' (write=%d)", module_name_buf->_buff_, full_path_buf->_buff_, is_write);
    
    bool is_system_dir = false;
    bool is_aggresive = false;
    checkValidElemConfigSTR(full_path_buf->_buff_, BinaryHomeDirectory, is_system_dir=true;)
    
    // Mojjjaaak Please develop me more , i know you are tied up but this line is really fcking stupid one , develope me 
    checkValidElemConfigSTR(sb_name_buf->_buff_, BinaryHomeDirectory, is_system_dir=true;)
    // For god , JK will hit me if i develop you , stay here and hold on 
    
    bpf_printk("INSPECT: System directory=%d", is_system_dir);
    
    // Check Aggresive before let them pass through ---> Mojjjak , it is a little bit difficult because the system highly is being restricted //
    checkValidElemConfigSTR(module_name_buf->_buff_, OpenFileDenyAggressivly, is_aggresive=true;)
    if(is_aggresive && is_system_dir)
    {
        bpf_printk("BLOCKED: Opening this file is strictly forbidden");
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_REJECT
    }

    // I have a bug here !!!!!!!!!!!!!!!!!!!!!!!! fix this mojjjak , i have to be un-readable even for some sb !
    if (is_system_dir && !is_write) {
        bpf_printk("ALLOWED: Reading from system directory");
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_ACCEPT
    }
    
    // Block ALL data file access (read/write) outside ValidateDirectory
    bool access_allowed = false;
    checkValidElemConfigSTR(full_path_buf->_buff_, ValidateDirectory, access_allowed=true;)
    
    bpf_printk("INSPECT: Directory access allowed=%d", access_allowed);
    
    if (!access_allowed) {
        bpf_printk("BLOCKED: File is outside allowed directories");
        char_memory_delete(&path_key);
        char_memory_delete(&module_key);
        char_memory_delete(&sb_name_key);
        char_memory_delete(&fs_type_key);
        RET_REJECT
    }

    // Block dangerous file extensions
    bool resCondition2=0;
    checkValidElemConfigForceSTRLen(module_name_buf->_buff_, OpenFileDeny, resCondition2=1;)
    if(resCondition2) {
        bpf_printk("BLOCKED: File type is not allowed");
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

    // Get first directory after root (same logic as prog)
    struct dentry *cur = de;
    struct dentry *parent;
    struct dentry *first_after_root = NULL;
    struct dentry *prev = cur;
    
    // Single loop: max 50 depth
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




// denyLoadModule //
static __u32 denyLoadModule_prog(struct hooks_context_t *hook_ctx){
    char *kmod_name = hook_ctx->args.kernel_module_request.kmod_name;
    if(!kmod_name) RET_ACCEPT

    __u64 module_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 600;
    struct empty_buffer *module_name_buf = char_memory_allocate(&module_key, NULL);
    if (!module_name_buf) {
        char_memory_delete(&module_key);
        RET_ACCEPT
    }

    bpf_core_read_str(module_name_buf->_buff_, MAX_STR, kmod_name);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: Kernel module load requested: %s", module_name_buf->_buff_));

    checkValidElemConfigForceSTRLen(module_name_buf->_buff_, ModuleDeny, RET_REJECT)
    
    char_memory_delete(&module_key);

    FLAG_FOR_HASH(hook_ctx, str_to_u32(module_name_buf->_buff_), 0, 0)
    RET_ACCEPT
}
static __u32 denyLoadModule_fingerprint(struct hooks_context_t *hook_ctx){
    char *kmod_name = hook_ctx->args.kernel_module_request.kmod_name;
    if(!kmod_name) RET_ACCEPT

    __u64 module_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 601;
    struct empty_buffer *module_name_buf = char_memory_allocate(&module_key, NULL);
    if (!module_name_buf) {
        char_memory_delete(&module_key);
        RET_ACCEPT
    }

    bpf_core_read_str(module_name_buf->_buff_, MAX_STR, kmod_name);
    
    FLAG_FOR_HASH(hook_ctx, str_to_u32(module_name_buf->_buff_), 0, 0)
    char_memory_delete(&module_key);
    RET_ACCEPT
}
__PROG_REGISTER__(denyLoadModule, KERNEL_MODULE_REQUEST, denyLoadModule_prog, denyLoadModule_fingerprint)



// credPrepareCheck //
static __u32 credPrepareCheck_prog(struct hooks_context_t *hook_ctx){
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: Credential change detected"));
    
    struct cred *new_cred = hook_ctx->args.cred_prepare.new;
    struct cred *old_cred = hook_ctx->args.cred_prepare.old;
    int flags = hook_ctx->args.cred_prepare.flags;
    
    if (!new_cred || !old_cred) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("WARNING: Credential structures missing, allowing"));
        RET_ACCEPT
    }
    
    kuid_t old_uid = BPF_CORE_READ(old_cred, uid);
    kuid_t new_uid = BPF_CORE_READ(new_cred, uid);
    kgid_t old_gid = BPF_CORE_READ(old_cred, gid);
    kgid_t new_gid = BPF_CORE_READ(new_cred, gid);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INSPECT: User ID changing from %d to %d, Group ID from %d to %d", old_uid.val, new_uid.val, old_gid.val, new_gid.val));
    
    // Block privilege escalation to root (UID 0)
    if (new_uid.val == 0 && old_uid.val != 0) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: User %d tried to become root (privilege escalation)", old_uid.val));
        RET_REJECT
    }
    
    // Block privilege escalation to root group (GID 0)
    if (new_gid.val == 0 && old_gid.val != 0) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Group %d tried to become root group (privilege escalation)", old_gid.val));
        RET_REJECT
    }
    
    
    // Analyze UID lineage for suspicious patterns
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0 && new_gid.val == 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("WARNING: Suspicious process ancestry pattern detected (severity=%d)", lineage_result));
    }
    
    // Block if suspicious UID pattern detected
    if (lineage_result > LOW_RISK) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Process ancestry indicates possible attack (severity=%d)", lineage_result));
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
    
    // Analyze UID lineage for fingerprinting
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
    }
    
    FLAG_FOR_HASH(hook_ctx, old_uid.val, new_uid.val, lineage_result)
    RET_ACCEPT
}
__PROG_REGISTER__(credPrepareCheck, CRED_PREPARE, credPrepareCheck_prog, credPrepareCheck_fingerprint)




// TaskFixSetUIDCheck //
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
    
    bpf_printk("INSPECT: SetUID change: UID %d->%d, EUID %d->%d, GID %d->%d", old_uid.val, new_uid.val, old_euid.val, new_euid.val, old_gid.val, new_gid.val, flags);
    
    // Block effective UID escalation to root (catches setuid binaries)
    if (new_euid.val == 0 && old_euid.val != 0 && old_uid.val != 0) {
        // Allow if it's a legitimate setuid binary from system paths
        struct execPath *ePath = getExecPath(task, createTaskUKey(task, &hook_ctx->taskUKey));
        if (ePath) {
            bpf_printk("INSPECT: Binary runs from trusted directory=%d", ePath->isValidDirectory);
            if (ePath->isValidDirectory == 1) {
                bpf_printk("ALLOWED: SetUID binary from a trusted system directory");
                RET_ACCEPT
            }
        } else {
            bpf_printk("WARNING: Could not determine binary path");
        }
        bpf_printk("BLOCKED: Process tried to gain root via seteuid(0) from EUID %d", old_euid.val);
        RET_REJECT
    }

    // Block real UID escalation to root
    if (new_uid.val == 0 && old_uid.val != 0) {
        bpf_printk("BLOCKED: Process tried to gain root via setuid(0) from UID %d", old_uid.val);
        RET_REJECT
    }
    
    // Block GID escalation to root
    if (new_gid.val == 0 && old_gid.val != 0) {
        bpf_printk("BLOCKED: Process tried to gain root group via setgid(0) from GID %d", old_gid.val);
        RET_REJECT
    }
    
    // UID lineage analysis
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
    }
    
    if (lineage_result > LOW_RISK) {
        bpf_printk("BLOCKED: SetUID denied due to suspicious process ancestry (severity=%d)", lineage_result);
        RET_REJECT
    }
    
    // Container escape detection
    if (new_uid.val == 0 && is_containerized_root(task)) {
        bpf_printk("BLOCKED: Container process tried to escape to root");
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
    
    // Analyze lineage for fingerprinting
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
    }
    
    FLAG_FOR_HASH(hook_ctx, old_uid.val, new_uid.val, lineage_result)
    RET_ACCEPT
}
__PROG_REGISTER__(taskFixSetUIDCheck, TASK_FIX_SETUID, taskFixSetUIDCheck_prog, taskFixSetUIDCheck_fingerprint)




// capableCheck //
static __u32 capableCheck_prog(struct hooks_context_t *hook_ctx){
    const struct cred *cred = hook_ctx->args.capable.cred;
    int cap = hook_ctx->args.capable.cap;
    unsigned int opts = hook_ctx->args.capable.opts;
    
    if (!cred) RET_ACCEPT
    
    kuid_t uid = BPF_CORE_READ(cred, uid);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("INSPECT: Capability check cap=%d for UID %d", cap, opts, uid.val));
    
    // Allow root to use SETUID/SETGID (needed for SSH, sudo, etc.)
    if (uid.val == 0) {
        int lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
        if (lineage_result > LOW_RISK) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Root process has suspicious ancestry, admin capability denied (severity=%d)", lineage_result));
            RET_REJECT
        }

        //Mojjjak bro , do not uncomment it , because most of time it comes with pid 0 which is causing issues
        //FLAG_FOR_HASH(hook_ctx, cap, opts, 0)

        RET_ACCEPT
    }
    
    // Block non-root from using dangerous capabilities
    // CAP_SETUID (7) - allows setuid() calls
    if (cap == 7) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Non-root user %d tried to use setuid capability", uid.val));
        RET_REJECT
    }
    
    // CAP_SETGID (6) - allows setgid() calls  
    if (cap == 6) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Non-root user %d tried to use setgid capability", uid.val));
        RET_REJECT
    }
    
    // CAP_SETPCAP (8) - transfer capabilities
    if (cap == 8) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Non-root user %d tried to transfer capabilities", uid.val));
        RET_REJECT
    }
    
    // CAP_SYS_ADMIN (21) - most dangerous capability
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





















// *** Fix Line *** //
// Initialize Hooks //
__INSTALL_PROGS__
// *** //