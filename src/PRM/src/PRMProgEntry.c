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
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Target PID: %d, has been killed by Killer PID: %d", target_pid, caller_pid));
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
    struct dentry *prev = cur;
    
    for (int i = 0; i < MAX_DIR_ITR && cur; i++) {
        parent = BPF_CORE_READ(cur, d_parent);
        if (!parent || cur == parent) break;
        prev = cur;
        cur = parent;
    }
    
    if (!prev) prev = cur;
    dname = BPF_CORE_READ(prev, d_name.name);
    bpf_core_read_str(path_buf->_buff_, MAX_STR, dname);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Path: %s", path_buf->_buff_));


    bool resCondition=0;
    checkValidElemConfigSTR(path_buf->_buff_,ValidateDirectory,resCondition=1;)
    if(resCondition){
        FLAG_FOR_HASH(hook_ctx, str_to_u32(path_buf->_buff_), 0, 0)
        char_memory_delete(&path_key);
        RET_ACCEPT
    }


    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("INODE CREATE REJECTED for %s",path_buf->_buff_));

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
    struct dentry *prev = cur;
    
    for (int i = 0; i < MAX_DIR_ITR && cur; i++) {
        parent = BPF_CORE_READ(cur, d_parent);
        if (!parent || cur == parent) break;
        prev = cur;
        cur = parent;
    }
    
    if (!prev) prev = cur;
    dname = BPF_CORE_READ(prev, d_name.name);
    bpf_core_read_str(path_buf->_buff_, MAX_STR, dname);
    
    bpf_printk("Path: %s", path_buf->_buff_);

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

    checkValidElemConfigNUMBER(family, SocketProtocolInvalid, RET_REJECT)

    // Implement Me more // Mojtaba
    if (family == AF_INET) {
        dest_ip = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);
        dest_port = BPF_CORE_READ((struct sockaddr_in *)address, sin_port);

        dest_port = (dest_port >> 8) | (dest_port<<8);
        
        bpf_printk("IP: %pI4, Port: %d", &dest_ip, dest_port);
        int len=sizeof(IPDestRules._holder_) / sizeof(IPDestRules._holder_[0]);
        for(int i=0;i<len;i++)
        {
            if (ip_in_subnet(dest_ip, dest_port, IPDestRules._holder_[i])) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Socket connection rejected!!! due to be matched with Rules"));
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
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BPRM with less than 3 char file name !!!! rejected\n"));
        char_memory_delete(&filename_key);
        RET_REJECT
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BPRM Filename called : %s\n", filename_buf->_buff_));

    checkValidElemConfigForceSTRLen(filename_buf->_buff_, BPRMDestination, RET_REJECT)

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file){
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BPRM Suspicious exec: no file struct (possibly memfd or deleted)\n"));
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
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BPRM File attached : %s\n", filepath_buf->_buff_));
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
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BPRM Interpreter caller : %s\n", interpreter_buf->_buff_));
                checkValidElemConfigForceSTRLen(interpreter_buf->_buff_, BPRMInterpreter,RET_REJECT)
            }
        }
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Safe BPRM Call\n"));

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
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Memory RX without root permission has been requested, MMAP attached to [anonymous]!"));
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
            bpf_printk("Memory RX without root permission has been requested, MMAP attached to [%s] directory and file [%s]!",path_buf->_buff_));

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
        
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Income from IP: %pI4 to Port: %d", &src_ip, dst_port));

        int len = sizeof(IPSrcRules._holder_) / sizeof(IPSrcRules._holder_[0]);
        for(int i = 0; i < len; i++) {
            if (ip_in_subnet(src_ip, dst_port, IPSrcRules._holder_[i])) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Income socket connection rejected!!! Source IP matched IPSrcRules for dst port %d", dst_port));
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

    struct dentry *cur = de;
    struct dentry *parent;
    struct dentry *prev = cur;
    
    for (int i = 0; i < MAX_DIR_ITR && cur; i++) {
        parent = BPF_CORE_READ(cur, d_parent);
        if (!parent || cur == parent) break;
        prev = cur;
        cur = parent;
    }
    
    // prev now contains the first directory after root
    if (prev) {
        const char *dir_name = BPF_CORE_READ(prev, d_name.name);
        if (dir_name) {
            bpf_core_read_str(full_path_buf->_buff_, MAX_STR, dir_name);
        }
    }

    bool resCondition1=0;
    checkValidElemConfigForceSTRLen(full_path_buf->_buff_, OpenFileDirectoryDeny, resCondition1=1;)

    bool resCondition2=0;
    checkValidElemConfigForceSTRLen(module_name_buf->_buff_, OpenFileDeny, resCondition2=1;)

    if(resCondition2) RET_REJECT
    
    FLAG_FOR_HASH(hook_ctx, str_to_u32(module_name_buf->_buff_), str_to_u32(full_path_buf->_buff_), 0)

    char_memory_delete(&path_key);
    char_memory_delete(&module_key);

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

    // Get first directory after root (same logic as prog)
    struct dentry *cur = de;
    struct dentry *parent;
    struct dentry *prev = cur;
    
    for (int i = 0; i < MAX_DIR_ITR && cur; i++) {
        parent = BPF_CORE_READ(cur, d_parent);
        if (!parent || cur == parent) break;
        prev = cur;
        cur = parent;
    }
    
    if (prev) {
        const char *dir_name = BPF_CORE_READ(prev, d_name.name);
        if (dir_name) {
            bpf_core_read_str(full_path_buf->_buff_, MAX_STR, dir_name);
        }
    }

    
    FLAG_FOR_HASH(hook_ctx, str_to_u32(module_name_buf->_buff_), str_to_u32(full_path_buf->_buff_), 0)

    char_memory_delete(&module_key);
    char_memory_delete(&path_key);

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
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Module request: %s", module_name_buf->_buff_));

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
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("=== CRED_PREPARE HOOK CALLED ==="));
    
    struct cred *new_cred = hook_ctx->args.cred_prepare.new;
    struct cred *old_cred = hook_ctx->args.cred_prepare.old;
    int flags = hook_ctx->args.cred_prepare.flags;
    
    if (!new_cred || !old_cred) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("CRED_PREPARE: Missing cred structures"));
        RET_ACCEPT
    }
    
    kuid_t old_uid = BPF_CORE_READ(old_cred, uid);
    kuid_t new_uid = BPF_CORE_READ(new_cred, uid);
    kgid_t old_gid = BPF_CORE_READ(old_cred, gid);
    kgid_t new_gid = BPF_CORE_READ(new_cred, gid);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("CRED_PREPARE: UID %d -> %d, GID %d -> %d", old_uid.val, new_uid.val, old_gid.val, new_gid.val));
    
    // Block privilege escalation to root (UID 0)
    if (new_uid.val == 0 && old_uid.val != 0) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Privilege escalation to root UID from %d", old_uid.val));
        RET_REJECT
    }
    
    // Block privilege escalation to root group (GID 0)
    if (new_gid.val == 0 && old_gid.val != 0) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Privilege escalation to root GID from %d", old_gid.val));
        RET_REJECT
    }
    
    
    // Analyze UID lineage for suspicious patterns
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0 && new_gid.val == 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Suspicious: Cred Prepare UID lineage pattern detected: %d", lineage_result));
    }
    
    // Block if suspicious UID pattern detected
    if (lineage_result > LOW_RISK) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Suspicious UID lineage pattern detected: %d", lineage_result));
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
    kgid_t old_gid = BPF_CORE_READ(old_cred, gid);
    kgid_t new_gid = BPF_CORE_READ(new_cred, gid);
    
    bpf_printk("TASK_FIX_SETUID: UID %d->%d, GID %d->%d, flags=%d", old_uid.val, new_uid.val, old_gid.val, new_gid.val, flags);
    
    // CRITICAL: Block any escalation to root (UID 0)
    if (new_uid.val == 0 && old_uid.val != 0) {
        bpf_printk("EXPLOIT BLOCKED: setuid(0) escalation from UID %d", old_uid.val);
        RET_REJECT
    }
    
    // Block escalation to root group (GID 0)
    if (new_gid.val == 0 && old_gid.val != 0) {
        bpf_printk("EXPLOIT BLOCKED: setgid(0) escalation from GID %d", old_gid.val);
        RET_REJECT
    }
    
    // Deep lineage analysis for suspicious patterns
    int lineage_result = BASE;
    if (hook_ctx->key.pid != 0) {
        lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
    }
    
    // Block high-risk lineage patterns
    if (lineage_result > LOW_RISK) {
        bpf_printk("EXPLOIT BLOCKED: Suspicious UID lineage pattern %d", lineage_result);
        RET_REJECT
    }
    
    // Check for containerized root attempts
    if (new_uid.val == 0 && is_containerized_root(task)) {
        bpf_printk("EXPLOIT BLOCKED: Container escape attempt to root");
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
    
    bpf_printk("CAPABLE: cap=%d, opts=%u", cap, opts);
    
    // Block dangerous capabilities that enable SETUID attacks
    // CAP_SETUID (7) - allows setuid() calls
    if (cap == 7) {
        kuid_t uid = BPF_CORE_READ(cred, uid);
        bpf_printk("BLOCKED: CAP_SETUID requested by UID %d", uid.val);
        RET_REJECT
    }
    
    // CAP_SETGID (6) - allows setgid() calls  
    if (cap == 6) {
        kuid_t uid = BPF_CORE_READ(cred, uid);
        bpf_printk("BLOCKED: CAP_SETGID requested by UID %d", uid.val);
        RET_REJECT
    }
    
    // CAP_SETPCAP (8) - transfer capabilities
    if (cap == 8) {
        kuid_t uid = BPF_CORE_READ(cred, uid);
        bpf_printk("BLOCKED: CAP_SETPCAP requested by UID %d", uid.val);
        RET_REJECT
    }
    
    // CAP_SYS_ADMIN (21) - most dangerous capability
    if (cap == 21) {
        kuid_t uid = BPF_CORE_READ(cred, uid);
        int lineage_result = lineageUIDAnalizer(hook_ctx->task, &hook_ctx->key);
        if (lineage_result > LOW_RISK) {
            bpf_printk("BLOCKED: CAP_SYS_ADMIN with suspicious lineage %d", lineage_result);
            RET_REJECT
        }
    }
    
    // CAP_DAC_OVERRIDE (1) - bypass file permissions
    if (cap == 1) {
        kuid_t uid = BPF_CORE_READ(cred, uid);
        if (uid.val != 0) {
            bpf_printk("BLOCKED: CAP_DAC_OVERRIDE by non-root UID %d", uid.val);
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