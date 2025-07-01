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
    if(!value) RET_ACCEPT
    
    struct task_struct *target_task = hook_ctx->args.task_kill.task; 
    struct task_struct *task_killer = bpf_get_current_task_btf();
    struct task_struct *parent = BPF_CORE_READ(task_killer, real_parent);

    __u32 target_pid = BPF_CORE_READ(target_task, pid);
    __u32 caller_uid = hook_ctx->key.pid;

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Self PID: %d, Kill-Target PID: %d, Caller EUID: %d", value->pid, target_pid, caller_uid));

    if(value->pid != target_pid) RET_ACCEPT
    
    if(is_containerized_root(task_killer)){
        RET_REJECT 
    }

    
    if(lineageUIDAnalizer(task_killer, &hook_ctx->key) > BASE){
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

    __u64 path_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 400;
    char *path = char_memory_allocate(&path_key, NULL);
    if (!path) {
        char_memory_delete(&path_key);
        RET_REJECT
    }

    char *dname;
    struct dentry *parent;
    struct dentry *next = cur;
    int i=0;
    for (i; i < MAX_DIR_ITR; i++) {

        dname = BPF_CORE_READ(cur, d_name.name);
        bpf_core_read_str(path, MAX_STR, dname);
        bpf_printk("last dir: %s",path);

        parent = BPF_CORE_READ(cur, d_parent);
        if(!parent || cur == parent) break;

        next=cur;
        cur = parent;
    }

    if(!next) next = cur;
    dname = BPF_CORE_READ(next, d_name.name);
    bpf_core_read_str(path, MAX_STR, dname);

    int len=sizeof(ValidateDirectory._holder_) / sizeof(ValidateDirectory._holder_[0]);
    for(i=0;i<len;i++){
        bpf_printk("checking dir: %d %s",i,ValidateDirectory._holder_[i]);
        if (strcmp_nolen(path, ValidateDirectory._holder_[i]) == 0){
            FLAG_FOR_HASH(hook_ctx,str_to_u32(path),0,0)
            RET_ACCEPT
        }
    }
    RET_REJECT 
}
static __u32 denyWriteOutSideOfValidDirectories_fingerprint(struct hooks_context_t *hook_ctx){
    struct dentry *cur = hook_ctx->args.inode_create.dentry;
    if(!cur) RET_REJECT

    __u64 path_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 401;
    char *path = char_memory_allocate(&path_key, NULL);
    if (!path) RET_REJECT

    char *dname;
    struct dentry *parent;
    struct dentry *next = cur;
    int i=0;
    for (i; i < MAX_DIR_ITR; i++) {

        dname = BPF_CORE_READ(cur, d_name.name);
        bpf_core_read_str(path, MAX_STR, dname);
        bpf_printk("last dir: %s",path);

        parent = BPF_CORE_READ(cur, d_parent);
        if(!parent || cur == parent) break;

        next=cur;
        cur = parent;
    }

    if(!next) next = cur;
    dname = BPF_CORE_READ(next, d_name.name);
    bpf_core_read_str(path, MAX_STR, dname);

    FLAG_FOR_HASH(hook_ctx,str_to_u32(path),0,0)
    RET_ACCEPT
}
__PROG_REGISTER__(denyWriteOutSideOfValidDirectories, INODE_CREATE, denyWriteOutSideOfValidDirectories_prog, denyWriteOutSideOfValidDirectories_fingerprint)




// denyMakeSocketToEndHost //
static __u32 denyMakeSocketToEndHost_prog(struct hooks_context_t *hook_ctx){
    bpf_printk("in");
    struct sockaddr *address = hook_ctx->args.socket_connect.address;
    if(!address) RET_ACCEPT

    __u32 dest_ip = 0;
    __u16 dest_port = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(address, sa_family);
    
    bpf_printk("Family: %d", family);

    if (family == AF_NET) {

        bpf_printk("in2");

        dest_ip = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);
        dest_port = BPF_CORE_READ((struct sockaddr_in *)address, sin_port);

        dest_port = (dest_port >> 8) | (dest_port<<8);
        
        bpf_printk("IP: %pI4, Port: %d", &dest_ip, dest_port);

        bpf_printk("in3");
        int len=sizeof(IPDestRules._holder_) / sizeof(IPDestRules._holder_[0]);
        for(int i=0;i<len;i++)
        {
            if (ip_in_subnet(dest_ip, dest_port, IPDestRules._holder_[i])) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Socket connection rejected!!! due to be matched with Rules"));
                RET_REJECT
            }   
        }
    }
    
    bpf_printk("in4");

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

    if (family == AF_NET) {
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
        ***
    */
    struct linux_binprm *bprm = hook_ctx->args.bprm_check_security.bprm;
    if(!bprm) RET_REJECT

    __u64 filename_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid)+137;
    __u64 interpreter_key = filename_key + 1;
    
    char *filename = char_memory_allocate(&filename_key, NULL);
    char *interpreter = char_memory_allocate(&interpreter_key, NULL);
    if (!filename || !interpreter) {
        char_memory_delete(&filename_key);
        char_memory_delete(&interpreter_key);
        RET_REJECT
    }
    
    __u8 filevalid=0;

    const char *bprm_filename = BPF_CORE_READ(bprm, filename);
    int res = bpf_probe_read_str(filename, MAX_STR, bprm_filename);
    if (res <= 0 || (res > 0 && res < 3))
    {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BPRM with less than 3 char file name !!!! rejected\n"));
        char_memory_delete(&filename_key);
        char_memory_delete(&interpreter_key);
        RET_REJECT
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BPRM Filename called : %s\n", filename));

    checkValidElemConfigForceSTRLen(&filename[0], BPRMDestination, 1)

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file){
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BPRM Suspicious exec: no file struct (possibly memfd or deleted)\n"));
        char_memory_delete(&filename_key);
        char_memory_delete(&interpreter_key);
        RET_ACCEPT
    }
    filevalid=1;

    const char *interp = BPF_CORE_READ(bprm, interp);

    if (bpf_probe_read_str(interpreter, MAX_STR, interp) > 0) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BPRM Interpreter: %s\n", interpreter));
        checkValidElemConfigForceSTRLen(&interpreter[0], BPRMValidInterpreter, 0)
    }

    bpf_printk("Safe BPRM Call\n");
    __u32 result = str_to_u32(filename);
    __u32 interp_result = str_to_u32(interpreter);
    
    char_memory_delete(&filename_key);
    char_memory_delete(&interpreter_key);
    
    FLAG_FOR_HASH(hook_ctx, result, interp_result, filevalid)
    RET_ACCEPT
}
static __u32 bprmSecurityCheck_fingerprint(struct hooks_context_t *hook_ctx){
    struct linux_binprm *bprm = hook_ctx->args.bprm_check_security.bprm;
    if(!bprm) RET_ACCEPT

    __u64 filename_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid)+136;
    __u64 interpreter_key = filename_key + 1;
    
    char *filename = char_memory_allocate(&filename_key, NULL);
    char *interpreter = char_memory_allocate(&interpreter_key, NULL);
    if (!filename || !interpreter) {
        char_memory_delete(&filename_key);
        char_memory_delete(&interpreter_key);
        RET_ACCEPT
    }
    
    __u8 filevalid=0;
    const char *bprm_filename = BPF_CORE_READ(bprm, filename);
    bpf_probe_read_str(filename, MAX_STR, bprm_filename);

    struct file *file = BPF_CORE_READ(bprm, file); //add me to cache , not now in future :) because i have structure not anything else , maybe we can add it as number 1

    if (!file){
        filevalid=1;
    }

    const char *interp = BPF_CORE_READ(bprm, interp);
    bpf_probe_read_str(interpreter, MAX_STR, interp);

    __u32 result = str_to_u32(filename);
    __u32 interp_result = str_to_u32(interpreter);
    
    char_memory_delete(&filename_key);
    char_memory_delete(&interpreter_key);

    FLAG_FOR_HASH(hook_ctx,result, interp_result, filevalid)
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
    char *path = char_memory_allocate(&path_key, NULL);
    if (!path) {
        char_memory_delete(&path_key);
        RET_REJECT
    }

    bpf_probe_read(&reqprot, sizeof(reqprot), &hook_ctx->args.file_mprotect.reqprot); // take care Mojtaba

    if (!file && (reqprot & PROT_EXEC)) {
        if (hook_ctx->key.pid != 0) {
            lineage = lineageUIDAnalizer(taskAskMMAP, &hook_ctx->key);
            bpf_printk("IN[%d], Lineage[%d]", reqprot, lineage);
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
            memset(path,'\0',MAX_STR);
            bpf_core_read_str(path, MAX_STR, dname);

            parent = BPF_CORE_READ(cur, d_parent);
            if(!parent || cur == parent) break;

            prv=cur;
            cur = parent;
        }

        if(!prv) prv = cur;
        dname = BPF_CORE_READ(prv, d_name.name);
        bpf_core_read_str(path, MAX_STR, dname);

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),
            bpf_printk("Memory RX without root permission has been requested, MMAP attached to [%s] directory and file [%s]!",path));

        checkValidElemConfigForceSTRLen(path, MMAPFileAttached, 1)
    }

    __u32 result = str_to_u32(path);
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
    char *path = char_memory_allocate(&path_key, NULL);
    if (!path) {
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
            memset(path,'\0',MAX_STR);
            bpf_core_read_str(path, MAX_STR, dname);

            parent = BPF_CORE_READ(cur, d_parent);
            if(!parent || cur == parent) break;

            next=cur;
            cur = parent;
        }

        if(!next) next = cur;
        dname = BPF_CORE_READ(next, d_name.name);
        bpf_core_read_str(path, MAX_STR, dname);
    }

    __u32 result = str_to_u32(path);
    char_memory_delete(&path_key);

    FLAG_FOR_HASH(hook_ctx,result, reqprot , lineage)
    RET_ACCEPT 
}
__PROG_REGISTER__(memoryProtectCheck, FILE_MPROTECT,&memoryProtectCheck_prog, &memoryProtectCheck_fingerprint)










// *** Fix Line *** //
__INSTALL_PROGS__
// *** //