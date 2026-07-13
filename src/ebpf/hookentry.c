#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "include/PRMVerifier.h"
#include "core/PRMVerifier.c"



char _license[] SEC("license") = "GPL";




// Mojtaba, The Hook Entry Point //
// Wellcome to the hooks center ;0 I hope have enjoyable time here//

// Notice: Attach BPF before other Progs we need to save this PID securly in the cookie //
SEC("raw_tp/sys_enter")
int BPF_PROG(boot_loader){
    RET_ACCEPT
}

// BPF // *** Mojtaba Added this for preventing from any self-attack! , Monitor the BPF hooks ;)
// Target -> Self-Attack , Try to monitor BPF //
SEC("lsm/bpf")
int BPF_PROG(monitor_bpf, int cmd, union bpf_attr *attr, unsigned int size) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2000;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    hook_ctx->key = UNIQUEKEY(pid_tgid,BPF);
    //kernelThreadCheck(hook_ctx);
    
    return saveSelfPID(hook_ctx);
}

// Any kind of permission like +r //
// Target-> bypass file access controls //
SEC("lsm/file_permission")
int BPF_PROG(monitor_file_permission, struct file *file, int mask) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2001;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT
    
    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,FILE_PERMISSION);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Any kind of file ctl //
// Target-> bypass file access controls //
SEC("lsm/file_ioctl")
int BPF_PROG(monitor_file_ioctl, struct file *file, unsigned int cmd) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2002;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT
    
    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,FILE_IOCTL);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Any kind of changing memory access //
// Target-> Check Before changing any memory access //
SEC("lsm/file_mprotect")
int BPF_PROG(monitor_file_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2003;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT
    
    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,FILE_MPROTECT);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    hook_ctx->args.file_mprotect.vma=vma;
    hook_ctx->args.file_mprotect.reqprot=reqprot;
    hook_ctx->args.file_mprotect.prot=prot;


    return entryStartPoint(hook_ctx);
}

// Giving File items via IPC //
// Target-> File transfer using IPC (only FD is able to be received by IPC) //
SEC("lsm/file_receive")
int BPF_PROG(monitor_file_receive, struct file *file) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2004;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT
    
    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,FILE_RECEIVE);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Send SIG to parent process SIGIO / SIGURG //
// Target-> SIGIO / SIGURG //
SEC("lsm/file_send_sigiotask")
int BPF_PROG(monitor_file_send_SIGIO_SIGURG, struct task_struct *task, struct fown_struct *fown, int signum) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2005;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT
    
    hook_ctx->key = UNIQUEKEY(pid_tgid,FILE_SIGIOTASK);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Open file or folder //
// Target -> open critical file like /etc/shadow //
SEC("lsm/file_open")
int BPF_PROG(monitor_file_open, struct file *file) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2006;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT
    
    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,FILE_OPEN);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    hook_ctx->args.file_open.file=file;
    return entryStartPoint(hook_ctx);
}

// Mount //
// Target -> Open Mount devices //
SEC("lsm/sb_mount")
int BPF_PROG(monitor_sb_mount, const char *dev_name, struct path *path, const char *type, unsigned long flags, void *data) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2007;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,SB_MOUNT);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Share Memory //
// Target-> Share memory Permission //
SEC("lsm/shm_alloc_security")
int BPF_PROG(monitor_shm_alloc, struct shmid_kernel *shp) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2008;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,SHM_ALLOC);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT

    return entryStartPoint(hook_ctx);
}

// Inode Permission //
// Target->  This hook is triggered when an inode Permission is checked out //
SEC("lsm/inode_permission")
int BPF_PROG(monitor_inode_permission, struct inode *inode, int mask){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2009;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,INODE_PERMISSION);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT

    return entryStartPoint(hook_ctx);
}

// Inode Set //
// Target->  This hook is triggered when Setting Attribute on inode table //
SEC("lsm/inode_setattr")
int BPF_PROG(monitor_inode_setattr, struct dentry *dentry, struct iattr *attr){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2010;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,INODE_SETATTR);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT

    return entryStartPoint(hook_ctx);
}

// Create directory , +w , +ow // Do not forget Dir is type of File
// Target->  This hook is triggered when an inode (essentially, a file) is created //
SEC("lsm/inode_mkdir")
int BPF_PROG(monitor_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2011;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,INODE_MKDIR);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT

    return entryStartPoint(hook_ctx);
}

// Create file , +w , +ow //
// Target->  This hook is triggered when an inode (essentially, a file) is created //
SEC("lsm/inode_create")
int BPF_PROG(monitor_inode_create, struct path *dir, struct dentry *dentry, int flags, umode_t mode){
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2012;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,INODE_CREATE);
    hook_ctx->args.inode_create.dir=dir;
    hook_ctx->args.inode_create.dentry=dentry;
    hook_ctx->args.inode_create.flags=flags;
    hook_ctx->args.inode_create.mode=mode;

    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    
    return entryStartPoint(hook_ctx);
}

// Modify Syslog messages //
// Target -> you can monitor or block attempts to write to system logs //
SEC("lsm/syslog")
int BPF_PROG(monitor_syslog, int type) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2013;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,SYSLOG);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Ptrace //
// Target -> parent process tries to keep tracing current process //
SEC("lsm/ptrace_traceme")
int BPF_PROG(monitor_ptrace) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2014;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_PTRACE);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Opening child or light process //
// Target -> Monitor the execve function //
// *** It is the root case of any attacks by using Execve functions //
// Func 1 - execve
SEC("lsm/bprm_check_security")
int BPF_PROG(monitor_bprm_security, struct linux_binprm *bprm) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2015;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,BPRM_SECURITY);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    hook_ctx->args.bprm_check_security.bprm=bprm;

    // struct execPath * execPath = bprm_memory_allocate(&hook_ctx->key.pid);
    // struct file *file = BPF_CORE_READ(bprm, file);
    // if (execPath){

    //     bpf_probe_read_str(&execPath->exec, sizeof(execPath->exec), &bprm->filename);
    //     bpf_printk("bprm_check_security %s %d %d", execPath->exec, pid_tgid >> 32, (__u32)pid_tgid);
    //     // struct path *path = NULL;
    //     // bpf_core_read(&path, sizeof(path),&file->f_path);

    //     // if(path){
    //     //     bpf_d_path(path, execPath->exec, sizeof(HUGE_STR));
    //     //     bpf_printk("bprm_check_security %s %d %d", execPath->exec, pid_tgid >> 32, (__u32)pid_tgid);
    //     // }
    // }

    return entryStartPoint(hook_ctx);
}

// Cap Get //
// Target -> This hook is invoked when capabilities are retrieved for a process //
SEC("lsm/capget")
int BPF_PROG(monitor_capget, struct task_struct *target, kernel_cap_t *effective, kernel_cap_t *inheritable, kernel_cap_t *permitted) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2016;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,SECURITY_CAPGET);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Capable //
// Target -> Block attempts by denying CAP_SETUID capability //
SEC("lsm/capable")
int BPF_PROG(monitor_capabilities, const struct cred *cred, struct user_namespace *ns, int cap, unsigned int opts) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2032;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    hook_ctx->key = UNIQUEKEY(pid_tgid,CAPABLE);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    hook_ctx->args.capable.cred = cred;
    hook_ctx->args.capable.ns = ns;
    hook_ctx->args.capable.cap = cap;
    hook_ctx->args.capable.opts = opts;
    return entryStartPoint(hook_ctx);
}

// Socket creation //
// Target -> Monitor creating socket //
SEC("lsm/socket_create")
int BPF_PROG(monitor_socket_create, int family, int type, int protocol, int kern) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2017;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,SOCKET_CREATE);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Socket connect //
// Target -> Monitor the end host of socket //
SEC("lsm/socket_connect")
int BPF_PROG(monitor_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2018;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,SOCKET_CONNECT);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    hook_ctx->args.socket_connect.sock = sock;
    hook_ctx->args.socket_connect.address = address;
    hook_ctx->args.socket_connect.addrlen = addrlen;
    return entryStartPoint(hook_ctx);
}

// Change the P, G id in the process //
// Target -> This hook checks when a process changes its process group ID (PGID) //
SEC("lsm/task_setpgid")
int BPF_PROG(monitor_spgid, struct task_struct *task, pid_t pgid) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2019;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_SETPGID);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Get the P, G id in the process //
// Target -> This hook checks when a process changes its process group ID (PGID) //
SEC("lsm/task_getpgid")
int BPF_PROG(monitor_gpid, struct task_struct *task) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2020;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_GETGID);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Get the P, S id in the process //
// Target -> This hook checks when a process changes its process s ID (sID) //
SEC("lsm/task_getsid")
int BPF_PROG(monitor_gsid, struct task_struct *task) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2021;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_GETSID);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}


// Change resource limits//
// Target -> This hook checks when a process changes prlimit //
SEC("lsm/task_prlimit")
int BPF_PROG(monitor_prlimit, struct task_struct *task, unsigned int resource, struct rlimit *new_rlim) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2022;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_PRLIMIT);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Change resource limits//
// Target -> This hook checks when a process changes prlimit //
SEC("lsm/task_setrlimit")
int BPF_PROG(monitor_setprlimit,struct task_struct *task, unsigned int resource, struct rlimit *new_rlim) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2023;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_SETPRLIMIT);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Kill //
// Target -> Try to kill defences ;) :) // Nothing can escape from me :)
SEC("lsm/task_kill")
int BPF_PROG(monitor_task_kill, struct task_struct *task, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2024;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_KILL);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    hook_ctx->args.task_kill.task=task;
    hook_ctx->args.task_kill.info=info;
    hook_ctx->args.task_kill.sig=sig;
    hook_ctx->args.task_kill.cred=cred;
    return entryStartPoint(hook_ctx);
}

// Clone //
// Target -> Clone from current process //
SEC("lsm/task_alloc")
int BPF_PROG(monitor_task_alloc, struct task_struct *task) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2025;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_ALLOC);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Move Memory in the process namespace //
// Target -> Fork //
SEC("lsm/task_movememory")
int BPF_PROG(monitor_task_movememory, struct task_struct *task) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2026;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_MOVEMEMORY);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Ptrace //
// Target -> Target Ptrace process //
SEC("lsm/task_setioprio")
int BPF_PROG(monitor_task_setioprio, struct task_struct *task, int ioprio) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2027;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_SETIOPRIO);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    return entryStartPoint(hook_ctx);
}

// Fix Xuid //
// Target -> any changes around guid or suid , consist of setuid() or guid() specificly for (sudo) making a fork and set uid as zero //
SEC("lsm/task_fix_setuid")
int BPF_PROG(monitor_task_Xid, struct task_struct *task, const struct cred *old, const struct cred *new, unsigned int flags) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2028;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    hook_ctx->key = UNIQUEKEY(pid_tgid,TASK_FIX_SETUID);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT

    hook_ctx->args.task_fix_set.task=task;
    hook_ctx->args.task_fix_set.old=old;
    hook_ctx->args.task_fix_set.new=new;
    hook_ctx->args.task_fix_set.flags=flags;

    return entryStartPoint(hook_ctx);
}

// Change Xuid //
// Target -> Any change on Xid , u or g //
SEC("lsm/cred_prepare")
int BPF_PROG(handle_priv_esc, struct cred *new, const struct cred *old, int flags) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2029;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    hook_ctx->key = UNIQUEKEY(pid_tgid,CRED_PREPARE);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT

    hook_ctx->args.cred_prepare.new = new;
    hook_ctx->args.cred_prepare.old = old;
    hook_ctx->args.cred_prepare.flags = flags;

    return entryStartPoint(hook_ctx);
}

// Socket accept //
// Target -> Monitor incoming socket connections //
SEC("lsm/socket_accept")
int BPF_PROG(monitor_socket_accept, struct socket *sock, struct socket *newsock) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2030;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,SOCKET_ACCEPT);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    hook_ctx->args.socket_accept.sock = sock;
    hook_ctx->args.socket_accept.newsock = newsock;
    return entryStartPoint(hook_ctx);
}

// Kernel module request //
// Target -> Monitor kernel module loading requests //
SEC("lsm/kernel_module_request")
int BPF_PROG(monitor_kernel_module_request, char *kmod_name) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 ctx_key = generate_tmp_ukey(pid_tgid >> 32, (__u32)pid_tgid) + 2031;
    struct hooks_context_t *hook_ctx = ctx_memory_allocate(&ctx_key);
    if (!hook_ctx) RET_ACCEPT

    hook_ctx->task = (struct task_struct *) bpf_get_current_task_btf();
    hook_ctx->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    hook_ctx->key = UNIQUEKEY(pid_tgid,KERNEL_MODULE_REQUEST);
    if(KERNEL_HOOKS_BYPASS&kernelThreadCheck(hook_ctx)) RET_ACCEPT
    hook_ctx->args.kernel_module_request.kmod_name = kmod_name;
    return entryStartPoint(hook_ctx);
}

