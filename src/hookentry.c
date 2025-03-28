
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <BTFFunctions.h>
#include <baseheaders.h>
#include <PRM/PRM.h>
#include <PRM/PRMprog.h>
#include <PRM/PRMProgEntry.h>
#include <PRM/PRMstructs.h>
#include <PRM/PRMengine.h>



char _license[] SEC("license") = "GPL";

// Put return -EPERM for rejecting any Write // General Role // Mojtaba
// If you want to put another struct in the flow do not forget to return 0 to let it keeps going // Mojtaba

// Write ----> STDOUT, File, Pipe //
// Mojtaba, In permission you can not change any struct because it is just deny or allow //
SEC("lsm/file_permission")
int BPF_PROG(hookentry_write, struct file *file, int mask) {

    
    // if(detectHarmfulSyscall()){
    //    return -EPERM;
    // }

    // Allow the write operations
    return 0;
}

// Any Write Open File Redirected To Home Directory //
// Mojtaba, At the opening time you are able to change the open struct //
SEC("lsm/inode_create")
int BPF_PROG(hookentry_open, struct path *dir, struct dentry *dentry, int flags, umode_t mode)
{
    // Put return -EPERM for rejecting any Write // General Role // Mojtaba
    // If you want to put another struct in the flow do not forget to return 0 to let it keeps going // Mojtaba
    
    if(detectSyscallRelations(ctx)){
        //redirectWritingDestinationFile(dir, dentry, flags, mode);
        return -1;
    }

    // Allow the write operations
    return 0;
}

// SEC("lsm/bprm_check_security")
// int BPF_PROG(deny_execve, struct linux_binprm *bprm) {
//     return -EPERM; // Deny execve
// }

// // LSM hook for file open
// SEC("lsm/file_open")
// int BPF_PROG(deny_open, struct file *file) {
//     return -EPERM; // Deny open
// }

// // LSM hook for socket creation
// SEC("lsm/socket_create")
// int BPF_PROG(deny_socket, int family, int type, int protocol) {
//     return -EPERM; // Deny socket
// }

// // LSM hook for socket connect
// SEC("lsm/socket_connect")
// int BPF_PROG(deny_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
//     return -EPERM; // Deny connect
// }

// // LSM hook for clone
// SEC("lsm/task_alloc")
// int BPF_PROG(deny_clone, struct task_struct *task, unsigned long clone_flags) {
//     return -EPERM; // Deny clone
// }

// // LSM hook for fork
// SEC("lsm/task_fork")
// int BPF_PROG(deny_fork, struct task_struct *task) {
//     return -EPERM; // Deny fork
// }

// // LSM hook for kill
// SEC("lsm/task_kill")
// int BPF_PROG(deny_kill, struct task_struct *task, struct kernel_siginfo *info, int sig) {
//     return -EPERM; // Deny kill
// }

// // LSM hook for ptrace
// SEC("lsm/task_ptrace")
// int BPF_PROG(deny_ptrace, struct task_struct *task, long request) {
//     return -EPERM; // Deny ptrace
// }
