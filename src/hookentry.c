
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <hookheaders.h>
#include <hookfunctions.h>

char _license[] SEC("license") = "GPL";

// Write ----> STDOUT, File, Pipe //
SEC("lsm/file_permission")
int BPF_PROG(hookentry_write, struct file *file, int mask) {

    if(bpf_detectHarmfulSyscall()) return -EPERM;

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
