
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <BTFFunctions.h>
#include <baseheaders.h>
#include <PRM/PRM.h>
#include <PRM/PRMProg.h>
#include <PRM/PRMProgEntry.h>
#include <PRM/PRMProgDispatcher.h>
#include <PRM/PRMstructs.h>
#include <PRM/PRMVerifier.h>



char _license[] SEC("license") = "GPL";

// Mojtaba, The Hook Entry Point //
// Mojtaba, Have Some Fun Times In This Framework //

// Any kind of permission like +r //
// Target-> bypass file access controls //
SEC("lsm/file_permission")
int BPF_PROG(monitor_permission, struct file *file, int mask) {
    return entryStartPoint(FILE_PERMISSION);
}

// Create file , +w , +ow //
// Target->  This hook is triggered when an inode (essentially, a file) is created //
SEC("lsm/inode_create")
int BPF_PROG(monitor_inode_create, struct path *dir, struct dentry *dentry, int flags, umode_t mode){
    return entryStartPoint(INODE_CREATE);
}

// Open or Create any kind of process //
// Target -> This hook is triggered when a new process is created //
SEC("lsm/process_init")
int BPF_PROG(monitor_process, struct task_struct *task) {
    return entryStartPoint(PROCESS_INIT);
}

// Change the P, G id in the process //
// Target -> This hook checks when a process changes its process group ID (PGID) //
SEC("lsm/task_setpgid")
int BPF_PROG(monitor_pgid, struct task_struct *task, pid_t pgid) {
    return entryStartPoint(TASK_SETPGID);
}

// Modify Syslog messages //
// Target -> you can monitor or block attempts to write to system logs //
SEC("lsm/syslog")
int BPF_PROG(monitor_syslog, int type, char *buf, int len) {
    return entryStartPoint(SYSLOG);
}

// Socket creation //
// Target -> Monitor creating socket //
SEC("lsm/socket_create")
int BPF_PROG(monitor_socket_create, int family, int type, int protocol) {
    return entryStartPoint(SOCKET_CREATE);
}

// Socket connect //
// Target -> Monitor the end host of socket //
SEC("lsm/socket_connect")
int BPF_PROG(monitor_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    return entryStartPoint(SOCKET_CONNECT);
}

// Opening child or light process //
// Target -> Monitor the execve function //
// *** It is the root case of any attacks //
SEC("lsm/execve")
int BPF_PROG(monitor_execve, const char *filename, struct task_struct *task) {
    return entryStartPoint(EXECVE);
}

// BPF //
// Target -> Self-Attack , Try to monitor BPF //
SEC("lsm/bpf")
int BPF_PROG(monitor_bpf, struct bpf_prog *prog) {
    return entryStartPoint(BPF);
}

// Open file or folder //
// Target -> open critical file like /etc/shadow //
SEC("lsm/open")
int BPF_PROG(monitor_open, struct file *file) {
    return entryStartPoint(OPEN);
}

// Cap Get //
// Target -> This hook is invoked when capabilities are retrieved for a process //
SEC("lsm/security_capget")
int BPF_PROG(monitor_capget, struct task_struct *task, struct __user_cap_header_struct *header, struct __user_cap_data_struct *data) {
    return entryStartPoint(SECURITY_CAPGET);
}


// Mount //
// Target -> Open Mount devices //
SEC("lsm/mount")
int BPF_PROG(monitor_mount, struct path *path, char *dev_name) {
    return entryStartPoint(MOUNT);
}

// Kill //
// Target -> Try to kill defences ;) :) // Nothing can escape from me :)
SEC("lsm/task_kill")
int BPF_PROG(monitor_task_kill, struct task_struct *task) {
    return entryStartPoint(TASK_KILL);
}

// Clone //
// Target -> Clone from current process //
SEC("lsm/task_alloc")
int BPF_PROG(monitor_clone, struct task_struct *task, unsigned long clone_flags) {
    return entryStartPoint(TASK_ALLOC);
}

// Fork //
// Target -> Fork //
SEC("lsm/task_fork")
int BPF_PROG(monitor_fork, struct task_struct *task) {
    return entryStartPoint(TASK_FORK);
}

// Ptrace //
// Target -> Target Ptrace process //
SEC("lsm/task_ptrace")
int BPF_PROG(monitor_ptrace, struct task_struct *task, long request) {
    return entryStartPoint(TASK_PTRACE);
}
