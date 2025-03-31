
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
// Wellcome to the hooks center ;0 I hope have enjoyable time here//


// File Section //

// Any kind of permission like +r //
// Target-> bypass file access controls //
SEC("lsm/file_permission")
int BPF_PROG(monitor_file_permission, struct file *file, int mask) {
    return entryStartPoint(FILE_PERMISSION);
}

// Any kind of file ctl //
// Target-> bypass file access controls //
SEC("lsm/file_ioctl")
int BPF_PROG(monitor_file_ioctl, struct file *file, unsigned int cmd) {
    return entryStartPoint(FILE_IOCTL);
}

// Any kind of changing memory access //
// Target-> Check Before changing any memory access //
SEC("lsm/file_mprotect")
int BPF_PROG(monitor_file_mprotect, struct file *file, unsigned long prot, unsigned long flags) {
    return entryStartPoint(FILE_MPROTECT);
}

// Giving File items via IPC //
// Target-> File transfer using IPC (only FD is able to be received by IPC) //
SEC("lsm/file_receive")
int BPF_PROG(monitor_file_receive, struct file *file) {
    return entryStartPoint(FILE_RECEIVE);
}

// Send SIG to parent process SIGIO / SIGURG //
// Target-> SIGIO / SIGURG //
SEC("lsm/file_send_sigiotask")
int BPF_PROG(monitor_file_send_SIGIO_SIGURG, struct task_struct *task, struct fown_struct *fown, int signum) {
    return entryStartPoint(FILE_SIGIOTASK);
}

// Open file or folder //
// Target -> open critical file like /etc/shadow //
SEC("lsm/file_open")
int BPF_PROG(monitor_file_open, struct file *file) {
    return entryStartPoint(FILE_OPEN);
}

// Mount //
// Target -> Open Mount devices //
SEC("lsm/sb_mount")
int BPF_PROG(monitor_sb_mount, const char *dev_name, struct path *path, const char *type, unsigned long flags, void *data) {
    return entryStartPoint(SB_MOUNT);
}



// Memory Section //

// Share Memory //
// Target-> Share memory Permission //
SEC("lsm/shm_alloc_security")
int BPF_PROG(monitor_shm_alloc, struct shmid_kernel *shp) {
    return entryStartPoint(SHM_ALLOC);
}




// The Inode Table Attributes //

// Inode Permission //
// Target->  This hook is triggered when an inode Permission is checked out //
SEC("lsm/inode_permission")
int BPF_PROG(monitor_inode_permission, struct inode *inode, int mask){
    return entryStartPoint(INODE_PERMISSION);
}

// Inode Set //
// Target->  This hook is triggered when Setting Attribute on inode table //
SEC("lsm/inode_setattr")
int BPF_PROG(monitor_inode_setattr, struct dentry *dentry, struct iattr *attr){
    return entryStartPoint(INODE_SETATTR);
}

// Create directory , +w , +ow // Do not forget Dir is type of File
// Target->  This hook is triggered when an inode (essentially, a file) is created //
SEC("lsm/inode_mkdir")
int BPF_PROG(monitor_inode_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode){
    return entryStartPoint(INODE_MKDIR);
}

// Create file , +w , +ow //
// Target->  This hook is triggered when an inode (essentially, a file) is created //
SEC("lsm/inode_create")
int BPF_PROG(monitor_inode_create, struct path *dir, struct dentry *dentry, int flags, umode_t mode){
    return entryStartPoint(INODE_CREATE);
}


// Utilitize //

// Modify Syslog messages //
// Target -> you can monitor or block attempts to write to system logs //
SEC("lsm/syslog")
int BPF_PROG(monitor_syslog, int type, int type) {
    return entryStartPoint(SYSLOG);
}

// Ptrace //
// Target -> parent process tries to keep tracing current process //
SEC("lsm/ptrace_traceme")
int BPF_PROG(monitor_ptrace, int type, void) {
    return entryStartPoint(TASK_PTRACE);
}

// Opening child or light process //
// Target -> Monitor the execve function //
// *** It is the root case of any attacks by using Execve functions //
// Func 1 - execve
SEC("lsm/bprm_check_security")
int BPF_PROG(monitor_bprm_security, struct linux_binprm *bprm) {
    return entryStartPoint(BPRM_SECURITY);
}

// BPF // *** Mojtaba Added this for preventing from any self-attack! , Monitor the BPF hooks ;)
// Target -> Self-Attack , Try to monitor BPF //
SEC("lsm/bpf")
int BPF_PROG(monitor_bpf, int cmd, union bpf_attr *attr, unsigned int size) {
    return entryStartPoint(BPF);
}

// Cap Get //
// Target -> This hook is invoked when capabilities are retrieved for a process //
SEC("lsm/capget")
int BPF_PROG(monitor_capget, struct task_struct *task, struct __user_cap_header_struct *header, struct __user_cap_data_struct *data) {
    return entryStartPoint(SECURITY_CAPGET);
}



// Network //

// Socket creation //
// Target -> Monitor creating socket //
SEC("lsm/socket_create")
int BPF_PROG(monitor_socket_create, int family, int type, int protocol, int kern) {
    return entryStartPoint(SOCKET_CREATE);
}

// Socket connect //
// Target -> Monitor the end host of socket //
SEC("lsm/socket_connect")
int BPF_PROG(monitor_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen) {
    return entryStartPoint(SOCKET_CONNECT);
}



// Task Base Hooks //

// Change the P, G id in the process //
// Target -> This hook checks when a process changes its process group ID (PGID) //
SEC("lsm/task_setpgid")
int BPF_PROG(monitor_spgid, struct task_struct *task, pid_t pgid) {
    return entryStartPoint(TASK_SETPGID);
}

// Get the P, G id in the process //
// Target -> This hook checks when a process changes its process group ID (PGID) //
SEC("lsm/task_getpgid")
int BPF_PROG(monitor_gpid, struct task_struct *task) {
    return entryStartPoint(TASK_GETGID);
}

// Get the P, S id in the process //
// Target -> This hook checks when a process changes its process s ID (sID) //
SEC("lsm/task_getsid")
int BPF_PROG(monitor_gsid, struct task_struct *task) {
    return entryStartPoint(TASK_GETSID);
}


// Change resource limits//
// Target -> This hook checks when a process changes prlimit //
SEC("lsm/task_prlimit")
int BPF_PROG(monitor_prlimit, struct task_struct *task, unsigned int resource, struct rlimit *new_rlim) {
    return entryStartPoint(TASK_PRLIMIT);
}

// Change resource limits//
// Target -> This hook checks when a process changes prlimit //
SEC("lsm/task_setrlimit")
int BPF_PROG(monitor_setprlimit,struct task_struct *task, unsigned int resource, struct rlimit *new_rlim) {
    return entryStartPoint(TASK_SETPRLIMIT);
}

// Kill //
// Target -> Try to kill defences ;) :) // Nothing can escape from me :)
SEC("lsm/task_kill")
int BPF_PROG(monitor_task_kill, struct task_struct *task, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    return entryStartPoint(TASK_KILL);
}

// Clone //
// Target -> Clone from current process //
SEC("lsm/task_alloc")
int BPF_PROG(monitor_task_alloc, struct task_struct *task) {
    return entryStartPoint(TASK_ALLOC);
}

// Move Memory in the process namespace //
// Target -> Fork //
SEC("lsm/task_movememory")
int BPF_PROG(monitor_task_movememory, struct task_struct *task) {
    return entryStartPoint(TASK_MOVEMEMORY);
}

// Ptrace //
// Target -> Target Ptrace process //
SEC("lsm/task_setioprio")
int BPF_PROG(monitor_task_setioprio, struct task_struct *task, int ioprio) {
    return entryStartPoint(TASK_SETIOPRIO);
}
