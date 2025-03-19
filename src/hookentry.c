
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <hookheaders.h>
#include <hookfunctions.c>

// Write ----> STDOUT, File, Pipe //
SEC("lsm/file_permission")
int BPF_PROG(hookentry, struct file *file, int mask) {
    // Get the current task (process)
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    // Check if the process name is "python"
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));

    // Check if the process name contains "python"
    if (bpf_strcontains(comm, "python")) {
        // Deny the write operation
        return -EPERM; // Operation not permitted
    }

    // if (bpf_strncmp(comm, TASK_COMM_LEN, "python") == 0) {
    //     // Deny the write operation
    //     return -1; // Operation not permitted
    // }

    // Allow the write operation
    return 0;
}











char _license[] SEC("license") = "GPL";
