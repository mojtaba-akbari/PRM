# PROG Examples

## Overview

This document provides practical examples of PROGs (Programs) in the PRM Framework. These examples demonstrate how to implement various security policies using the framework's PROG system.

## Example 1: Memory Protection

This PROG prevents non-root processes from making memory executable:

```c
static int memoryProtectCheck(struct hooks_context_t *hook_ctx) {
    bpf_printk("memory protection call\n");
    
    // Use BPF_CORE_READ to safely access the field
    unsigned long prot = BPF_CORE_READ(hook_ctx, args.file_mprotect.prot);
    
    if (prot & PROT_EXEC) {
        if (hook_ctx->key.pid != 0) {
            bpf_printk("memory protection without root\n");
            return -EPERM;
        }
    }

    return 0;
}
```

This PROG:
1. Checks if the memory protection flags include PROT_EXEC
2. If so, verifies that the process has root privileges (pid 0)
3. Denies the operation if a non-root process attempts to make memory executable

## Example 2: Process Execution Control

This PROG prevents execution of binaries from suspicious locations:

```c
static int bprmSecurityCheck(struct hooks_context_t *hook_ctx) {
    struct linux_binprm *bprm = hook_ctx->args.bprm_check_security.bprm;
    if (!bprm) return 1;

    char filename[MAX_STR] = {0};
    char interpreter[MAX_STR] = {0};

    int res = bpf_probe_read_str(filename, sizeof(filename), bprm->filename);
    if (res <= 0 || (res > 0 && res < 3)) {
        bpf_printk("BPRM with less than 3 char file name !!!! rejected\n");
        return 1;
    }

    bpf_printk("BPRM Filename called : %s\n", filename);

    // Check against suspicious locations
    checkValidElemConfigForceSTRLen(&filename[0], BPRMDestination, 1)

    struct file *file = BPF_CORE_READ(bprm, file);
    if (!file) {
        bpf_printk("BPRM Suspicious exec: no file struct (possibly memfd or deleted)\n");
        return 0;
    }

    // Check interpreter
    const char *interp = BPF_CORE_READ(bprm, interp);
    if (bpf_probe_read_str(interpreter, sizeof(interpreter), interp) > 0) {
        bpf_printk("BPRM Interpreter: %s\n", interpreter);
        checkValidElemConfigForceSTRLen(&interpreter[0], BPRMValidInterpreter, 0)
    }

    bpf_printk("Safe BPRM Call\n");
    return 0;
}
```

This PROG:
1. Extracts the binary path and interpreter
2. Checks if the binary is being executed from a suspicious location
3. Verifies that the interpreter is legitimate
4. Denies execution if any checks fail

## Example 3: Network Access Control

This PROG prevents connections to restricted IP addresses and ports:

```c
static int denyMakeSocketToEndHost(struct hooks_context_t *hook_ctx) {
    struct sockaddr *address = hook_ctx->args.socket_connect.address;
    if (!address) return 0;

    struct sockaddr_in *addr4;
    __u32 dest_ip;
    __u16 dest_port;
    __u16 family;

    bpf_probe_read_user(&family, sizeof(family), &address->sa_family);

    if (family == AF_NET) {
        if (bpf_core_read_user(&dest_ip, sizeof(dest_ip), &((struct sockaddr_in *)address)->sin_addr.s_addr))
            return 0;

        if (bpf_core_read_user(&dest_port, sizeof(dest_port), &((struct sockaddr_in *)address)->sin_port))
            return 0;

        dest_port = (dest_port >> 8) | (dest_port<<8);

        int len = sizeof(IPDestRules._holder_) / sizeof(IPDestRules._holder_[0]);
        for (int i = 0; i < len; i++) {
            if (ip_in_subnet(dest_ip, dest_port, IPDestRules._holder_[i])) {
                bpf_printk("Socket connection rejected!!! due to be matched with Rules");
                return 1;
            }   
        }
    }
    
    return 0;
}
```

This PROG:
1. Extracts the destination IP address and port
2. Checks if the connection matches any restricted IP/port combinations
3. Denies the connection if a match is found

## Example 4: Process Protection

This PROG prevents critical processes from being killed:

```c
static int signalKillTracer(struct hooks_context_t *hook_ctx) {
    __u32 key = 0;
    struct SelfPID *value = bpf_map_lookup_elem(&self_pids, &key);
    if (!value) return 0;
    
    struct task_struct *target_task = hook_ctx->args.task_kill.task; 
    struct task_struct *task_killer = bpf_get_current_task_btf();
    struct task_struct *parent = BPF_CORE_READ(task_killer, real_parent);

    __u32 target_pid = BPF_CORE_READ(target_task, pid);
    __u32 caller_uid = (__u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

    bpf_printk("Self PID: %d, Kill-Target PID: %d, Caller EUID: %d", 
               value->pid, target_pid, caller_uid);

    if (value->pid != target_pid) return 0;
    
    if (is_containerized_root(task_killer)) {
        return 1; 
    }

    // Check who wants to kill me
    return lineageUIDAnalizer(task_killer, &hook_ctx->key) > 5 ? 1 : 0;
}
```

This PROG:
1. Checks if the target process is a protected process
2. If so, examines the process trying to kill it
3. Denies the kill if it comes from a containerized root or has a suspicious ancestry

## Example 5: File System Protection

This PROG prevents writing outside of allowed directories:

```c
static int denyWriteOutSideOfValidDirectories(struct hooks_context_t *hook_ctx) {
    struct dentry *cur = hook_ctx->args.inode_create.dentry;
    if (!cur) return 1;

    char *dname;
    char path[MAX_STR] = {0}; 
    struct dentry *parent;
    struct dentry *next;
    int i = 0;
    
    // Traverse directory structure to build path
    for (i; i < MAX_DIR_ITR; i++) {
        dname = BPF_CORE_READ(cur, d_name.name);
        bpf_core_read_str(path, MAX_STR, dname);
        bpf_printk("last dir: %s", path);

        parent = BPF_CORE_READ(cur, d_parent);
        if (!parent || cur == parent) break;

        next = cur;
        cur = parent;
    }

    dname = BPF_CORE_READ(next, d_name.name);
    bpf_core_read_str(path, MAX_STR, dname);

    // Check against allowed directories
    int len = sizeof(ValidateDirectory._holder_) / sizeof(ValidateDirectory._holder_[0]);
    for (i = 0; i < len; i++) {
        bpf_printk("checking dir: %d %s", i, ValidateDirectory._holder_[i]);
        if (strcmp_nolen(&path[0], ValidateDirectory._holder_[i]) == 0)
            return 0; // Allow
    }

    return 1; // Deny
}
```

This PROG:
1. Extracts the directory path for a file creation operation
2. Checks if the directory is in the list of allowed directories
3. Denies the operation if the directory is not allowed

## Best Practices Demonstrated

These examples demonstrate several best practices for PROG development:

1. **Safe Memory Access**: Using proper methods for structure field access
2. **Error Handling**: Checking for null pointers and other error conditions
3. **Debugging**: Using logging functions for debugging
4. **Configuration Access**: Using the PRM system for rule access
5. **Early Returns**: Exiting early when a decision can be made
6. **Bounded Loops**: Using explicit loop bounds for compliance with kernel restrictions