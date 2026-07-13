# UID Ancestor Concept

## Overview

The UID Ancestor concept is a sophisticated security feature in the PRM Framework that tracks the lineage of processes to make security decisions based on their heritage. This approach provides deeper context for security decisions by considering not just the current process, but also its ancestors.

## Core Concept

Every process in Linux has:
1. A parent process that created it
2. A user ID (UID) under which it runs
3. A process ID (PID) that uniquely identifies it

The UID Ancestor system tracks this information to build a process lineage tree and uses it to make security decisions.

## Key Components

### 1. Process Lineage Tracking

The framework tracks process creation and maintains a lineage tree:

```
init (UID 0)
  └── sshd (UID 0)
       └── bash (UID 1000)
            └── sudo (UID 1000 → 0)
                 └── target_process (UID 0)
```

### 2. UID Transition Analysis

The framework analyzes UID transitions in the process lineage:

```c
static int lineageUIDAnalizer(struct task_struct *task, struct hook_key *key) {
    int score = 0;
    struct task_struct *parent;
    
    // Traverse process ancestry
    for (int i = 0; i < MAX_ANCESTRY_DEPTH; i++) {
        // Get parent process
        parent = BPF_CORE_READ(task, real_parent);
        if (!parent || parent == task) break;
        
        // Check for UID transitions
        __u32 task_uid = BPF_CORE_READ(task, cred, uid.val);
        __u32 parent_uid = BPF_CORE_READ(parent, cred, uid.val);
        
        if (task_uid != parent_uid) {
            // UID transition detected
            score += calculate_transition_score(parent_uid, task_uid);
        }
        
        task = parent;
    }
    
    return score;
}
```

### 3. Security Score Calculation

Based on the lineage analysis, a security score is calculated:

```c
static int calculate_transition_score(__u32 from_uid, __u32 to_uid) {
    // Higher score for transitions to privileged UIDs
    if (to_uid == 0) return 5;
    
    // Lower score for transitions to normal user UIDs
    if (from_uid == 0 && to_uid > 1000) return 1;
    
    // Default score for other transitions
    return 2;
}
```

## Security Applications

The UID Ancestor concept is used for:

### 1. Privilege Escalation Detection

Detecting suspicious privilege escalations:

```c
if (lineageUIDAnalizer(task, &hook_ctx->key) > 5) {
    // Suspicious privilege escalation detected
    return -EPERM; // Deny
}
```

### 2. Process Authentication

Verifying that processes are launched through legitimate paths:

```c
// Check if a process trying to access sensitive resources
// has a legitimate ancestry (e.g., launched via proper authentication)
if (!has_legitimate_ancestry(task)) {
    return -EACCES; // Deny
}
```

### 3. Container Escape Prevention

Preventing container escape attempts:

```c
if (is_containerized(task) && attempts_host_access(task)) {
    // Potential container escape attempt
    return -EPERM; // Deny
}
```

## Example: Signal Kill Protection

The framework uses UID ancestry to protect critical processes from being killed:

```c
static int signalKillTracer(struct hooks_context_t *hook_ctx) {
    __u32 key = 0;
    struct SelfPID *value = bpf_map_lookup_elem(&self_pids, &key);
    if (!value) return 0;
    
    struct task_struct *target_task = hook_ctx->args.task_kill.task; 
    struct task_struct *task_killer = bpf_get_current_task_btf();
    
    __u32 target_pid = BPF_CORE_READ(target_task, pid);
    
    // Check if the target is a protected process
    if (value->pid != target_pid) return 0;
    
    // Check if the killer is running in a container with root
    if (is_containerized_root(task_killer)) {
        return 1; // Deny
    }

    // Check the ancestry of the process trying to kill
    return lineageUIDAnalizer(task_killer, &hook_ctx->key) > 5 ? 1 : 0;
}
```

## UID Ancestry Database

The framework maintains a database of known-good and known-bad UID transition patterns:

1. **Known-Good Patterns**: Legitimate privilege transitions (e.g., user → sudo → root)
2. **Known-Bad Patterns**: Suspicious transitions that may indicate attacks

## Performance Optimization

To maintain performance:

1. Ancestry depth is limited (typically to 10 levels)
2. Results are cached to avoid repeated analysis
3. Early-exit patterns are used when clear decisions can be made

## Security Benefits

The UID Ancestor concept provides:

1. **Context-Aware Security**: Decisions based on process history, not just current state
2. **Attack Path Detection**: Identification of unusual process creation patterns
3. **Privilege Escalation Protection**: Prevention of unauthorized privilege gains
4. **Lateral Movement Detection**: Identification of attempts to move between security contexts