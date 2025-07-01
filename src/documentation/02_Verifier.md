# Verifier

## Overview

The Verifier in the PRM Framework is a sophisticated process ancestry checker that examines the lineage of processes to make security decisions. Unlike the eBPF verifier (which is a kernel component), this Verifier is a custom component that analyzes the relationship between a process, its parent, and its grandparent to enforce security policies.

## Key Functions

### Process Ancestry Analysis

The Verifier performs several important checks:

1. **Process Identification**: Identifies the current process, its parent, and grandparent
2. **Command Name Matching**: Compares process command names against security rules
3. **Relationship Validation**: Verifies that process relationships match allowed patterns
4. **Action Determination**: Decides whether to allow, reject, or redirect based on matches
5. **Cache Management**: Updates the LRU cache with decisions for future reference

### Verification Process

When a system call is intercepted, the following verification process occurs:

1. The current process, parent, and grandparent information is collected
2. This process lineage is compared against defined security rules
3. If a match is found, the corresponding action is taken (accept, reject, redirect)
4. The decision is cached for future reference
5. The system call is either allowed to proceed or blocked

## Core Implementation

The heart of the Verifier is the `PRMVerifier` function:

```c
static int PRMVerifier(struct hooks_context_t *hook_ctx) {
    struct task_struct *task = (struct task_struct *) bpf_get_current_task_btf();
    struct task_struct *parent;
    struct task_struct *grandparent;
    
    char comm[TASK_COMM_LEN], p_comm[TASK_COMM_LEN], grand_p_comm[TASK_COMM_LEN]={0};

    // Get current process name
    bpf_get_current_comm(comm, TASK_COMM_LEN);
    
    // Get parent process name
    parent = task->real_parent;
    if (parent) {
        bpf_probe_read_kernel_str(p_comm, TASK_COMM_LEN, parent->comm);
    }

    // Get grandparent process name
    grandparent = parent->real_parent;
    if (grandparent) {
        bpf_probe_read_kernel_str(grand_p_comm, TASK_COMM_LEN, grandparent->comm);
    }

    // Compare against security rules
    // ...
}
```

## Rule Matching

The Verifier matches process lineage against defined rules:

```c
// Check if process lineage matches rule
__u32 mixedUP = 1;
if (strcmp(prm->process, PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0) 
    mixedUP &= (strcmp(comm, prm->process, MAX_RELATION_PROCESSNAME) == 0);

if (mixedUP && (strcmp(prm->parent, PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0)) 
    mixedUP &= (strcmp(p_comm, prm->parent, MAX_RELATION_PROCESSNAME) == 0);

if (mixedUP && (strcmp(prm->grandparent, PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0)) 
    mixedUP &= (strcmp(grand_p_comm, prm->grandparent, MAX_RELATION_PROCESSNAME) == 0);
```

## Action Types

The Verifier supports several action types:

1. **ACCEPT**: Allow the system call to proceed
2. **REJECT**: Block the system call
3. **DEBUG**: Allow but log for debugging purposes
4. **REDIRECT**: Redirect to another rule for further processing
5. **RETURN**: Execute a specific program handler

## Caching Mechanism

The Verifier uses an LRU cache to optimize repeated decisions:

```c
static void addLRUCache(struct UniqueKey *key, int *relationKey) {
    __u32 index = (relationKey != NULL) ? *relationKey : NEGETIVE_UPDATE;
    bpf_map_update_elem(&process_list, key, &index, BPF_ANY);
}

static int checkLRUCache(struct UniqueKey *key) {
    __u32 *index = bpf_map_lookup_elem(&process_list, key);
    if (index) {
        // Check cache entry
        // ...
        return 0; // Cache hit
    }
    return 1; // Cache miss
}
```

## Example Rule Definition

A rule might define that a specific process can only be launched by certain parent processes:

```
Process: bash
Parent: sshd
Grandparent: *
Action: ACCEPT
```

This rule would allow bash processes that are children of sshd to execute system calls, regardless of sshd's parent.

## Security Benefits

The process ancestry verification provides:

1. **Context-Aware Security**: Decisions based on process lineage, not just individual processes
2. **Attack Path Detection**: Identification of unusual process creation patterns
3. **Privilege Escalation Protection**: Prevention of unauthorized privilege gains
4. **Supply Chain Protection**: Ensuring processes are launched through legitimate paths