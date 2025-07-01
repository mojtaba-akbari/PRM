# Cache Mechanism

## Overview

The Cache Mechanism in the PRM Framework is a critical performance optimization that stores security decisions to avoid redundant processing of identical system calls. It operates at the earliest stage of the security pipeline, allowing the framework to bypass expensive verification steps for previously evaluated system calls.

## UniqueKey Structure

The cache is built around the `UniqueKey` structure, which uniquely identifies a system call context:

```c
struct UniqueKey {
    __u32 pid;                 // Process ID
    __u32 tpid;                // Thread ID
    enum PRM_HOOK_ENUM hook;   // System call hook type
};
```

This key captures the essential context needed to identify identical system calls:
- The process making the call (`pid`)
- The specific thread within the process (`tpid`)
- The type of system call being made (`hook`)

## Cache Implementation

The cache is implemented as an LRU (Least Recently Used) hash map:

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, ALLOWED_PIDS);  
    __type(key, struct UniqueKey);
    __type(value, __u32); 
} process_list SEC(".maps");
```

This map stores:
- Keys: `UniqueKey` structures identifying specific system calls
- Values: Relation indices or `NEGETIVE_UPDATE` for allowed but uncategorized calls

## Core Cache Functions

### Adding to Cache

The `addLRUCache` function adds a decision to the cache:

```c
static void addLRUCache(struct UniqueKey *key, int *relationKey) {
    // Take care of memory which we can allocate for stack
    __u32 index = (relationKey != NULL) ? *relationKey : NEGETIVE_UPDATE;
    bpf_map_update_elem(&process_list, key, &index, BPF_ANY);
}
```

This function:
- Takes a `UniqueKey` and an optional relation index
- If a relation index is provided, it's stored in the cache
- If no relation index is provided, `NEGETIVE_UPDATE` is stored, indicating a default allow

### Checking the Cache

The `checkLRUCache` function checks if a decision is already cached:

```c
static int checkLRUCache(struct UniqueKey *key) {
    __u32 *index = bpf_map_lookup_elem(&process_list, key);
    if (index) {
        if (index != NEGETIVE_UPDATE) {
            struct process_relation *processTmpx = bpf_map_lookup_elem(&prm_map, index);
            if (processTmpx) {
                if (processTmpx->hookType == NONE_CELL || processTmpx->hookType == key->hook) {
                    return 0; // Cache hit - allow
                }
                else return 1; // Hook type mismatch - continue verification
            }
        }
        
        return 0; // Default allow for NEGETIVE_UPDATE
    }

    return 1; // Cache miss - continue verification
}
```

This function:
- Looks up the `UniqueKey` in the cache
- If found and not `NEGETIVE_UPDATE`, verifies the hook type matches
- Returns 0 (allow) for valid cache hits
- Returns 1 (continue verification) for cache misses or hook type mismatches

## Cache Flow in the Security Pipeline

The cache is positioned at the very beginning of the security pipeline:

```c
static int entryStartPoint(struct hooks_context_t *hook_ctx) {
    // First check if this is our own process
    __u32 key = 0;
    struct SelfPID *value = bpf_map_lookup_elem(&self_pids, &key);
    if (value && value->pid == hook_ctx->key.pid && value->magic == MAGIC_VALUE) {
        return 0; // Allow our own process
    } 

    // Then check the cache
    if (!checkLRUCache(&hook_ctx->key)) {
        return 0; // Cache hit - allow
    }

    // If not in cache, perform full verification
    if (detectSyscallRelations(hook_ctx)) {
        return -EPERM; // Deny
    }

    return 0; // Allow
}
```

This positioning allows the framework to:
1. First check if the call is from the framework itself
2. Then check if the decision is already cached
3. Only if not cached, proceed with the full verification process

## Security Implications

The cache mechanism has important security implications:

### 1. Hook-Specific Caching

The cache verifies that the cached decision applies to the current hook type:

```c
if (processTmpx->hookType == NONE_CELL || processTmpx->hookType == key->hook) {
    return 0; // Allow only if hook types match or rule applies to all hooks
}
else return 1; // Continue verification if hook types don't match
```

This prevents security bypasses where a process is allowed for one hook type but tries to perform a different operation.

### 2. Potential Bypass Risks

For certain hook types, caching decisions can be risky. For example:

- **Network Connections**: If a process is allowed to connect to one IP address, caching this decision could allow it to connect to any IP address without further verification.
- **File Operations**: If a process is allowed to open one file, caching might allow it to open any file.

These risks must be carefully managed by:
1. Using hook-specific rules in the PRM table
2. Ensuring critical operations always specify a hook type rather than using `NONE_CELL`
3. Implementing additional checks in PROGs for sensitive operations

### 3. Default Allow for Unknown Patterns

The framework adds unknown patterns to the cache with `NEGETIVE_UPDATE`:

```c
FULLY_DEBUG(__DEBUG__, (VERBOSE | HIGH | EXTERA | NORMAL | LOWER), 
    bpf_printk("Unknown Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Not Matched any relations (Take it as White Process - Or Add Role) \n", 
    hook_ctx->key.hook, hook_ctx->key.pid, comm, p_comm, grand_p_comm));

addLRUCache(&hook_ctx->key, NULL);
```

This implements a default-allow policy for unknown patterns, which improves performance but could potentially allow malicious activities if not properly managed.

## Performance Benefits

The cache mechanism provides significant performance benefits:

1. **Reduced Verification Overhead**: Bypasses expensive process ancestry checks for cached decisions
2. **Optimized Common Paths**: Frequently used system calls are served directly from cache
3. **Minimal Latency**: Cache lookups are much faster than full verification
4. **Scalability**: LRU eviction ensures the cache remains effective even with many processes

## Best Practices

To effectively use the cache mechanism:

1. **Hook-Specific Rules**: Define rules with specific hook types for sensitive operations
2. **Careful Caching**: Consider which operations should be cached and which should always be verified
3. **Monitor Cache Size**: Adjust `ALLOWED_PIDS` based on system workload
4. **Default Deny for Critical Operations**: Use explicit deny rules for sensitive operations rather than relying on default behavior
5. **Regular Rule Updates**: Update rules as new patterns emerge to ensure the cache contains accurate decisions