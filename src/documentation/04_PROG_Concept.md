# PROG Concept

## Overview

The PROG (Program) concept is a fundamental building block of the PRM Framework. PROGs are specialized programs that implement specific security policies and are attached to system call hooks to enforce these policies.

## PROG Architecture

Each PROG consists of:

1. **Entry Point**: The main function that receives the system call context
2. **Context Access**: Methods to safely access system call parameters
3. **Decision Logic**: Code that implements the security policy
4. **Return Value**: A decision code (allow/deny) that determines the fate of the system call

## PROG Types

The framework supports several types of PROGs:

### 1. System Call PROGs

These are attached directly to system calls and make decisions based on call parameters:

```c
static int syscall_open_prog(struct hooks_context_t *hook_ctx) {
    // Extract parameters
    const char *filename = hook_ctx->args.file_open.filename;
    int flags = hook_ctx->args.file_open.flags;
    
    // Apply security policy
    if ((flags & O_WRONLY) || (flags & O_RDWR)) {
        // Check if write access is allowed to this file
        if (!is_write_allowed(filename)) {
            return -EACCES; // Deny
        }
    }
    
    return 0; // Allow
}
```

### 2. Helper PROGs

These implement common functionality used by multiple system call PROGs:

```c
static int check_file_access(const char *path, int access_type) {
    // Implementation of file access checking logic
    // ...
    return result;
}
```

### 3. Management PROGs

These handle framework management tasks like cache invalidation:

```c
static int invalidate_cache_prog(void *ctx) {
    // Clear the decision cache
    // ...
    return 0;
}
```

## PROG Lifecycle

1. **Development**: PROGs are written in C with kernel extensions
2. **Compilation**: PROGs are compiled to bytecode
3. **Verification**: The verifier checks PROGs for safety
4. **Loading**: Verified PROGs are loaded into the kernel
5. **Attachment**: PROGs are attached to system call hooks
6. **Execution**: PROGs run when their associated system calls are invoked
7. **Unloading**: PROGs are detached and unloaded when no longer needed

## Example PROG: Memory Protection

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

## PROG Optimization Techniques

1. **Minimal Processing**: PROGs should do the minimum work necessary
2. **Early Returns**: Exit as soon as a decision can be made
3. **Register Usage**: Minimize stack usage by leveraging registers
4. **Helper Functions**: Use helper functions for complex operations
5. **Bounded Loops**: Ensure all loops have explicit bounds

## PROG Limitations

Due to kernel restrictions, PROGs:

1. Cannot use arbitrary loops (must be bounded)
2. Have limited stack space (512 bytes)
3. Cannot call arbitrary kernel functions
4. Must pass verifier safety checks
5. Cannot use certain language features (recursion, function pointers, etc.)

## Best Practices for PROG Development

1. Keep PROGs simple and focused
2. Use BPF_CORE_READ for structure field access
3. Validate all inputs
4. Handle error cases gracefully
5. Add debug prints during development
6. Test incrementally with increasing complexity