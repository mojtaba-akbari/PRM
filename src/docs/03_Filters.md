# Filters

## Overview

Filters in the PRM Framework are lightweight pre-processing components that run before the Verifier to modify input or make fast decisions without requiring full verification. They serve as an optimization layer that can quickly handle common cases or prepare the context for more detailed analysis.

## Filter Purpose

Filters serve several key purposes:

1. **Fast Path Processing**: Handle common cases quickly without invoking the full verification process
2. **Input Modification**: Transform or normalize system call parameters before verification
3. **Early Rejection**: Quickly reject obviously invalid system calls
4. **Context Enrichment**: Add additional context information for the Verifier

## Filter Implementation

Filters are implemented as simple functions that:

1. Receive the system call context
2. Optionally modify the input
3. Return a decision flag that affects further processing

The basic structure of a filter is:

```c
static __u32 filter1(struct hooks_context_t *hook, __u32 input)
{
    // Process or modify input
    return input; // Return modified decision flag
}
```

## Filter Injection

Filters are injected into the processing pipeline using the `__INJECT_FILTERS__` macro:

```c
static int detectSyscallRelations(struct hooks_context_t *hook_ctx) {
    __u32 output = 0;
    __u32 input = 1;

    __INJECT_FILTERS__(hook_ctx, input, output)

    return (PRMVerifier(hook_ctx) & output);
}
```

This macro applies all registered filters to the system call context, potentially modifying the input and output flags.

## Filter Types

The framework can support various types of filters:

### 1. Fast-Path Filters

These filters quickly identify common cases that can bypass full verification:

```c
static __u32 whitelistFilter(struct hooks_context_t *hook, __u32 input)
{
    // Check if this is a whitelisted process
    if (is_whitelisted_process(hook->key.pid)) {
        return 0; // Skip verification
    }
    return input; // Continue with verification
}
```

### 2. Input Normalization Filters

These filters normalize or sanitize input before verification:

```c
static __u32 pathNormalizeFilter(struct hooks_context_t *hook, __u32 input)
{
    // Normalize path parameters
    // ...
    return input;
}
```

### 3. Context Enrichment Filters

These filters add additional context information:

```c
static __u32 containerContextFilter(struct hooks_context_t *hook, __u32 input)
{
    // Add container context information
    // ...
    return input;
}
```

## Performance Benefits

Filters provide significant performance benefits:

1. **Reduced Verification Overhead**: Fast-path filters can bypass expensive verification
2. **Optimized Processing**: Input normalization can simplify verification logic
3. **Early Exit**: Obviously invalid calls can be rejected immediately
4. **Specialized Handling**: Common cases can be handled with optimized code paths

## Example: Self-PID Filter

A filter that bypasses verification for the framework's own processes:

```c
static __u32 selfPIDFilter(struct hooks_context_t *hook, __u32 input)
{
    __u32 key = 0;
    struct SelfPID *value = bpf_map_lookup_elem(&self_pids, &key);

    if (value && value->pid == hook->key.pid && value->magic == MAGIC_VALUE) {
        // This is our own process, bypass verification
        return 0;
    }
    
    return input;
}
```

## Filter Chain

Multiple filters can be chained together:

1. Each filter receives the output of the previous filter
2. Filters are applied in a predefined order
3. Any filter can short-circuit the chain by returning 0
4. The final output determines whether verification proceeds

## Extending the Filter System

New filters can be added by:

1. Implementing a new filter function
2. Registering it in the filter injection macro
3. Ensuring proper ordering in the filter chain