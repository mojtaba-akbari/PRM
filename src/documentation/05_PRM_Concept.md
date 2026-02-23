# PRM Concept

## Overview

PRM (Policy Rule Management) is a core concept in the PRM Framework that provides a structured approach to defining, organizing, and enforcing security policies. It serves as the bridge between high-level security requirements and low-level PROGs.

## Key Components

### 1. Policy Definition

PRM provides a declarative way to define security policies:

```c
// Writing outside of these folders is invalid
__SCONFIG__(12, ValidateDirectory, 3,
            ENTRY(home),
            ENTRY(tmp),
            ENTRY(mnt)
)

// Valid user who is doing something
__N32CONFIG__(1, SafeUID, 1,
            1001
)

// Connection to any of these ip/mask/port would be invalid
__LCONFIG__(1, IPDestRules, 3,
            ENTRY(192.168.1.1/32:80-1000),
            ENTRY(10.10.0.0/16:20000-25500),
            ENTRY(192.168.1.250/27:0-65535)
)
```

### 2. Rule Organization

PRM organizes rules into logical categories:

- File system access rules
- Network access rules
- Process execution rules
- Memory protection rules
- Inter-process communication rules

### 3. Rule Enforcement

PRM connects rules to eBPF programs that enforce them:

```c
static int denyMakeSocketToEndHost(struct hooks_context_t *hook_ctx) {
    struct sockaddr *address = hook_ctx->args.socket_connect.address;
    if (!address) return 0;

    // Extract connection details
    // ...

    // Check against rules
    int len = sizeof(IPDestRules._holder_) / sizeof(IPDestRules._holder_[0]);
    for (int i = 0; i < len; i++) {
        if (ip_in_subnet(dest_ip, dest_port, IPDestRules._holder_[i])) {
            return 1; // Deny
        }   
    }
    
    return 0; // Allow
}
```

## PRM Configuration Types

The framework supports several configuration types:

### 1. String Configurations

Used for path and name-based rules:

```c
__SCONFIG__(12, ValidateDirectory, 3,
            ENTRY(home),
            ENTRY(tmp),
            ENTRY(mnt)
)
```

### 2. Numeric Configurations

Used for numeric values like UIDs, PIDs, and ports:

```c
__N32CONFIG__(1, SafeUID, 1,
            1001
)
```

### 3. Complex Configurations

Used for rules with multiple components:

```c
__LCONFIG__(1, IPDestRules, 3,
            ENTRY(192.168.1.1/32:80-1000),
            ENTRY(10.10.0.0/16:20000-25500),
            ENTRY(192.168.1.250/27:0-65535)
)
```

## PRM Configuration Macros

The framework provides several macros for defining configurations:

- `__SCONFIG__`: Short string configuration (16 chars)
- `__LCONFIG__`: Long string configuration (32 chars)
- `__HCONFIG__`: Huge string configuration (64 chars)
- `__N32CONFIG__`: 32-bit numeric configuration
- `__N64CONFIG__`: 64-bit numeric configuration

## PRM Access in Code

Configurations are accessed in code using array notation:

```c
// Get number of elements
int len = sizeof(ValidateDirectory._holder_) / sizeof(ValidateDirectory._holder_[0]);

// Access individual elements
for (int i = 0; i < len; i++) {
    if (strcmp_nolen(&path[0], ValidateDirectory._holder_[i]) == 0) {
        // Match found
    }
}
```

## PRM Optimization

The PRM system includes optimization features:

1. **Magic Index**: The first parameter in configuration can store metadata:
   ```c
   __SCONFIG__(12, ValidateDirectory, 3, ...)
   ```
   Here, `12` can represent the maximum string length or other metadata.

2. **Fast Lookups**: Configurations are organized for efficient access.

3. **Minimal Memory Usage**: Configurations use the minimum necessary memory.

## Dynamic Configuration

While eBPF programs are loaded at runtime, PRM configurations can be updated:

1. Define new configuration values
2. Recompile and reload the eBPF programs
3. The framework will use the updated configurations

## Best Practices

1. Group related rules in the same configuration
2. Use meaningful configuration names
3. Document the purpose of each configuration
4. Use the smallest configuration type that fits the data
5. Leverage the magic index for optimization hints