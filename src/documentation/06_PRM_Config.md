# PRM Config

## Overview

The PRM (Policy Rule Management) Config is a key component in the PRM Framework that defines and organizes security policies. It provides an efficient way to configure rules that are evaluated during system call processing.

## Configuration Structure

The PRM Config is organized as a collection of configuration entries, each representing a different type of security policy:

```
PRM Config
├── ValidateDirectory[]
├── SafeUID[]
├── IPDestRules[]
├── BPRMDestination[]
├── MMAPFileAttached[]
└── BPRMValidInterpreter[]
```

Each configuration contains entries of a specific type (string, numeric, or complex) and is accessed by PROGs to make security decisions.

## Configuration Definition

The PRM Config is defined using configuration macros:

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

## Configuration Access

The PRM Config is accessed in PROGs using array notation:

```c
// Get number of elements in a configuration
int len = sizeof(ValidateDirectory._holder_) / sizeof(ValidateDirectory._holder_[0]);

// Access individual elements
for (int i = 0; i < len; i++) {
    if (strcmp_nolen(&path[0], ValidateDirectory._holder_[i]) == 0) {
        // Match found
    }
}
```

## Configuration Types

The PRM Config supports several types of entries:

### 1. String Configurations

Used for path and name-based rules:

- `__SCONFIG__`: Short string configuration (16 chars per entry)
- `__LCONFIG__`: Long string configuration (32 chars per entry)
- `__XLCONFIG__`: Extra large string configuration (64+ chars per entry)

### 2. Numeric Configurations

Used for numeric values like UIDs, PIDs, and ports:

- `__N32CONFIG__`: 32-bit numeric configuration
- `__N32N32CONFIG__`: 2D array of 32-bit numeric values

### 3. Complex Configurations

Used for rules with multiple components, typically implemented as structured string entries that are parsed at runtime.

## Configuration Optimization

The PRM Config includes several optimization features:

1. **Magic Index**: The first parameter in configuration definition can store metadata:
   ```c
   __SCONFIG__(12, ValidateDirectory, 3, ...)
   ```
   Here, `12` can represent the maximum string length or other metadata.

2. **Fixed-Size Entries**: Each configuration uses fixed-size entries for efficient access.

3. **Compile-Time Initialization**: Configurations are initialized at compile time to avoid runtime overhead.

## Memory Layout

The memory layout of a PRM Config is optimized for kernel access:

```
ValidateDirectory Config:
+----------------+----------------+----------------+
| "home" (16B)   | "tmp" (16B)    | "mnt" (16B)    |
+----------------+----------------+----------------+

SafeUID Config:
+----------------+
| 1001 (4B)      |
+----------------+
```

## Configuration Helpers

The framework provides helper macros for checking against configurations:

```c
// Check if a string matches any entry in a configuration
checkValidElemConfigSTR(&path[0], ValidateDirectory, 0)

// Check if a number matches any entry in a configuration
checkValidElemConfigNUMBER(uid, SafeUID, 1)

// Check with forced string comparison
checkValidElemConfigForceSTRLen(&filename[0], BPRMDestination, 1)
```

## Configuration Limitations

Due to kernel restrictions, PRM Configs:

1. Have a fixed size determined at compile time
2. Cannot be dynamically resized at runtime
3. Have a maximum number of entries
4. Have fixed-size entries (strings are truncated if too long)

## Best Practices

1. Group related rules in the same configuration
2. Use the smallest entry size that fits the data
3. Leverage the magic index for optimization hints
4. Keep configurations small to minimize memory usage and lookup time
5. Use meaningful configuration names that reflect their purpose