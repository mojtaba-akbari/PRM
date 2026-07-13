# PRM Table Rules

## Overview

PRM Table Rules define the security policies that the Verifier uses to determine whether a system call from a process is legitimate and should be allowed. These rules form the core decision-making logic of the framework by analyzing the process ancestry (process → parent → grandparent) and making security decisions based on this lineage.

## Rule Structure

Each rule in the PRM Table follows a consistent structure:

```
PREFIX, PREFIX, PREFIX, ACTION, REDIRECT-INDEX, PROTECTED-ZONE, HOOKS
```

Where:
- **PREFIX**: Process name pattern (3 entries for process, parent, and grandparent)
- **ACTION**: What to do when the rule matches (ACCEPT, REJECT, REDIRECT, RETURN, DEBUG)
- **REDIRECT-INDEX**: Index to another rule (0-99) for REDIRECT and RETURN actions
- **PROTECTED-ZONE**: Flag (0-1) indicating if this is a protected zone rule
- **HOOKS**: System call hook number (0-30) or 0 for all hooks

## Process Ancestry Patterns

The framework supports various process ancestry patterns:

| Pattern | Description | Use Case |
|---------|-------------|----------|
| `{PREFIX_NOCARE, PREFIX_NOCARE, PREFIX_NOCARE}` | Match any process lineage | Global deny rules |
| `{X, PREFIX_NOCARE, PREFIX_NOCARE}` | Focus on specific process | Process-specific rules |
| `{X, X, PREFIX_NOCARE}` | Focus on process and parent | Shell service rules (bash, zsh) |
| `{X, PREFIX_NOCARE, X}` | Focus on process and grandparent | Container isolation rules |
| `{PREFIX_NOCARE, X, PREFIX_NOCARE}` | Focus on parent process | Exploit prevention rules |
| `{PREFIX_NOCARE, X, X}` | Focus on parent and grandparent | Root isolation rules |
| `{PREFIX_NOCARE, PREFIX_NOCARE, X}` | Focus on grandparent | Isolation focus rules |
| `{X, X, X}` | Exact process lineage match | Specific known patterns |

Where `X` is a specific process name and `PREFIX_NOCARE` means any process (wildcard).

## Actions

The framework supports several actions when a rule matches:

| Action | Description |
|--------|-------------|
| `ACCEPT` | Allow the system call to proceed |
| `REJECT` | Block the system call |
| `REDIRECT` | Jump to another rule for further evaluation |
| `RETURN` | Execute a specific PROG handler |
| `DEBUG` | Allow but log for debugging purposes |

## Protected Zones

Protected zones are specialized rule sections for specific process types:

- **Protected Zone (1)**: Rules that are only evaluated when explicitly redirected to
- **Unprotected Zone (0)**: Rules that are evaluated in the normal flow

Protected zones allow for more detailed and specific rules for certain processes. For example:
- Docker protected zone (rules 50-59)
- Bash protected zone (rules 70-79)
- SSH protected zone (rules 80-89)

## Hook Types

The framework supports numerous system call hooks (30+), including:

- File operations (FILE_PERMISSION, FILE_OPEN, etc.)
- Memory operations (FILE_MPROTECT, SHM_ALLOC, etc.)
- Process operations (TASK_KILL, TASK_PTRACE, etc.)
- Network operations (SOCKET_CREATE, SOCKET_CONNECT, etc.)
- Security operations (SECURITY_CAPGET, CRED_PREPARE, etc.)

## Debug Levels

The framework supports various debug levels for logging:

- `NOTHING`: No debugging
- `LOWER`: Minimal debugging
- `NORMAL`: Standard debugging
- `EXTERA`: Extra debugging information
- `HIGH`: High verbosity debugging
- `VERBOSE`: Maximum debugging information

## Example Rules

### Process Protection Rule

```c
// Protect the framework from being killed
#define RELATION_0 PREFIX_NOCARE, PREFIX_NOCARE, PREFIX_NOCARE, RETURN, 2, 0, 19
```

This rule:
- Matches any process ancestry
- For TASK_KILL hooks (19)
- Returns to PROG handler 2
- Is in the unprotected zone (0)

### Container Security Rule

```c
// If found any containerd-docker, redirect to Docker Zone
#define RELATION_11 PREFIX_NOCARE, "containerd-shim", PREFIX_NOCARE, REDIRECT, 50, 0, 0
```

This rule:
- Matches any process with "containerd-shim" as parent
- Redirects to rule 50 (Docker protected zone)
- Applies to all hooks (0)
- Is in the unprotected zone (0)

### Protected Zone Rule

```c
// Docker Protect Zone
#define RELATION_50 "runc", "containerd-shim", PREFIX_NOCARE, ACCEPT, 0, 1, 0
```

This rule:
- Matches "runc" processes with "containerd-shim" as parent
- Accepts all system calls
- Is in a protected zone (1)
- Applies to all hooks (0)

## Rule Ordering

Rule ordering is critical for performance and security:

1. Rules are evaluated in order (0-99)
2. The first matching rule determines the action
3. Protected zones are only evaluated when explicitly redirected to
4. REDIRECT actions must point to higher-numbered rules to prevent loops

## Best Practices

1. **Start with Observation**: Never add rules without sufficient tracing and understanding
2. **Order Matters**: Place more common rules earlier for better performance
3. **Use Protected Zones**: Group related rules in protected zones for better organization
4. **Be Specific**: Use the most specific process ancestry pattern that meets your needs
5. **Debug First**: Use DEBUG action to observe behavior before implementing ACCEPT/REJECT
6. **Avoid Empty Rules**: Use EMPTY for placeholder rules that might be needed later

## Implementation

The PRM Table Rules are defined in the PRM.h file and are loaded into the framework at initialization. The Verifier component uses these rules to make security decisions based on process ancestry and system call hooks.