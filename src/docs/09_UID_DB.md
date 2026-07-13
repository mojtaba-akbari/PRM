# UID Database

## Overview

The UID Database is a sophisticated component of the PRM Framework that analyzes user identity transitions and patterns to detect privilege escalation attempts and other security threats. It uses vector-based pattern matching to identify suspicious UID transitions in process ancestry chains.

## Core Concepts

### UID Vectors

The framework uses UID vectors to represent patterns of user identity transitions across process ancestry chains:

```c
struct UIDVector {
    __u8 severity;
    __u8 val[MAX_VECTOR_CELL];
};
```

Each vector contains:
- A severity level indicating the security risk
- An array of UID pattern elements (typically 4 elements representing a process ancestry chain)

### UID Pattern Elements

The framework defines several types of UID pattern elements:

| Element | Value | Description |
|---------|-------|-------------|
| `UIDROOT` | 0 | Root user (UID 0) |
| `UIDEMPTYCELL` | 1 | Empty or undefined cell |
| `UIDWILDCARD` | 2 | Any non-root user |
| `UIDMISMATCH` | 3 | UID transition/mismatch between processes |

### Severity Levels

The framework defines a comprehensive scale of severity levels for UID patterns:

| Level | Value | Description |
|-------|-------|-------------|
| `EASY` | 0 | Not checked or not applicable |
| `BASE` | 1 | Normal base behavior |
| `BENIGN` | 2 | Expected, non-privileged action |
| `LOW_RISK` | 3 | Mildly uncommon, likely okay |
| `SUSPICIOUS` | 4 | Unusual pattern, worth watching |
| `ANOMALOUS` | 5 | Unexpected, but unclear intent |
| `ELEVATED` | 6 | Privilege escalation likely |
| `ESCALATED` | 7 | Confirmed setuid/sudo jump |
| `DANGEROUS` | 8 | Likely malicious behavior |
| `CRITICAL` | 9 | High-confidence exploit |
| `ROOT_COMPROMISED` | 10 | Confirmed root takeover path |

## Pre-trained UID Vectors

The framework includes a set of pre-trained UID vectors that represent known patterns:

### Normal Patterns

```c
// Normal root actions like daemon
{.severity=EASY, .val={0, 0, 0, 0}}

// Normal user actions
{.severity=LOW_RISK, .val={2, 2, 2, 2}}

// Syscalls from normal user (last might be daemon)
{.severity=LOW_RISK, .val={2, 2, 2, 0}}
```

### Suspicious Patterns

```c
// Root using another user (could be legitimate or suspicious)
{.severity=BASE, .val={0, 2, 0, 0}}

// Consecutive actions as root after UID change
{.severity=ESCALATED, .val={0, 0, 0, 2}}
{.severity=ESCALATED, .val={0, 0, 2, 2}}
{.severity=ESCALATED, .val={0, 2, 2, 2}}
{.severity=ESCALATED, .val={0, 2, 0, 2}}
```

### Malicious Patterns

```c
// UID mismatch + root (critical security risk)
{.severity=CRITICAL, .val={0, 2, 2, 3}}
{.severity=CRITICAL, .val={0, 2, 3, 2}}
{.severity=CRITICAL, .val={0, 3, 2, 2}}
{.severity=CRITICAL, .val={0, 0, 3, 2}}
{.severity=CRITICAL, .val={0, 0, 3, 3}}
{.severity=CRITICAL, .val={0, 3, 3, 2}}
{.severity=CRITICAL, .val={0, 3, 3, 3}}
```

### Anomalous Patterns

```c
// Mismatch at the end (post-spawn)
{.severity=ANOMALOUS, .val={2, 2, 2, 3}}

// Mismatch + non-root
{.severity=ANOMALOUS, .val={2, 2, 3, 2}}

// Normal user → double root
{.severity=ANOMALOUS, .val={2, 3, 2, 2}}

// Alternating mismatch & root
{.severity=ANOMALOUS, .val={3, 2, 2, 2}}
```

## Implementation

The UID Database is implemented using two key data structures:

### Base Vector Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_VECTORS);
    __type(key, __u32);
    __type(value, struct UIDVector);
} uid_base_map SEC(".maps");
```

This map stores the pre-trained UID vectors that represent known patterns.

### Lineage Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, ALLOWED_PIDS_UID_MAP);
    __type(key, struct UniqueKey);
    __type(value, struct UIDVectorAncestors);
} uid_lineage_map SEC(".maps");
```

This map caches the UID ancestry information for processes to avoid repeated analysis.

## Attack Detection Examples

### Privilege Escalation Detection

The framework can detect various privilege escalation techniques:

1. **Direct Root Compromise**: When a non-root process suddenly gains root privileges
   ```
   Pattern: {2, 2, 2, 0} → Severity: CRITICAL
   ```

2. **UID Mismatch Chains**: When there are multiple UID mismatches in the ancestry chain
   ```
   Pattern: {0, 3, 3, 3} → Severity: CRITICAL
   ```

3. **Setuid Exploitation**: When a process changes its UID through setuid exploitation
   ```
   Pattern: {0, 0, 3, 2} → Severity: CRITICAL
   ```

### Container Escape Detection

The framework can detect container escape attempts:

```
Pattern: {0, 2, 0, 2} → Severity: ESCALATED
```

This pattern indicates a process that started as root, switched to a non-root user, then back to root, which could indicate a container escape.

## Security Benefits

The UID Database provides several key security benefits:

1. **Pattern-Based Detection**: Identifies known malicious UID transition patterns
2. **Severity Classification**: Assigns risk levels to different patterns
3. **Context-Aware Security**: Makes decisions based on the full process ancestry chain
4. **Pre-trained Vectors**: Comes with built-in knowledge of common attack patterns
5. **Efficient Caching**: Uses LRU caching to optimize repeated lookups

## Usage in the Framework

The UID Database is used by the framework to:

1. Analyze process ancestry chains during system call interception
2. Compare observed UID patterns against known patterns
3. Assign severity levels to detected patterns
4. Make security decisions based on the severity level
5. Cache results for future reference

This sophisticated pattern matching approach allows the framework to detect complex privilege escalation attempts and other security threats that might be missed by simpler security mechanisms.