# PRM -- Process Rule Management Framework

PRM is a Linux kernel security framework that makes access-control decisions
based on process ancestry.  It hooks into the kernel via eBPF/LSM, inspects
the calling process together with its parent and grandparent, and evaluates a
300-entry rule table to ACCEPT, REJECT, REDIRECT, or hand off to specialised
PROG handlers.  An LRU cache (2 024 entries, Jenkins hash) turns repeated
identical syscalls into O(1) lookups.

The framework targets HPC and multi-tenant Linux environments where
traditional MAC systems (SELinux, AppArmor, seccomp) lack the runtime context
to distinguish a legitimate scientific job from an exploit that happens to
carry the same credentials.

---

## Table of contents

1. [How it works](#how-it-works)
2. [Project layout](#project-layout)
3. [Requirements](#requirements)
4. [Building](#building)
5. [Installation and loading](#installation-and-loading)
6. [Configuration](#configuration)
7. [Rule table (PRM.h)](#rule-table-prmh)
8. [PROG handlers](#prog-handlers)
9. [Trace collector](#trace-collector)
10. [Deployment helpers](#deployment-helpers)
11. [Unloading](#unloading)
12. [Known limitations](#known-limitations)
13. [License](#license)

---

## How it works

Every syscall that reaches an LSM hook passes through five layers:

```
syscall
  |
  v
[1] Cache lookup  -----> hit? return cached decision
  |
  v
[2] Fast-decision filters  -----> kernel thread bypass, self-PID skip
  |
  v
[3] Process ancestry extraction  -----> (process, parent, grandparent)
  |
  v
[4] Rule table walk (300 entries)
      |
      +-- ACCEPT   -> allow
      +-- REJECT   -> deny
      +-- REDIRECT -> jump to another rule index
      +-- RETURN   -> invoke a PROG handler (see below)
      +-- BYPASS   -> skip with no decision
      +-- DEBUG    -> log and continue
      +-- END      -> stop evaluation, accept
  |
  v
[5] Default policy  -----> accept (fail-open with logging)
```

Ancestry is extracted from `task_struct` at runtime: the current process
name, its parent, and its grandparent.  Rules can match on any combination
using exact names, wildcards (`PREFIX_NOCARE`), symmetric matching (the `|`
prefix matches the name in any of the three positions), or invalid-binary
detection (`PREFIX_INVALID_BINARY` matches processes whose executable lives
outside trusted system directories).

UID transition analysis runs a sliding-window pattern matcher over the
ancestry chain against 19 pre-trained attack vectors, producing a severity
score used by several PROG handlers to block privilege escalation.

---

## Project layout

```
src/
  ebpf/
    hookentry.c            LSM hook entry points (30+ hooks)
    core/
      PRMVerifier.c        Rule matching, ancestry extraction, cache
      PRMFilters.c         Kernel-thread bypass, self-PID detection
      PRMStructs.c         Map operations, rule loading
      PRMCacheService.c    LRU cache implementation
      PRMProgDispatcher.c  PROG dispatch switch
    progs/
      PRMProgEntry.c       All PROG handler implementations
      PRMProgHelper.c      Shared PROG utilities (IP/CIDR matching, etc.)
    include/
      baseheaders.h        Buffer sizes, constants
      BTFFunctions.h       String helpers (strcmp_forceS1, etc.)
      PRMVerifier.h        Verifier header
      PRMFilters.h         Fast-decision filters header
      PRMStructs.h         Data structures, BPF maps
      PRMProgDispatcher.h  PROG dispatch logic
      PRMProgEntry.h       PROG handler declarations
      PRMProgHelper.h      PROG utility functions header
      PRMConfigGenerator.h Config macros (__SCONFIG__, __LCONFIG__, etc.)
      PRMCacheService.h    Cache service header
    conf/
      PRM.h                Rule table (300 RELATION_* macros)
      PRMConfig.h          Security configuration (paths, IPs, modules, ...)
      PRMProg.h            PROG dispatcher config
  tools/
    prm-loader.c           User-space loader with GPG token auth
    prm-configure.c        ncurses TUI rule editor
    trace-collector.c      Reads trace_pipe, forwards to syslog
  docs/
    00_Framework_Overview.md ... 14_Chain_Scenario.md
    honeypot-report/       Real-world attack data from PRM deployment

deployment/
  Makefile                 Build eBPF object, loader, configure, collector
  ecc                      eBPF compiler (eunomia-bpf toolchain)
  ecli                     eBPF CLI runner
  prm-gentoken             GPG token generator for load/unload auth
  prm.service              systemd unit file (prm-loader)
  trace-collector.service  systemd unit file (log collector)
  dev-deploy.sh            QEMU Rocky Linux 9 dev VM
  debian_deploy.sh         QEMU Debian 12 dev VM
  deploy-inventory.sh      Deploy to remote host via SSH

test-samples/
  test_security.py         19-test security suite with CLI selection
  vuln-cgi.c               Buffer overflow demo (CGI binary)
  exploit.py               Exploit script
  nginx-vuln.conf          Nginx config for CGI endpoint
  setup-vuln-cgi.sh        Deploy vulnerable CGI

benchmarks/
  benchmark.py             1M syscall benchmark (open/close)
  run_comparison.sh        PRM vs AppArmor comparison
  ...
```

---

## Requirements

Kernel:
- Linux >= 5.15 with BPF LSM enabled (`CONFIG_BPF_LSM=y`)
- BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- The kernel boot parameter `lsm=...,bpf` must include `bpf`

Packages (RHEL/Rocky/Alma):
```
clang llvm libbpf bpftool elfutils-libelf-devel gcc make kernel-devel
```

Packages (Debian/Ubuntu):
```
clang llvm libbpf-dev bpftool libelf-dev gcc make linux-headers-$(uname -r)
```

The `ecc` compiler from the eunomia-bpf project is included in
`deployment/ecc`.  It produces the `hookentry.bpf.o` object file.

---

## Building

```
cd deployment
make          # builds ebpf object, prm-loader, prm-configure, and trace-collector
```

This runs four steps:

1. `make ebpf` -- compiles `src/ebpf/hookentry.c` into `hookentry.bpf.o`
   using `ecc`.
2. `make loader` -- compiles `src/tools/prm-loader.c` into the `prm-loader`
   binary, linking against libbpf.
3. `make configure` -- compiles `src/tools/prm-configure.c` into
   `prm-configure` (ncurses TUI editor).
4. `make collector` -- compiles `src/tools/trace-collector.c` into
   `trace-collector`.

After a successful build the deployment directory contains:

```
hookentry.bpf.o    eBPF object (all LSM programs + maps)
prm-loader         user-space loader (GPG token auth required)
prm-configure      ncurses TUI rule editor
trace-collector    syslog forwarder
package.json       eunomia metadata (used by ecli)
```

---

## Installation and loading

### Installing

```
cd deployment
sudo make install
```

This installs:
- `prm-loader` → `/usr/local/sbin/prm-loader`
- `trace-collector` → `/usr/local/bin/trace-collector`
- Enables and starts `trace-collector.service` (systemd)

### GPG token authentication

All load/unload operations require a signed GPG token.  Generate one on the
control node:

```
./prm-gentoken manage <hostname>
```

Token format: `ACTION:HOSTNAME:TIMESTAMP:NONCE` with a detached `.sig` file.
Tokens expire after 1 hour and nonces cannot be reused.

### Loading PRM

```
prm-loader load --token /path/to/token
```

If the eBPF object is not in the current directory:

```
prm-loader load --token /path/to/token --dir /opt/prm/
```

To keep the loader running as a foreground daemon (debugging):

```
prm-loader load --token /path/to/token --daemon
```

### Inspecting state

```
prm-loader status              # state, self-PID, cache usage
prm-loader show relations      # dump the 300-entry rule table
prm-loader show config         # buffer sizes and map capacities
prm-loader show cache          # whitelist/blacklist stats
prm-loader show progs          # list PROG security handlers
```

### Verifying

After loading, check that the BPF programs are attached:

```
sudo bpftool prog list | grep lsm
```

Check the trace pipe for PRM log output:

```
journalctl -t kernel -f    # if trace-collector is running
# or directly:
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

---

## Configuration

All security policy lives in two header files that are compiled into the eBPF
object.  Changing policy requires editing these files and rebuilding.

### PRMConfig.h

`src/ebpf/conf/PRMConfig.h` defines:

| Directive | Purpose |
|-----------|---------|
| SafeUID | UIDs that bypass certain checks |
| UnSafeGID | GIDs subject to stricter rules |
| BinaryHomeDirectory | Trusted system directories (usr, bin, sbin, ...) |
| ValidateDirectory | Directories where file operations are allowed |
| BlockedPaths | Paths always denied (proc/kcore, etc.) |
| SocketProtocolInvalid | Blocked socket families (AF_PACKET, AF_IB, ...) |
| IPDestRules / IPSrcRules | Network allow/deny by CIDR |
| BPRMDestination | Paths from which execve is blocked (/tmp/, /dev/shm/, ...) |
| BPRMInterpreter | Blocked interpreter binaries |
| MMAPFileAttached | Directories denied for executable mmap |
| OpenFileDeny | File names always blocked (shadow, passwd, ...) |
| OpenFileDenyAggressivly | Stricter file deny list (blocks even for system reads) |
| ModuleDeny | Kernel module prefixes blocked from loading |

Config macros:

- `__SCONFIG__` -- short string array (MAX_STR = 16 chars per entry)
- `__LCONFIG__` -- long string array (LARGE_STR = 32 chars)
- `__N32CONFIG__` -- 32-bit integer array

### PRM.h (rule table)

See the next section.

---

## Rule table (PRM.h)

`src/ebpf/conf/PRM.h` defines 300 rules as `RELATION_0` through
`RELATION_299`.  Each rule is a tuple:

```
process, parent, grandparent, ACTION, redirect_index, protect_zone, hook_type
```

The verifier walks rules top-to-bottom.  First match wins (for ACCEPT,
REJECT, END).  REDIRECT jumps to another index.  RETURN invokes a PROG
handler.

Rule regions in the default configuration:

| Rules | Purpose |
|-------|---------|
| 0 | Default bypass (catch-all) |
| 1--20 | System services: systemd, sshd, sshd-session, containerd, slurm, prm-loader, gpg, ... |
| 17--24 | Reserved for admin use |
| 25--42 | Blocked processes: ruby, node, php, gdb, strace, nmap, ... |
| 43--53 | Hook-specific redirects to protected zone (BPRM, FILE_OPEN, SOCKET, ...) |
| 61 | END -- anything reaching here is accepted |
| 62 | Protected zone entry (DEBUG) |
| 63--96 | Symmetric RETURN rules for known binaries (bash, python, sshd, ...) |
| 97 | End-of-pattern redirect (loop = accept) |
| 290--292 | TASK_KILL signal handling zone |

Symmetric rules (prefixed with `|`) match the process name in any ancestry
position.  For example `|bash` matches whether bash is the current process,
the parent, or the grandparent.

---

## PROG handlers

When a rule has action RETURN, it invokes a PROG handler -- a specialised
function for a specific LSM hook type.  Defined in
`src/ebpf/progs/PRMProgEntry.c`:

| PROG | Name | Hook | What it does |
|------|------|------|-------------|
| 0 | test | -- | Always accept (placeholder) |
| 1 | signalKillTracer | TASK_KILL | Prevents killing the PRM process |
| 2 | denyWriteOutSideOfValidDirectories | INODE_CREATE | Blocks file creation outside allowed dirs |
| 3 | denyMakeSocketToEndHost | SOCKET_CONNECT | Blocks outbound connections to non-private IPs |
| 4 | bprmSecurityCheck | BPRM_SECURITY | Blocks execve from /tmp, /dev/shm, etc. |
| 5 | memoryProtectCheck | FILE_MPROTECT | Blocks mprotect(EXEC) on anonymous/untrusted memory |
| 6 | denyIncomeSocket | SOCKET_ACCEPT | Filters incoming connections by source IP |
| 7 | denyFileOpen | FILE_OPEN | Restricts file access by directory and name |
| 8 | denyLoadModule | KERNEL_MODULE_REQUEST | Blocks loading of dangerous kernel modules |
| 9 | credPrepareCheck | CRED_PREPARE | Blocks UID/GID escalation to root |
| 10 | capableCheck | CAPABLE | Blocks dangerous capabilities for non-root |
| 11 | taskFixSetUIDCheck | TASK_FIX_SETUID | Blocks setuid exploitation |

Each PROG has two functions: the enforcement function (`_prog`) and a
fingerprint function (`_fingerprint`) that computes cache-key parameters via
`FLAG_FOR_HASH`.

---

## Trace collector

`trace-collector` reads `/sys/kernel/debug/tracing/trace_pipe` and forwards
every line to syslog.  It disguises its process name as `kworker/u8:3` to
avoid being targeted by attackers.

```
sudo ./trace-collector &
```

Logs appear in the system journal:

```
journalctl -t kernel -f
```

A systemd unit is provided at `deployment/trace-collector.service`.

---

## Deployment helpers

### Ansible parallel reload

For multi-server deployments, use the provided Ansible playbook:

```
ansible-playbook -i inventory prm-reload.yml
```

This generates tokens with `prm-gentoken`, distributes the eBPF object, and
runs `prm-loader unload` + `prm-loader load` on each target in parallel.

### Local QEMU VM (development)

Rocky Linux 9:
```
cd deployment
./dev-deploy.sh
ssh -p 2222 rocker@localhost
```

Debian 12:
```
cd deployment
./debian_deploy.sh
ssh -p 2223 debian@localhost
```

Both scripts download a cloud image, create a cloud-init seed with the
required packages, launch QEMU with KVM, and scp the project into the VM.

### Remote host

```
cd deployment
./deploy-inventory.sh <IP>
```

This installs dependencies via dnf, copies the project to `~/PRM/` on the
target, and requires root SSH access.

---

## Unloading

```
prm-loader unload --token /path/to/token
```

This removes the pin directory at `/sys/fs/bpf/prm` and detaches all hooks.

Alternatively, if you have direct root access:

```
rm -rf /sys/fs/bpf/prm
```

BPF programs are automatically detached when the last reference (pin or fd)
is removed.

---

## Known limitations

- Policy changes require recompilation.  There is no runtime policy reload.
- The rule table is fixed at 300 entries.
- Ancestry depth is limited to 3 levels (process, parent, grandparent).
- String comparisons are bounded by MAX_STR (16 chars); process names longer
  than 15 characters are truncated (this is a kernel `comm` limitation).
- The eBPF verifier imposes loop and instruction limits that constrain the
  complexity of PROG handlers.

---

## Authors

Mojtaba Akbari (Mojjjak)  
GWDG -- Georg-August-Universitaet Goettingen  
mojtaba.akbari@gwdg.de  
mojtaba.akbari.sec@gmail.com

---

## License

GPL (required for eBPF programs that use GPL-only BPF helpers).
