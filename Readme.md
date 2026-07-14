# PRM — Process Rule Management Framework

Kernel-level access control for Linux based on process ancestry.
Hooks into LSM via eBPF, inspects the calling process + parent + grandparent,
and evaluates a rule table to decide ACCEPT/REJECT/REDIRECT per syscall.

Built for HPC and multi-tenant environments where SELinux/AppArmor/seccomp
don't have enough runtime context to tell a legit job from an exploit
running under the same credentials.

## Requirements

- Linux >= 5.15, `CONFIG_BPF_LSM=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Boot param: `lsm=...,bpf`
- RHEL/Rocky: `clang llvm libbpf bpftool elfutils-libelf-devel gcc make kernel-devel`
- Debian/Ubuntu: `clang llvm libbpf-dev bpftool libelf-dev gcc make linux-headers-$(uname -r)`

## Building

```
cd deployment
make
```

Produces: `hookentry.bpf.o`, `prm-loader`, `prm-configure`, `trace-collector`

## Installation

```
cd deployment
sudo make install
```

Installs `prm-loader` to `/usr/local/sbin/`, `trace-collector` to `/usr/local/bin/`,
enables `trace-collector.service`.

## Usage

Loading and unloading requires a GPG-signed token (see `src/docs/15_Token_Auth_And_Deployment.md`).

```bash
# Load
prm-loader load --token /tmp/prm-token-HOSTNAME --dir /path/to/bpf/

# Unload
prm-loader unload --token /tmp/prm-token-HOSTNAME

# Status
prm-loader status
prm-loader show relations
prm-loader show config
prm-loader show cache
prm-loader show progs
```

After loading, the loader exits. The eBPF programs stay pinned in the kernel
at `/sys/fs/bpf/prm/` — no user-space daemon to kill.

## Configuration

All policy is compiled into the eBPF object. Two files:

- `src/ebpf/conf/PRMConfig.h` — paths, IPs, UIDs, blocked files, modules, etc.
- `src/ebpf/conf/PRM.h` — 300-entry rule table (process ancestry matching)

Change policy → rebuild → redeploy.

## Project Layout

```
src/
  ebpf/
    hookentry.c              30+ LSM hook entry points
    core/                    verifier, cache, filters, dispatcher
    progs/
      PRMProgEntry.c         aggregator (includes all modules)
      modules/               individual security handlers (12 modules)
      PRMProgHelper.c        shared utilities
    include/                 headers, macros, data structures
    conf/                    PRM.h (rules), PRMConfig.h (policy), PRMProg.h (slots)
  tools/
    prm-loader.c             loader with GPG token auth
    prm-configure.c          ncurses rule editor
    trace-collector.c        trace_pipe → syslog forwarder
  docs/                      detailed documentation (15 chapters + paper)

deployment/
  Makefile                   build targets
  ecc                        eBPF compiler (eunomia-bpf)
  prm-gentoken               token generator
  prm.service                systemd unit (loader)
  trace-collector.service    systemd unit (collector)
  dev-deploy.sh              Rocky Linux QEMU dev VM
  debian_deploy.sh           Debian 12 QEMU dev VM
  deploy-inventory.sh        remote deploy via SSH

test-samples/                security test suite, vuln demos
benchmarks/                  syscall benchmarks, AppArmor comparison
```

## PROG Handlers

Security handlers invoked by RETURN rules in the rule table:

| # | Handler | Hook | Purpose |
|---|---------|------|---------|
| 1 | signalKillTracer | TASK_KILL | protect PRM process from signals |
| 2 | denyWriteOutside | INODE_CREATE | block writes outside allowed dirs |
| 3 | denySocketEndHost | SOCKET_CONNECT | block outbound to non-private IPs |
| 4 | bprmSecurityCheck | BPRM_SECURITY | block exec from /tmp, /dev/shm |
| 5 | memoryProtect | FILE_MPROTECT | block mprotect(EXEC) on untrusted mem |
| 6 | denyIncomeSocket | SOCKET_ACCEPT | filter inbound by source IP |
| 7 | denyFileOpen | FILE_OPEN | restrict file access by path/name |
| 8 | denyLoadModule | KERNEL_MODULE | block dangerous kernel modules |
| 9 | credPrepareCheck | CRED_PREPARE | block UID/GID escalation to root |
| 10 | capableCheck | CAPABLE | block dangerous capabilities |
| 11 | taskFixSetUIDCheck | TASK_FIX_SETUID | block setuid exploitation |

## Development VMs

```bash
# Rocky Linux 9 (port 2222)
cd deployment && ./dev-deploy.sh

# Debian 12 (port 2223)
cd deployment && ./debian_deploy.sh
```

## Documentation

Full docs in `src/docs/`:
- Framework internals (verifier, cache, filters, dispatcher)
- Rule table syntax and examples
- UID ancestry analysis
- Token authentication and deployment workflows
- Honeypot attack reports
- Academic paper

## Known Limitations

- Policy changes require recompilation (no runtime reload)
- Rule table fixed at 300 entries
- Ancestry depth: 3 levels (process, parent, grandparent)
- Process names truncated at 15 chars (kernel `comm` limit)
- eBPF verifier limits constrain PROG handler complexity

## Author

Mojtaba Akbari — GWDG, Georg-August-Universität Göttingen

## License

GPL
