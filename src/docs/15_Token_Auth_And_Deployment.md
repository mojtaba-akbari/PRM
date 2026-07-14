# Token Authentication & Deployment

This document covers the GPG-based token authentication system used by
`prm-loader` for load/unload operations, and the deployment workflow for
single and multi-server environments.

---

## GPG Key Setup (one-time)

PRM uses GPG signatures to authenticate load/unload operations.  The admin
generates a keypair once, and distributes the public key to all target nodes.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ONE-TIME KEY SETUP                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  CONTROL NODE (admin workstation)                                       │
│  ─────────────────────────────────                                      │
│                                                                         │
│  1. Generate GPG keypair:                                               │
│     $ gpg --full-generate-key                                           │
│       → Real name: PRM Admin                                            │
│       → Email: prm-admin@gwdg.de                                        │
│       → Key type: RSA 4096                                              │
│                                                                         │
│  2. Export public key:                                                  │
│     $ gpg --export --armor prm-admin@gwdg.de > prm-admin.pub            │
│                                                                         │
│                          │                                              │
│                          │ scp / ansible                                │
│                          ▼                                              │
│                                                                         │
│  TARGET NODES (servers running PRM)                                     │
│  ──────────────────────────────────                                     │
│                                                                         │
│  3. Import public key:                                                  │
│     $ gpg --import prm-admin.pub                                        │
│                                                                         │
│  Result:                                                                │
│    • Control node holds PRIVATE key (signs tokens)                      │
│    • Target nodes hold PUBLIC key (verify signatures)                   │
│    • Private key NEVER leaves the control node                          │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Token Generation and Verification Flow

Every load/unload requires a fresh, signed, single-use token.  This prevents
unauthorized loading even if an attacker gains root on a target node.

```
┌──────────────────────┐                        ┌──────────────────────┐
│    CONTROL NODE      │                        │    TARGET NODE       │
│  (admin workstation) │                        │  (server running PRM)│
└──────────┬───────────┘                        └──────────┬───────────┘
           │                                               │
           │  1. Generate token                            │
           │     $ prm-gentoken manage node-01             │
           │                                               │
           │     Creates:                                  │
           │       /tmp/prm-token-node-01                  │
           │       Content: manage:node-01:1719500000:a3f… │
           │                                               │
           │  2. Sign with GPG private key                 │
           │     → /tmp/prm-token-node-01.sig              │
           │                                               │
           │  3. Transfer token + signature                │
           │─────────────────scp──────────────────────────▶│
           │                                               │
           │  4. Execute loader                            │
           │─────────────────ssh──────────────────────────▶│
           │     prm-loader load --token /tmp/prm-token-…  │
           │                                               │
           │                                    ┌──────────┴──────────┐
           │                                    │  VERIFICATION:      │
           │                                    │  ✓ GPG sig valid?   │
           │                                    │  ✓ Action matches?  │
           │                                    │  ✓ Hostname matches?│
           │                                    │  ✓ Age < 1 hour?    │
           │                                    │  ✓ Nonce not reused?│
           │                                    └──────────┬──────────┘
           │                                               │
           │                                    All pass → load eBPF
           │                                    Any fail → REJECTED
           │                                               │
           │◀──────────── result ──────────────────────────│
           │                                               │
```

**Token format:**

```
 ACTION : HOSTNAME : TIMESTAMP : NONCE
   │         │          │          │
   │         │          │          └── 32-char random hex (replay protection)
   │         │          └───────────── Unix epoch seconds (1-hour expiry)
   │         └──────────────────────── Must match target's hostname
   └────────────────────────────────── load | unload | manage (wildcard)
```

**Why this works:**
- Token is bound to a specific host → stolen token can't be used elsewhere
- Token expires in 1 hour → narrow attack window
- Nonce is recorded after use → replay attacks impossible
- GPG signature → only the holder of the private key can generate valid tokens
- `manage` action → single token works for both unload + load (reload scenario)

---

## Load Sequence

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          LOAD SEQUENCE                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  $ prm-loader load --token /tmp/prm-token-node-01 --dir /opt/prm/       │
│                                                                         │
│  ┌─────────────────┐                                                    │
│  │ Verify GPG token│──── FAIL ──→ "TOKEN REJECTED" (exit 1)             │
│  └────────┬────────┘                                                    │
│           │ PASS                                                        │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ Open .bpf.o     │──── FAIL ──→ "Failed to open BPF object"           │
│  └────────┬────────┘                                                    │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ Load into kernel│     BPF verifier checks all programs               │
│  └────────┬────────┘                                                    │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ Attach LSM hooks│     30+ hooks (file_open, socket_connect, ...)     │
│  └────────┬────────┘                                                    │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ Pin to bpffs    │     /sys/fs/bpf/prm/{programs, maps, links}        │
│  └────────┬────────┘                                                    │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ EXIT            │     Process exits. eBPF stays in kernel.           │
│  └─────────────────┘     No user-space process remains.                 │
│                                                                         │
│  Result:                                                                │
│    • All syscalls now pass through PRM rule engine                      │
│    • ps aux | grep prm → nothing (stealth)                              │
│    • bpftool prog list | grep lsm → 30+ programs attached              │
│    • /sys/fs/bpf/prm/ → pinned programs and maps persist                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Unload Sequence

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         UNLOAD SEQUENCE                                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  $ prm-loader unload --token /tmp/prm-token-node-01                     │
│                                                                         │
│  ┌─────────────────┐                                                    │
│  │ Verify GPG token│──── FAIL ──→ "TOKEN REJECTED" (exit 1)             │
│  └────────┬────────┘                                                    │
│           │ PASS                                                        │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ rm -rf          │     Removes /sys/fs/bpf/prm/                       │
│  │ /sys/fs/bpf/prm │     Kernel auto-detaches all LSM hooks             │
│  └────────┬────────┘     when last pin reference is removed             │
│           │                                                             │
│           ▼                                                             │
│  ┌─────────────────┐                                                    │
│  │ DONE            │     System returns to unprotected state            │
│  └─────────────────┘                                                    │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Multi-Server Reload Workflow

Typical production scenario: rebuild config, reload across all nodes.

```
┌──────────────┐         ┌──────────┐  ┌──────────┐  ┌──────────┐
│ Control Node │         │ node-01  │  │ node-02  │  │ node-03  │
└──────┬───────┘         └────┬─────┘  └────┬─────┘  └────┬─────┘
       │                      │             │             │
       │  1. Edit PRMConfig.h / PRM.h                     │
       │  2. make ebpf (rebuild hookentry.bpf.o)          │
       │  3. prm-gentoken manage node-01                  │
       │     prm-gentoken manage node-02                  │
       │     prm-gentoken manage node-03                  │
       │                      │             │             │
       │──── scp .bpf.o ─────▶│             │             │
       │──── scp .bpf.o ──────────────────▶│             │
       │──── scp .bpf.o ─────────────────────────────────▶│
       │──── scp tokens ─────▶│             │             │
       │──── scp tokens ──────────────────▶│             │
       │──── scp tokens ─────────────────────────────────▶│
       │                      │             │             │
       │── ssh: unload ──────▶│             │             │
       │── ssh: unload ───────────────────▶│             │
       │── ssh: unload ──────────────────────────────────▶│
       │                      │             │             │
       │── ssh: load ────────▶│             │             │
       │── ssh: load ─────────────────────▶│             │
       │── ssh: load ────────────────────────────────────▶│
       │                      │             │             │
       ▼                      ▼             ▼             ▼
  All nodes running new config (< 30 seconds total)
```

Automated with Ansible: `ansible-playbook -i inventory prm-reload.yml`

---

## Security Model

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    WHY THIS IS SECURE                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Attack: "I got root on a target node, can I unload PRM?"               │
│                                                                         │
│  ✗ sudo prm-loader unload                                               │
│    → sudo blocked (passwd in forbidden file list)                       │
│                                                                         │
│  ✗ prm-loader unload --token (forged token)                             │
│    → GPG signature check fails (no private key on target)               │
│                                                                         │
│  ✗ rm -rf /sys/fs/bpf/prm                                              │
│    → lsm/bpf hook blocks bpf() syscall from unauthorized PIDs           │
│                                                                         │
│  ✗ Write to BPF maps directly                                           │
│    → Same lsm/bpf hook: only PRM's own PID can call bpf()              │
│                                                                         │
│  ✗ Kill PRM process                                                     │
│    → No process to kill (loader already exited)                         │
│                                                                         │
│  ✗ SUID binary to escalate                                              │
│    → taskFixSetUIDCheck (PROG #11) blocks UID transitions               │
│                                                                         │
│  ✓ Only way: SSH as root from control node with valid GPG token         │
│    → Requires physical access to admin's GPG private key                │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```
