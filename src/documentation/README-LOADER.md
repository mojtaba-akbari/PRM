# PRM Simple Loader

## What is this?

A minimal C program that loads PRM eBPF programs and exits.

**Key difference from ecli:**
- `ecli`: Stays running as user-space process
- `prm-loader`: Loads eBPF and exits (no process!)

## How it works

1. Loads `hookentry.bpf.o` into kernel
2. Pins programs to `/sys/fs/bpf/prm`
3. Pins maps to `/sys/fs/bpf/prm`
4. **Exits** - eBPF stays loaded in kernel!

## Build

```bash
cd deployment
make
```

This builds:
- `hookentry.bpf.o` (eBPF program)
- `prm-loader` (loader binary)

## Usage

### Load PRM
```bash
cd deployment
sudo ./prm-loader
```

Output:
```
PRM Simple Loader - Loading hookentry.bpf.o
BPF object loaded successfully
PRM loaded and pinned to /sys/fs/bpf/prm
Programs and maps will persist after this process exits
```

### Verify (no process!)
```bash
ps aux | grep prm     # Nothing!
ps aux | grep loader  # Nothing!

# But eBPF is loaded:
ls /sys/fs/bpf/prm/
bpftool prog list | grep prm
```

### Unload PRM
```bash
sudo rm -rf /sys/fs/bpf/prm
```

## Daemon Mode (optional)

If you want loader to stay running:

```bash
sudo ./prm-loader --daemon
```

This keeps process alive (for debugging).

## Stealth Deployment

### Method 1: Load and exit (best)
```bash
sudo ./prm-loader
# Process exits, eBPF stays loaded
# Attacker sees: Nothing!
```

### Method 2: Load with hidden name
```bash
exec -a "[kworker/prm]" sudo ./prm-loader --daemon &
# Process hidden as kernel worker
```

### Method 3: Systemd service
```bash
sudo cp prm-loader /usr/local/bin/
sudo systemctl enable prm-loader.service
sudo systemctl start prm-loader.service
```

## Advantages

✅ **No user-space process** (after load)
✅ **eBPF stays in kernel** (pinned)
✅ **Survives loader exit**
✅ **Simple C code** (no dependencies on ecli)
✅ **Easy to hide** (rename binary)

## Disadvantages

❌ **No map management** (ecli manages maps)
❌ **No log reading** (ecli reads trace_pipe)
❌ **No runtime updates** (ecli can update rules)

## When to use

**Use prm-loader when:**
- You want minimal footprint
- You don't need runtime updates
- You want stealth deployment
- You're okay with static rules

**Use ecli when:**
- You need map management
- You need log collection
- You need runtime rule updates
- You need full PRM features

## Comparison

| Feature | ecli | prm-loader |
|---------|------|------------|
| User-space process | YES | NO (exits) |
| Map management | YES | NO |
| Log reading | YES | NO |
| Runtime updates | YES | NO |
| Stealth | Medium | High |
| Complexity | High | Low |

## Test

```bash
cd deployment

# Build
make

# Load
sudo ./prm-loader

# Check (no process!)
ps aux | grep prm

# Check eBPF loaded
sudo bpftool prog list | grep lsm

# Unload
sudo rm -rf /sys/fs/bpf/prm
```

## Notes

- Requires `libbpf` installed
- Requires root to load eBPF
- eBPF programs must be pinned to persist
- Maps are pinned so they persist too
