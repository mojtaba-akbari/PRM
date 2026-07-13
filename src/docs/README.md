# PRM Framework Documentation

## Documentation Structure

1. [Framework Overview](00_Framework_Overview.md) - Architecture and components
2. [Entrypoint](01_Entrypoint.md) - LSM hook entry points (`hookentry.c`)
3. [Verifier](02_Verifier.md) - Process ancestry checker
4. [Filters](03_Filters.md) - Fast-decision pre-processing
5. [PROG Concept](04_PROG_Concept.md) - Security handler programs
6. [PRM Concept](05_PRM_Concept.md) - Policy Rule Management system
7. [PRM Config](06_PRM_Config.md) - Configuration system (`PRMConfig.h`)
8. [PRM Table Rules](07_PRM_Table_Rules.md) - 300-entry rule table (`PRM.h`)
9. [UID Ancestor Concept](08_UID_Ancestor_Concept.md) - Process lineage tracking
10. [UID DB](09_UID_DB.md) - UID transition pattern detection
11. [PROG Examples](10_PROG_Examples.md) - Practical PROG handler examples
12. [Comparison With Other Tools](11_Comparison_With_Other_Tools.md) - vs SELinux, AppArmor, seccomp
13. [Framework Advantages](12_Framework_Advantages.md) - Design benefits
14. [Cache Mechanism](13_Cache_Mechanism.md) - LRU cache optimization
15. [Chain Scenario](14_Chain_Scenario.md) - Multi-hop attack chain analysis

## Operational Docs

- [PRM Loader](README-LOADER.md) - Loading, unloading, GPG token auth, inspection commands

## Reports

- [Honeypot Report](honeypot-report/PRM_Honeypot_Report.md) - Real-world attack data from PRM deployment

## Source Layout

```
src/ebpf/           eBPF kernel code
  hookentry.c       Entry point (includes everything)
  core/             Verifier, filters, cache, structs
  progs/            PROG handlers + helpers
  include/          Headers
  conf/             PRM.h, PRMConfig.h, PRMProg.h

src/tools/          User-space tools
  prm-loader.c      Loader with GPG token verification
  prm-configure.c   ncurses TUI editor
  trace-collector.c Log forwarder (trace_pipe → syslog)
```

## Quick Start

```bash
cd deployment
make                # build everything
sudo make install   # install loader + collector service
prm-loader load --token /tmp/prm-token-$(hostname)
prm-loader status   # verify
```
