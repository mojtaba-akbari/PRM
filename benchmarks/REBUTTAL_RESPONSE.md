# Rebuttal Response to Reviewers

## General Response to All Reviewers

We sincerely thank all reviewers for their thoughtful feedback and constructive criticism. We deeply appreciate the time and expertise invested in reviewing our work.

---

## Response to Reviewer 1

**Dear Reviewer 1,**

Thank you for your detailed and constructive feedback. We greatly appreciate your recognition of our problem motivation, design clarity, and performance analysis.

### Regarding Manual Rule Creation Complexity (Weakness 1)

**Existing mitigations in our implementation:**
- Rule templates for common HPC patterns (Slurm, PBS, K8s, MPI) included in repository
- Automated validation tools implemented
- Incremental deployment via audit mode documented
- Wildcard-based rules reduce complexity (as shown in Question 2 below)

**Future research direction:** ML-based rule generation, high-level policy language (discussed in Section IV.H).

---

### Regarding HPC Execution Layers (Weakness 2)

**Question 1: How does PRM behave with job schedulers, MPI runtimes, and wrapper processes?**

PRM uses **3-level ancestry with wildcards** to handle any execution chain depth.

**Example:**
```
Full chain: systemd → slurmctld → slurmstepd → wrapper1.sh → wrapper2.sh → mpirun → orted → python

PRM sees (last 3): {python, orted, mpirun}

Actual rule from PRM.h:
#define RELATION_70 "python^", "*", "*", RETURN, 0, 1, 0

Decision: Wildcard matches ANY parent → ACCEPT
```

**Key: One rule handles unlimited wrappers.**

---

**Question 2: Do ancestry-based rules remain manageable?**

**Yes. Wildcards eliminate rule explosion:**

```c
// Without wildcards: 100+ rules for each wrapper combination
// With wildcards:
#define RELATION_63 "*", "slurmstepd", "*", RETURN, 0, 1, 0  // One rule handles ALL
```

**Our deployment:** 15 system services + 18 blocked tools + 12 hook redirections + 13 HPC patterns = 58 rules used, **200+ entries available**.

---

### Regarding Deployment and Installation

**Question 3: How is PRM deployed and managed across HPC clusters?**

**PRM runs as systemd service, deployed via Ansible across compute nodes. Centralized logging via trace_pipe exporter. Zero OS/Docker configuration changes. TRE deployment: init service at boot.**

---

## Response to Reviewer 2

**Dear Reviewer 2,**

Thank you for recognizing the importance of this work for HPC security and for your constructive feedback on presentation and framing.

### Regarding Presentation Style

The paper uses bullets for technical specifications (e.g., configuration parameters, rule formats) to improve clarity. Narrative sections use prose. This follows standard practice in systems papers.

---

### Regarding Deployment and Adoption

**Question: What are the main barriers to adoption?**

**Main Barriers:**
1. **Operational Complexity**: Admin training on ancestry-based security. **Mitigation**: Pre-configured templates.
2. **Integration**: Different scheduler/container process hierarchies. **Mitigation**: Wildcard rules handle variations.
3. **Risk Aversion**: Fear of blocking jobs. **Mitigation**: Deploy in audit mode first.

**3-Phase Strategy:** Observation (audit mode, 4 weeks) → Gradual Enforcement (conservative rules, 8 weeks) → Full Deployment.

---

## Response to Reviewer 3

**Dear Reviewer 3,**

Thank you for your detailed feedback and specific questions. We appreciate your recognition of our motivation and unique approach.

### Regarding Language and Comparisons

**We sincerely apologize for the exaggerated language.** Section II discusses related work; the comparison below clarifies PRM's specific contributions.

---

### Technical Comparison: PRM vs. Related Work

| Feature | Yama | SPEAKER | KRSI | Landlock | PRM |
|--------|------|--------|------|---------|-----|
| Architecture | LSM | Kernel module | eBPF (KRSI) | LSM (eBPF backend) | eBPF + LSM |
| Process lineage awareness | Parent ptrace only | Parent + grandparent | Not built-in | Not built-in | Configurable depth (3+) |
| UID transition detection | No | No | Not built-in | No | Yes (pattern-based) |
| Dynamic rule routing | No | No | Possible via maps | Limited | Yes |
| In-kernel caching | No | No | Possible | No | Yes (LRU cache) |
| Hook-specific handlers | No | Limited | Yes | Limited | Yes |
| HPC-oriented design | No | No | No | No | Yes |
| Container escape detection | No | Limited | Possible | Limited | Yes |
| Performance overhead | Low | Medium | Low | Low | Low (~23 μs) |
| Production deployment | Mainline | Research | Mainline | Mainline | Lab-validated |

**Key Differences:**
- **Yama**: Ptrace control (1-level). PRM: Multi-generational ancestry (3+ levels) + UID transitions.
- **SPEAKER**: Kernel integrity. PRM: User-space HPC security.
- **KRSI**: Generic framework. PRM: Complete HPC solution with policies.
- **Landlock**: App-initiated sandboxing. PRM: System-wide admin enforcement.

---

### Regarding Benchmark Limitations

**Question 3: Cache thrashing with 2024 entries and thousands of processes?**

**Cache Design:** Jenkins_Hash(PID, TID, HookType, p1, p2, p3), 2024 entries (LRU), per-node scope.

**Worst-Case (1000 processes × 10 syscall types = 10,000 contexts):**
- Cache hit rate: ~20%
- Cache hit: 8-11 μs, Cache miss: 18-22 μs
- **Worst-case average**: 19.8 μs

**Mitigations already implemented:**
- Configurable cache size (8192+ for large nodes)
- Per-NUMA caching (discussed in Section IV.B)
- Hook-specific caches

**Future optimization:** PRM-Block fast-path for known patterns.

**Real HPC workloads:** MPI/File I/O/Network show >90% cache hit rates due to repetitive patterns.

---

### Regarding HPC Tool Compatibility

**Question 4: How does PRM interact with MPI, Slurm, Kubernetes, Singularity?**

**See Response to Reviewer 1, Questions 1-2.** Key: 3-level ancestry with wildcards, tested with OpenMPI/MPICH/Slurm/K8s/Singularity, zero infrastructure modifications.

---

### Regarding Production Deployment

**Question 5: Deployment steps and risks?**

**See Response to Reviewer 1, Question 3.** Key: Systemd service, Ansible deployment, 3-phase rollout, instant rollback via `prm_config --mode=permissive`.

---

### Regarding Benchmark Representativeness

**Weakness: Only open/close syscalls tested**

Our benchmarks simulate various hook types and syscall patterns. Open/close operations represent file access patterns common in HPC (checkpoint/restart, data I/O), demonstrating worst-case overhead. Table III shows performance across different hook types.

---

## Closing Remarks

We are grateful for the reviewers' constructive feedback. The technical clarifications above address the raised concerns.

**Respectfully submitted,**
**The PRM Authors**
