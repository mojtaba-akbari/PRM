# 🛡️ Filtering Syscall Framework

A Linux Security Module (LSM)-based framework for syscall filtering using **process relation patterns**. This modular and flexible system leverages **BPF** and static policy definitions to enforce syscall-level security through a customizable rule engine called the **Process Relation Map (PRM)**.

## 📑 Table of Contents

- [Introduction](#introduction)
- [How PRM Works](#how-prm-works)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Configuration](#configuration)
- [Hook Index Table](#hook-index-table)
- [Examples](#examples)
- [Troubleshooting & Tips](#troubleshooting--tips)
- [Acknowledgement](#acknowledgement)
- [License](#license)

---

## 🧩 Introduction

The Filtering Syscall Framework introduces a **rule-based security mechanism** that filters syscalls based on the ancestry of the calling process. By analyzing the relationships (e.g., parent, grandparent), the system can enforce nuanced policies on process behavior.

At the core lies **PRM**: a lightweight, table-driven rule engine integrated into the BPF/LSM pipeline.

---

## ⚙️ How PRM Works

PRM evaluates syscall events against a set of predefined rules based on the calling process’s ancestry.

**Rule Format:**

PREFIX_1, PREFIX_2, PREFIX_3, ACTION, REDIRECT_INDEX, PROTECTED_ZONE_FLAG, HOOK


- `PREFIX`: Process name or `PREFIX_NOCARE` (wildcard)
- `ACTION`: One of `ACCEPT`, `REJECT`, `REDIRECT`, `RETURN`, `DEBUG`
- `REDIRECT_INDEX`: Used if `REDIRECT` action is chosen
- `PROTECTED_ZONE_FLAG`: Indicates whether the rule is in a protected context
- `HOOK`: Index of the syscall event hook (see table below)

### 🔐 Protected Zones

Rules with `PROTECTED_ZONE_FLAG=1` can only be entered via `REDIRECT`. This enables more stringent evaluation in critical contexts like `slurmstepd`, `containerd`, or `su`.

---

## 📁 Project Structure
```
filtering-syscall-framework/
├── deployment/
│   ├── ecc
│   ├── ecli
│   ├── filtering-syscall-framework.service
│   └── Makefile
├── src/
│   ├── include/
│   │   ├── baseheaders.h
│   │   └── BTFFunctions.h
│   ├── PRM/
│   │   ├── include/
│   │   │   ├── conf/
│   │   │   │   └── PRM.h
│   │   │   ├── PRMFilters.h
│   │   │   ├── PRMProg.h
│   │   │   ├── PRMProgDispatcher.h
│   │   │   ├── PRMProgEntry.h
│   │   │   ├── PRMStructs.h
│   │   │   └── PRMVerifier.h
│   │   └── src/
│   │       ├── PRMFilters.c
│   │       ├── PRMProgDispatcher.c
│   │       ├── PRMProgEntry.c
│   │       ├── PRMStructs.c
│   │       └── PRMVerifier.c
│   ├── hookentry.c
│   ├── hooks-struct.struct
│   └── task-struct.struct
└── README.md
```

---

## 🛠️ Installation

For development purpose just use dev-deploy.sh inside of deployment project , it makes (qemu, vm, network, project) then copy daemon file and use systemctl to start it. (have fun) :)

1. Ensure you have **Linux kernel headers** and **BPF toolchain** available.
2. Clone the repository:
   ```bash
   git clone https://github.com/your-org/filtering-syscall-framework.git


Navigate to the project directory and build:

cd filtering-syscall-framework/deployment
make

 Kernel version compatibility and LSM support must be ensured before compilation.

 Usage

    Define syscall roles and patterns in PRM.h.

    Compile the BPF program.

    Load the PRM filter logic into your LSM/BPF stack.

    Apply the LSM hooks using the appropriate indexes.

Tips:

    Place high-probability rules earlier for performance.

    Test new rules using debug mode before production deployment.

    Separate protected and general roles using REDIRECT logic.

✨ Features

    Rule-based filtering using process ancestry (up to grandparent)

    Configurable action types: ACCEPT, REJECT, REDIRECT, RETURN, DEBUG

    Integration with multiple LSM hooks

    Support for protected zones with restricted entry

    BPF-based implementation for high performance

⚙️ Configuration

In PRM.h, define your role rules as:

```
#define RELATION_0 PREFIX_BASH, PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,0 ,0
#define RELATION_11 PREFIX_NOCARE, "containerd-shim" ,PREFIX_NOCARE ,REDIRECT ,50 ,0 ,0
#define RELATION_90 PREFIX_NOCARE, PREFIX_BASH ,"su" , ACCEPT ,0 ,1 ,0
```

Reserved roles: Use #define RELATION_N EMPTY

Maximum rules: MAX_NUMBER_OF_RELATION (100)

Hook Index Table
Hook Name	Index
FILE_PERMISSION	1
FILE_OPEN	6
SB_MOUNT	7
BPF	16
TASK_KILL	19
TASK_PTRACE	22
...	...

To apply rules to a hook, set the HOOK field to the respective index.

 Examples
Process	Parent	Grandparent	Match Rule Example
bash	any	any	{PREFIX_BASH, PREFIX_NOCARE, PREFIX_NOCARE}
any	sshd	any	{PREFIX_NOCARE, PREFIX_SSH, PREFIX_NOCARE}
python	any	slurm	{PREFIX_PYTHON, PREFIX_NOCARE, "slurmstepd"}

Troubleshooting & Tips

    Avoid heavy use of DEBUG in production

    Test rules thoroughly using trace tools

    Profile rule execution for ordering optimizations

    Ensure clear boundaries between protected and general zones

Acknowledgement

Designed by Mojjjak (Mojtaba)

    "This is PRM, I hope you are able to create your pattern ;)"

