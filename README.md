🛡️ Filtering Syscall Framework
Overview

This project is a Linux Security Module (LSM)-based framework for filtering syscalls based on process relation patterns, offering a flexible and modular way to enforce syscall-level security rules using BPF and static policy definitions.

At the heart of the system lies the Process Relation Map (PRM): a powerful and configurable rule engine that filters syscalls based on process ancestry and relation roles.
📂 Project Structure

filtering-syscall-framework/
├── src/
│   └── PRM/
│       ├── include/
│       │   ├── conf/
│       │   │   └── PRM.h        # Main configuration and rule definitions
│       │   └── PRMStructs.h     # PRM-related data structures
│       └── PRMFilters.c         # PRM filter logic implementation
├── README.md
└── ...

⚙️ How PRM Works

PRM is a table-driven engine that inspects the syscall context and uses the process’s ancestry (process, parent, grandparent) to match rules and determine whether to allow, deny, or redirect the syscall evaluation.

Each rule has the form:

PREFIX, PREFIX, PREFIX, ACTION, REDIRECT_INDEX, PROTECTED_ZONE_FLAG, HOOK

    PREFIX: Process name or PREFIX_NOCARE to match anything

    ACTION:

        ACCEPT: Allow syscall

        REJECT: Deny syscall

        REDIRECT: Jump to another PRM rule index

        RETURN: Return control to another pre-defined program

        DEBUG: Log matched rule for debugging

    REDIRECT_INDEX: Target index to jump to on redirect

    PROTECTED_ZONE_FLAG: Marks if rule belongs to a protected evaluation zone

    HOOK: Index of the LSM/BPF hook the rule applies to

🔁 Matching Examples:
Process	Parent	G-Parent	Match Pattern
bash	any	any	{PREFIX_BASH, PREFIX_NOCARE, PREFIX_NOCARE}
any	sshd	any	{PREFIX_NOCARE, PREFIX_SSH, PREFIX_NOCARE}
python	any	slurm	{PREFIX_PYTHON, PREFIX_NOCARE, "slurmstepd"}
🔐 Protected Zones

Certain roles are marked as protected zones, which can only be entered via REDIRECT actions. This enables deep inspection of sensitive contexts (e.g., slurmstepd, containerd, su) without affecting unrelated syscall evaluations.
🪝 Hook Index Table

This framework supports many LSM hooks like:
Hook Name	Index
FILE_PERMISSION	1
FILE_OPEN	6
SB_MOUNT	7
BPF	16
TASK_KILL	19
TASK_PTRACE	22
...	...

To apply a rule to a specific hook, use the corresponding index.
📌 Role Configuration

In PRM.h, roles are defined with macros such as:

#define RELATION_0 PREFIX_BASH, PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,0 ,0
#define RELATION_11 PREFIX_NOCARE, "containerd-shim" ,PREFIX_NOCARE ,REDIRECT ,50 ,0 ,0
#define RELATION_90 PREFIX_NOCARE, PREFIX_BASH ,"su" , ACCEPT ,0 ,1 ,0

Empty slots are reserved with #define RELATION_N EMPTY.

You can define up to MAX_NUMBER_OF_RELATION (100) roles.
🛠️ Building

Make sure to compile with the appropriate kernel headers and BPF toolchain support. The .c files implement the BPF programs referenced by the PRM configuration.
📎 Usage Tips

    Use ordered rules for performance (most likely patterns first).

    Avoid excessive DEBUG actions in production.

    Always test new roles under tracing before deployment.

    Maintain separation between general and protected roles using redirect logic.

💬 Acknowledgement

Designed by Mojtaba — "This is PRM, I hope you are able to create your pattern ;)"