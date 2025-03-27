#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM
#define FILTERING_SYSCALL_FRAMEWORK_PRM

/*  Mojtaba, 
    This Is PRM , Process Relation Map

    PRM Table Page Size ---> 5 * Process Relation
    Number Of PRM Tables ---> 1 - 8 (Ordered) (If you want to check order faster put it by order --- it improves our performance)
    Process Relation Names ---> 16 * Byte (extra bytes are eliminated)
    
    Notice: Without enough tracing never add roles !!!
    Notice: Dynamic Orders , you can use this ability to put your roles depends on different situation and conditions
*/

#define MAX_NUMBER_OF_RELATION 50

/* Roles :
    (X) means knownable process, (NULL) means not important or everything or * PREFIX_NOCARE

    {PREFIX_NOCARE,PREFIX_NOCARE,PREFIX_NOCARE} ---> EveryThings (Deny Anything)
    {X,PREFIX_NOCARE,PREFIX_NOCARE} ---> Focus on process (More Strict On Process)
    {X,X,PREFIX_NOCARE} ---> Focus on process and parent (More Middle User-Space service like bash , zsh , fish , ssh, ...)
    {X,PREFIX_NOCARE,X} ---> Focus on process and grand-parent (Any Isolation Level with docker , kvm , ... Restrict to process)
    {PREFIX_NOCARE,X,PREFIX_NOCARE} ---> Focus on parent (High Strict Any process just Parent more focuse on exploits ...)
    {PREFIX_NOCARE,X,X} ---> Focus on parent and grand-parent (High Strict Any root Isolation level apptainer , singolarity ...) 
    {PREFIX_NOCARE,PREFIX_NOCARE,X} ---> Focus on grand-parent (High focus on Isolation)
    {X,X,X} ---> Focus On This pattern (For specific pattern which is knownable)
*/

// direct hit roles
#define RELATION_0 PREFIX_BASH,PREFIX_BASH,PREFIX_NOCARE

// direct hit roles
#define RELATION_1 PREFIX_NOCARE,PREFIX_BASH,PREFIX_NOCARE

#define RELATION_2 PREFIX_NOCARE,PREFIX_FISH,PREFIX_NOCARE

#define RELATION_3 PREFIX_NOCARE,PREFIX_SSH,PREFIX_NOCARE

#define RELATION_4 PREFIX_NOCARE,PREFIX_ZSH,PREFIX_NOCARE

// isolation level docker
#define RELATION_5 PREFIX_PYTHON, PREFIX_SH, "containerd-shim"

// isolation level slurm
#define RELATION_6 PREFIX_PYTHON, PREFIX_BASH, "slurm_script"

// High Strict isolation level docker
#define RELATION_7 PREFIX_NOCARE, PREFIX_NOCARE, "containerd-shim"

// High Strict slurm script level
#define RELATION_8 PREFIX_NOCARE, PREFIX_NOCARE, "slurm_script"

// Focus on bash slurmstepd.scope script level
#define RELATION_9 PREFIX_BASH, PREFIX_NOCARE, "slurmstepd.scope"

// High Strict slurmstepd.scope script level
#define RELATION_10 PREFIX_NOCARE, PREFIX_NOCARE, "slurmstepd.scope"

// High Strict kvm level
#define RELATION_11 PREFIX_NOCARE, PREFIX_NOCARE, "qumo"

#define RELATION_12 EMPTY

#define RELATION_13 EMPTY

#define RELATION_14 EMPTY

#define RELATION_15 EMPTY

#define RELATION_16 EMPTY

#define RELATION_17 EMPTY

#define RELATION_18 EMPTY

#define RELATION_19 EMPTY

#define RELATION_20 EMPTY

#define RELATION_21 EMPTY

#define RELATION_22 EMPTY

#define RELATION_23 EMPTY

#define RELATION_24 EMPTY

#define RELATION_25 EMPTY

#define RELATION_26 EMPTY

#define RELATION_27 EMPTY

#define RELATION_28 EMPTY

#define RELATION_29 EMPTY

#define RELATION_30 EMPTY

#define RELATION_31 EMPTY

#define RELATION_32 EMPTY

#define RELATION_33 EMPTY

#define RELATION_34 EMPTY

#define RELATION_35 EMPTY

#define RELATION_36 EMPTY

#define RELATION_37 EMPTY

#define RELATION_38 EMPTY

#define RELATION_39 EMPTY

#define RELATION_40 EMPTY

#define RELATION_41 EMPTY

#define RELATION_42 EMPTY

#define RELATION_43 EMPTY

#define RELATION_44 EMPTY

#define RELATION_45 EMPTY

#define RELATION_46 EMPTY

#define RELATION_47 EMPTY

#define RELATION_48 EMPTY

#define RELATION_49 EMPTY

#endif