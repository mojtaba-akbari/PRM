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
#define RELATION_1 {PREFIX_NOCARE,PREFIX_BASH,PREFIX_NOCARE}
#define RELATION_2 {PREFIX_NOCARE,PREFIX_FISH,PREFIX_NOCARE} 
#define RELATION_3 {PREFIX_NOCARE,PREFIX_SSH,PREFIX_NOCARE}
#define RELATION_4 {PREFIX_NOCARE,PREFIX_ZSH,PREFIX_NOCARE}
// isolation level docker
#define RELATION_5 {PREFIX_PYTHON, PREFIX_SH, "containerd-shim"}
// isolation level slurm
#define RELATION_6 {PREFIX_PYTHON, PREFIX_BASH, "slurm_script"}
// High Strict isolation level docker
#define RELATION_7 {PREFIX_NOCARE, PREFIX_NOCARE, "containerd-shim"}
// High Strict slurm script level
#define RELATION_8 {PREFIX_NOCARE, PREFIX_NOCARE, "slurm_script"}
// Focus on bash slurmstepd.scope script level
#define RELATION_9 {PREFIX_BASH, PREFIX_NOCARE, "slurmstepd.scope"}
// High Strict slurmstepd.scope script level
#define RELATION_10 {PREFIX_NOCARE, PREFIX_NOCARE, "slurmstepd.scope"}
// High Strict kvm level
#define RELATION_11 {PREFIX_NOCARE, PREFIX_NOCARE, "qumo"}


// *** Rendarable Roles *** //

// PRM Table 1 ---> Highest Priority
#define PRM_1 RELATION_1, \
            RELATION_2, \
            RELATION_3, \
            RELATION_4, \
            RELATION_5

// PRM Table 2 
#define PRM_2 RELATION_6, \
            RELATION_7, \
            RELATION_8, \
            RELATION_9, \
            RELATION_10

// PRM Table 3 
#define PRM_3 RELATION_11

// PRM Table 4 
#define PRM_4 EMPTY

// PRM Table 5 
#define PRM_5 EMPTY

// PRM Table 6 
#define PRM_6 EMPTY

// PRM Table 7 
#define PRM_7 EMPTY

// PRM Table 8 ---> Lowest Priority
#define PRM_8 EMPTY


#endif