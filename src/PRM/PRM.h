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

// Super Direct hit roles
#define RELATION_0 PREFIX_BASH, PREFIX_NOCARE ,PREFIX_NOCARE ,REJECT ,0 ,0

// High Direct hit roles
#define RELATION_1 PREFIX_BASH, PREFIX_SSH ,PREFIX_NOCARE ,REJECT ,0 ,0

#define RELATION_2 PREFIX_FISH, PREFIX_NOCARE ,PREFIX_NOCARE ,REJECT ,0 ,0

#define RELATION_3 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_SSH ,REJECT ,0 ,0

#define RELATION_4 PREFIX_ZSH, PREFIX_NOCARE ,PREFIX_NOCARE ,REJECT ,0 ,0

// Super Indirect hit roles
#define RELATION_5 PREFIX_NOCARE, PREFIX_BASH ,PREFIX_NOCARE ,REJECT ,0 ,0

#define RELATION_6 PREFIX_NOCARE, PREFIX_FISH ,PREFIX_NOCARE ,REJECT ,0 ,0

#define RELATION_7 PREFIX_NOCARE, PREFIX_ZSH ,PREFIX_NOCARE ,REJECT ,0 ,0

// Focus on python slurmstepd script level
#define RELATION_8 PREFIX_PYTHON, PREFIX_NOCARE ,"slurmstepd" ,REJECT ,0 ,0

// Focus on bash slurmstepd script level
#define RELATION_9 PREFIX_BASH, PREFIX_NOCARE ,"slurmstepd" ,REJECT ,0 ,0

// High Strict slurmstepd script level
#define RELATION_10 PREFIX_NOCARE, PREFIX_NOCARE ,"slurmstepd" ,REJECT ,0 ,0

// If Found Any containerd - docker Redirect To Docker Zone
#define RELATION_11 PREFIX_NOCARE, "containerd-shim" ,PREFIX_NOCARE ,REDIRECT ,46 ,0

#define RELATION_12 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_SH ,REJECT ,0 ,0

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

// Docker Protect Zone , Focus More To Strict it
#define RELATION_46 "runc", "containerd-shim" , PREFIX_NOCARE ,REJECT ,0 ,1

#define RELATION_47 PREFIX_PYTHON, "containerd-shim" , PREFIX_NOCARE ,REJECT ,0 ,1

#define RELATION_48 PREFIX_NOCARE, "containerd-shim" ,PREFIX_NOCARE ,REDIRECT ,12 ,1

#define RELATION_49 EMPTY

#endif