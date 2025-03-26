#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM
#define FILTERING_SYSCALL_FRAMEWORK_PRM

/*  Mojtaba, 
    This Is PRM , Process Relation Map
    Please Avoid To Change Roles If You Did Not Trace The Specific Role
    First Trace With Debug Role Then Add Role Here As Action
    Do Not Forget To Add Your Role Into PRM And Number of RELATION 
*/

#define MAX_RELATION 8 // Change it if you add roles


/* Roles :
    [NULL,NULL,NULL] ---> EveryThings (Deny Anything)
    [X,NULL,NULL] ---> Focus on process (More Strict On Process)
    [X,X,NULL] ---> Focus on process and parent (More Middle User-Space service like bash , zsh , fish , ssh, ...)
    [X,NULL,X] ---> Focus on process and grand-parent (Any Isolation Level with docker , kvm , ... Restrict to process)
    [NULL,X,NULL] ---> Focus on parent (High Strict Any process just Parent more focuse on exploits ...)
    [NULL,X,X] ---> Focus on parent and grand-parent (High Strict Any root Isolation level apptainer , singolarity ...) 
    [NULL,NULL,X] ---> Focus on grand-parent (High focus on Isolation)
    [X,X,X] ---> Focus On This pattern (For specific pattern which is knownable)
*/


// direct hit roles
#define RELATION_1 {NULL,PREFIX_BASH,NULL}
#define RELATION_2 {NULL,PREFIX_FISH,NULL} 
#define RELATION_3 {NULL,PREFIX_SSH,NULL}
#define RELATION_4 {NULL,PREFIX_ZSH,NULL}
// isolation level docker
#define RELATION_5 {PREFIX_PYTHON, PREFIX_SH, "containerd-shim"}
// isolation level slurm
#define RELATION_6 {PREFIX_PYTHON, PREFIX_BASH, "slurm_script"}
// High Strict isolation level docker
#define RELATION_7 {NULL, NULL, "containerd-shim"}
// High Strict slurm script level
#define RELATION_8 {NULL, NULL, "slurm_script"}



// Rendarable Roles //
#define PRM RELATION_1, \
            RELATION_3, \
            RELATION_4, \
            RELATION_5, \
            RELATION_6, \
            RELATION_7, \
            RELATION_8

#endif