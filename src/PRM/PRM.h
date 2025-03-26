#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM
#define FILTERING_SYSCALL_FRAMEWORK_PRM

/*  Mojtaba, 
    This Is PRM , Process Relation Map
    Please Avoid To Change Roles If You Did Not Trace The Specific Role
    First Trace With Debug Role Then Add Role Here As Action
    Do Not Forget To Add Your Role Into PRM And Number of RELATION
    If you make your role but forget to add it to PRM , it is suppose not to count
*/

#define MAX_RELATION 8 // Change it if you add roles


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



// Rendarable Roles //
#define PRM RELATION_1, \
            RELATION_2, \
            RELATION_3, \
            RELATION_4, \
            RELATION_5, \
            RELATION_6, \
            RELATION_7, \
            RELATION_8, \


#endif