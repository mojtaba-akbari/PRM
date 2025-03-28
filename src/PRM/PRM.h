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

#define MAX_NUMBER_OF_RELATION 80

/* Structure:
    PREFIX, PREFIX, PREFIX, ACTION, REDIRECT-INDEX(0<= x <=MAX_NUMBER_OF_RELATION-1), PROTECTED-ZONE(0-1), Syscall-Numbers(0-N)
    Notice: Protected zone define specific zone for checking more roles , just only with REDIRECT action you can jump there and check those roles otherwise 
            Protected zone flag true(1) never checks

   Roles :
    (X) means knownable process, (NULL) means not important or everything or * PREFIX_NOCARE

    {PREFIX_NOCARE,PREFIX_NOCARE,PREFIX_NOCARE} ---> EveryThings (Deny Anything)

    {X,PREFIX_NOCARE,PREFIX_NOCARE} ---> Focus on process (More Strict On Process)

    {X,X,PREFIX_NOCARE} ---> Focus on process and parent (More Middle User-Space service like bash , zsh , fish , ssh, ...)

    {X,PREFIX_NOCARE,X} ---> Focus on process and grand-parent (Any Isolation Level with docker , kvm , ... Restrict to process)

    {PREFIX_NOCARE,X,PREFIX_NOCARE} ---> Focus on parent (High Strict Any process just Parent more focuse on exploits ...)

    {PREFIX_NOCARE,X,X} ---> Focus on parent and grand-parent (High Strict Any root Isolation level apptainer , singolarity ...) 

    {PREFIX_NOCARE,PREFIX_NOCARE,X} ---> Focus on grand-parent (High focus on Isolation)
    
    {X,X,X} ---> Focus On This pattern (For specific pattern which is knownable)

   Actions :
    ACCEPT, ---> Accept Matched Syscall
    REJECT, ---> Reject Matched Syscall
    REDIRECT, ---> Redirect to another role , * it (must) be higher than current role index , otherwise Redirect on current index causes Syscall being accepted
    RETURN, ---> Return to the next prog , use RedirectIndex(0-32) , make sure the prog has been defined already, we have predefined prog (refers to development progress)
    DEBUG, ---> Debug every thing

*/

// Super Direct hit roles
#define RELATION_0 PREFIX_BASH, PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,0 ,0

// High Direct hit roles
#define RELATION_1 PREFIX_BASH, PREFIX_SSH ,PREFIX_NOCARE ,REJECT ,0 ,0 ,0

#define RELATION_2 PREFIX_FISH, PREFIX_NOCARE ,PREFIX_NOCARE ,REJECT ,0 ,0 ,0

#define RELATION_3 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_SSH ,REJECT ,0 ,0 ,0

#define RELATION_4 PREFIX_ZSH, PREFIX_NOCARE ,PREFIX_NOCARE ,REJECT ,0 ,0 ,0

// Super Indirect hit roles
#define RELATION_5 PREFIX_NOCARE, PREFIX_BASH ,PREFIX_NOCARE ,REJECT ,0 ,0 ,0

#define RELATION_6 PREFIX_NOCARE, PREFIX_FISH ,PREFIX_NOCARE ,REJECT ,0 ,0 ,0

#define RELATION_7 PREFIX_NOCARE, PREFIX_ZSH ,PREFIX_NOCARE ,REJECT ,0 ,0 ,0

// Focus on python slurmstepd script level
#define RELATION_8 PREFIX_PYTHON, PREFIX_NOCARE ,"slurmstepd" ,REJECT ,0 ,0 ,0

// Focus on bash slurmstepd script level
#define RELATION_9 PREFIX_BASH, PREFIX_NOCARE ,"slurmstepd" ,REJECT ,0 ,0 ,0

// High Strict slurmstepd script level
#define RELATION_10 PREFIX_NOCARE, PREFIX_NOCARE ,"slurmstepd" ,REJECT ,0 ,0 ,0

// If Found Any containerd - docker Redirect To Docker Zone
#define RELATION_11 PREFIX_NOCARE, "containerd-shim" ,PREFIX_NOCARE ,REDIRECT ,46 ,0 ,0

#define RELATION_12 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_SH ,REJECT ,0 ,0 ,0

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

// Docker Protect Zone , Focus More To Strict it
#define RELATION_50 "runc", "containerd-shim" , PREFIX_NOCARE ,REJECT ,0 ,1 ,0

#define RELATION_51 PREFIX_PYTHON, "containerd-shim" , PREFIX_NOCARE ,REJECT ,0 ,1 ,0

#define RELATION_52 PREFIX_NOCARE, "containerd-shim" ,PREFIX_NOCARE ,REDIRECT ,52 ,1 ,0

#define RELATION_53 EMPTY

#define RELATION_54 EMPTY

#define RELATION_55 EMPTY

#define RELATION_56 EMPTY

#define RELATION_57 EMPTY

#define RELATION_58 EMPTY

#define RELATION_59 EMPTY

#define RELATION_60 EMPTY

#define RELATION_61 EMPTY

#define RELATION_62 EMPTY

#define RELATION_63 EMPTY

#define RELATION_64 EMPTY

#define RELATION_65 EMPTY

#define RELATION_66 EMPTY

#define RELATION_67 EMPTY

#define RELATION_68 EMPTY

#define RELATION_69 EMPTY

#define RELATION_70 EMPTY

#define RELATION_71 EMPTY

#define RELATION_72 EMPTY

#define RELATION_73 EMPTY

#define RELATION_74 EMPTY

#define RELATION_75 EMPTY

#define RELATION_76 EMPTY

#define RELATION_77 EMPTY

#define RELATION_78 EMPTY

#define RELATION_79 EMPTY

#endif