#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM
#define FILTERING_SYSCALL_FRAMEWORK_PRM

/*  Mojtaba, 
    This Is PRM , Process Relation Map , I hope you are able to create your pattern ;)



    PRM Table Page Size ---> 5 * Process Relation
    Number Of PRM Tables ---> 1 - 8 (Ordered) (If you want to check order faster put it by order --- it improves our performance)
    Process Relation Names ---> 16 * Byte (extra bytes are eliminated)
    
    Notice: Without enough tracing never add roles !!!
    Notice: Dynamic Orders , Take care of order which you put the roles
*/

/* Structure:
    
    PREFIX, PREFIX, PREFIX, ACTION, REDIRECT-INDEX(0<= x <=MAX_NUMBER_OF_RELATION-1), PROTECTED-ZONE(0-1), Hooks(0-N) (0 Means do not care)

    Notice: Protected zone define specific zone for checking more roles , just only with REDIRECT action you can jump there and check those roles otherwise 
            Protected zone flag true(1) never checks

   Roles :
    (X) means knownable process,  PREFIX_NOCARE means everything (*)

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
    RETURN, ---> Return to the next prog , use RedirectIndex(0-32) , make sure the prog has been defined already, we have predefined prog (refers to development progress) (user RETURN 0 for any kind of test)
    DEBUG, ---> Debug Matched Roles , (low overhead)
   
   Redirect:
    0 <= X <= 99

   Protect-Zone:
    Protected ---> 1
    Unprotected ---> 0
   
   Hooks:
    FILE_PERMISSION, ---> Index 1
    FILE_IOCTL,
    FILE_MPROTECT,
    FILE_RECEIVE,
    FILE_SIGIOTASK,
    FILE_OPEN,
    SB_MOUNT,
    SHM_ALLOC,
    INODE_CREATE,
    INODE_PERMISSION, ---> Index 10
    INODE_SETATTR,
    INODE_MKDIR,
    SYSLOG,
    SOCKET_CREATE,
    SOCKET_CONNECT,
    BPRM_SECURITY,
    BPF,
    SECURITY_CAPGET,
    TASK_KILL,
    TASK_ALLOC, ---> Index 20
    TASK_MOVEMEMORY,
    TASK_PTRACE,
    TASK_SETPGID,
    TASK_GETGID,
    TASK_GETSID,
    TASK_PRLIMIT,
    TASK_SETPRLIMIT,
    TASK_SETIOPRIO,
    TASK_FIX_SETUID,
    CRED_PREPARE ---> Index 30

   __DEBUG__:
    NOTHING,
    LOWER,
    NORMAL,
    EXTERA,
    HIGH,
    VERBOSE
*/

#define MAX_NUMBER_OF_RELATION 150

#define __DEBUG__ (NORMAL|LOWER)




// ********************************************************************************//

// KILL SIG Prog Zone //
#define RELATION_0 "k8m3x7q1wz", "v5n9b2c6hy", "r4j8s1t0xl", RETURN, 1, 0, 19 // KILL SIG

// INODE CREATE Prog Zone //
#define RELATION_1 "p2h6k9m4qx", "w7z1v3n8by", "f0r5j2s6tl", RETURN, 2, 0, 9 // INODE CREATE

// SOCKET-OPEN Prog Zone //
#define RELATION_2 "q3w8e1r5ty", "a9s4d7f2gh", "z6x0c5v3bn", RETURN, 3, 0, 15 // SOCKET

// EXECV Prog Zone //
#define RELATION_3 "m7n4b1v8cx", "l2k5j9h6gf", "p3q0w7e4rt", RETURN, 4, 0, 16 // EXECV

// MEMORY PROC Prog Zone //
#define RELATION_4 "y8u2i5o9pa", "s6d1f4g7hj", "k0l3z9x5cv", RETURN, 5, 0, 3 // MEM PROC

#define RELATION_5 "xk7m9p2qwz", "n4v8b1c5hy", "r3j6s0t9xl", RETURN, 1, 0, 19

#define RELATION_6 "f2h8k4m7qx", "w9z3v6n1by", "p5r0j8s2tl", RETURN, 2, 0, 9

#define RELATION_7 "q1w5e9r3ty", "a7s2d6f0gh", "z4x8c3v7bn", RETURN, 3, 0, 15

#define RELATION_8 "m6n2b9v5cx", "l3k7j1h4gf", "p0q8w4e6rt", RETURN, 4, 0, 16

#define RELATION_9 "y5u8i2o6pa", "s1d4f7g0hj", "k9l3z6x2cv", RETURN, 5, 0, 3

#define RELATION_10 "b3n7m1k5jh", "g9f2d6s0aq", "w8e4r7t1yu", RETURN, 1, 0, 19

#define RELATION_11 "i6o0p3a7sl", "d2f5g8h1jk", "l4z7x9c6vb", RETURN, 2, 0, 9

#define RELATION_12 "n8m2k6j4hg", "f1d5s9a3qw", "e7r0t4y8ui", RETURN, 3, 0, 15

#define RELATION_13 "o2p6a0s4df", "g8h1j5k9lz", "x3c7v1b5nm", RETURN, 4, 0, 16

#define RELATION_14 "q4w8e2r6ty", "u9i3o7p1as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_15 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_16 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_17 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_18 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_19 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_20 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_21 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_22 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_23 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_24 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_25 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_26 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_27 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_28 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_29 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_30 "b1n5m8k2jh", "g4f7d3s6aq", "w9e0r2t5yu", RETURN, 1, 1, 19

#define RELATION_31 "i3o7p1a4sl", "d8f2g5h9jk", "l6z3x0c7vb", RETURN, 1, 1, 19

#define RELATION_32 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_33 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_34 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_35 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_36 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_37 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_38 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_39 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_40 "n0m4k7j2hg", "f5d8s1a6qw", "e3r9t6y2ui", RETURN, 2, 1, 9

#define RELATION_41 "o4p8a2s5df", "g1h6j0k3lz", "x7c2v9b1nm", RETURN, 2, 1, 9

#define RELATION_42 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_43 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_44 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_45 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_46 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_47 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_48 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_49 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_50 "q6w0e4r8ty", "u2i7o1p5as", "d9f3g7h4jk", RETURN, 3, 1, 15

#define RELATION_51 "l8z2x6c0vb", "n5m1k4j7hg", "f3d6s9a2qw", RETURN, 5, 1, 15

#define RELATION_52 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_53 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_54 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_55 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_56 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_57 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_58 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_59 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_60 "e7r1t5y9ui", "o3p6a0s4df", "g8h2j5k1lz", RETURN, 4, 1, 16

#define RELATION_61 "x4c8v2b6nm", "q0w5e9r3ty", "u7i1o4p8as", RETURN, 5, 1, 16

#define RELATION_62 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_63 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_64 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_65 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_66 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_67 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_68 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_69 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_70 "d2f6g0h4jk", "l9z3x7c1vb", "n6m0k3j8hg", RETURN, 5, 1, 3

#define RELATION_71 "f5d9s3a7qw", "e1r4t8y2ui", "o6p0a3s7df", RETURN, 3, 1, 3

#define RELATION_72 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_73 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_74 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_75 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_76 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_77 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_78 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_79 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_80 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_81 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_82 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_83 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_84 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_85 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_86 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_87 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_88 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_89 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_90 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_91 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_92 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_93 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_94 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_95 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_96 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_97 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_98 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_99 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_100 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_101 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_102 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_103 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_104 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_105 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_106 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_107 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_108 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_109 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_110 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_111 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_112 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_113 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_114 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_115 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_116 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_117 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_118 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_119 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_120 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_121 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_122 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_123 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_124 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_125 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_126 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_127 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_128 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_129 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_130 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_131 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_132 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_133 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_134 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_135 "l6z0x4c8vb", "n2m6k0j4hg", "f8d2s6a0qw", RETURN, 1, 0, 19

#define RELATION_136 "e4r8t2y6ui", "o0p4a8s2df", "g6h0j4k8lz", RETURN, 2, 0, 9

#define RELATION_137 "x2c6v0b4nm", "q8w2e6r0ty", "u4i8o2p6as", RETURN, 3, 0, 15

#define RELATION_138 "d0f4g8h2jk", "l6z0x4c8vb", "n2m6k0j4hg", RETURN, 4, 0, 16

#define RELATION_139 "f8d2s6a0qw", "e4r8t2y6ui", "o0p4a8s2df", RETURN, 5, 0, 3

#define RELATION_140 "g6h0j4k8lz", "x2c6v0b4nm", "q8w2e6r0ty", RETURN, 1, 0, 19

#define RELATION_141 "u4i8o2p6as", "d0f4g8h2jk", "l6z0x4c8vb", RETURN, 2, 0, 9

#define RELATION_142 "n2m6k0j4hg", "f8d2s6a0qw", "e4r8t2y6ui", RETURN, 3, 0, 15

#define RELATION_143 "o0p4a8s2df", "g6h0j4k8lz", "x2c6v0b4nm", RETURN, 4, 0, 16

#define RELATION_144 "q8w2e6r0ty", "u4i8o2p6as", "d0f4g8h2jk", RETURN, 5, 0, 3

#define RELATION_145 PREFIX_NOCARE, PREFIX_NOCARE, PREFIX_NOCARE, RETURN, 1, 0, 19

#define RELATION_146 PREFIX_NOCARE, PREFIX_NOCARE, PREFIX_NOCARE, RETURN, 2, 0, 9

#define RELATION_147 PREFIX_NOCARE, PREFIX_NOCARE, PREFIX_NOCARE, RETURN, 3, 0, 15

#define RELATION_148 PREFIX_NOCARE, PREFIX_NOCARE, PREFIX_NOCARE, RETURN, 4, 0, 16

#define RELATION_149 PREFIX_NOCARE, PREFIX_NOCARE, PREFIX_NOCARE, RETURN, 5, 0, 3

#endif