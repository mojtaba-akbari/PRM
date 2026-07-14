#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM
#define FILTERING_SYSCALL_FRAMEWORK_PRM

/*  Mojjjak, 
    This Is PRM , Process Relation Map , I hope you are able to create your pattern ;)



    PRM Table Page Size ---> 300 Record
    Number Of PRM Tables ---> 1
    Process Relation Names ---> 16 Chars
    
    Notice: Without enough tracing never add roles !!!
    Notice: Dynamic Orders , Take care of order which you put the roles, Performance significantly is related sorted out rules
*/

/* Structure:
    
    PREFIX, PREFIX, PREFIX, ACTION, REDIRECT-INDEX(0<= x <=MAX_NUMBER_OF_RELATION-1), PROTECTED-ZONE(0-1) (Or in Pattern-Style the prog numbers), Hooks(0-N) (0 Means do not care)

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
    ACCEPT, ---> Accept Matched Syscall (Direct Accept)
    REJECT, ---> Reject Matched Syscall (Direct Reject)
    REDIRECT, ---> Redirect to another role , * it (must) be higher than current role index , otherwise Redirect on current index causes Syscall being accepted
    RETURN, ---> Return to the next prog , use RedirectIndex(0-32) , make sure the prog has been defined already, we have predefined prog (refers to development progress) (user RETURN 0 for any kind of test)
    BYPASS, ---> Bypass Matched Roles , (low overhead)
    END,   ---> End of checking (forcefully)
   
   Redirect:
    0 <= X <= 299

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
    CRED_PREPARE, ---> Index 30
    SOCKET_ACCEPT,
    KERNEL_MODULE_REQUEST,
    CAPABLE

   __BYPASS__:
    NOTHING,
    LOWER,
    NORMAL,
    EXTERA,
    HIGH,
    VERBOSE

    KERNEL_HOOKS_BYPASS ---> bypass all kernel hooks (performance improving)

*/

#define MAX_NUMBER_OF_RELATION 300

#define KERNEL_HOOKS_BYPASS 1
 
#define __DEBUG__ (LOWER)



// ********************************************************************************//
// 
// 

//   _    _ _____   _____ 
//  | |  | |  __ \ / ____|
//  | |__| | |__) | |     
//  |  __  |  ___/| |     
//  | |  | | |    | |____ 
//  |_|  |_|_|     \_____|
//
                                           
// 
// Mojjjak
// ********************************************************************************//


#define RELATION_0 PREFIX_NOCARE, PREFIX_NOCARE, PREFIX_NOCARE, BYPASS, 0,0,0 // FIX IT WHEN YOU NEED TO (BYPASS) OR CHANGE IT TO (BYPASS)

#define RELATION_1 "systemd", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // if you have any other system daemon manager add it here | TEST-PASSED

#define RELATION_2 "NetworkManager", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // Network kit , if you have other kit put it here , usually it is placed /usr/sbin/NetworkManager| TEST-PASSED

#define RELATION_3 "irqbalance", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // Balancer

#define RELATION_4 "nm-dispatcher", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // Network Manager Dispatcher | TEST-PASSED

#define RELATION_5 "systemd-udevd", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // udevd , if you have anything else replace it or add a new one, comes from systemd or , ... | TEST-PASSED

#define RELATION_6 "systemd-logind", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // systemd login manager | TEST-PASSED develop config to allow some binary from container 

#define RELATION_7 "systemd-journal", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // Journal if you have 

#define RELATION_8 "runc", "containerd-shim", PREFIX_NOCARE, ACCEPT, 0,0,0 // just runc ! the end service can be containerd, systemd , .... | TEST-PASSED

#define RELATION_9 "runc", "runc", "containerd-shim", ACCEPT, 0,0,0 // any kind of spawn from runc , runc:[2:INIT], ... | TEST-PASSED

#define RELATION_10 "containerd-shim", "containerd", PREFIX_NOCARE, ACCEPT, 0,0,0 // the end service can be containerd, systemd , .... | TEST-PASSED

#define RELATION_11 "containerd", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // containerd fork | TEST-PASSED

#define RELATION_12 "starter", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // apptainer fork | TEST-PASSED

#define RELATION_13 "20-chrony-dhcp", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // DHCP process 

#define RELATION_14 "chronyd", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // Chrony

#define RELATION_15 "slurmstepd", "slurmstepd", "systemd", ACCEPT, 0,0,0 // Slurm Job Manager , any kind of spawn from slurmstepd | TEST-PASSED

#define RELATION_16 "sshd", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // SSHD internal deamon | TEST-PASSED

// ─── FREE SLOTS FOR ACCEPT RULES (17-56) ─── //


// --- FREE SLOTS FOR ACCEPT RULES (17-56) --- //
#define RELATION_17 "prm-loader", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // PRM loader via SSH session | TEST-PASSED
#define RELATION_18 "prm-loader", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // PRM loader via sh (ansible) | TEST-PASSED
#define RELATION_19 "gpg", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // GPG token verification (child of prm-loader only) | Mojjjak , it is a little bit weird !
#define RELATION_20 "sshd-session", PREFIX_NOCARE, PREFIX_NOCARE, ACCEPT, 0,0,0 // SSHD internal session deamon *** Be-aware after openssh 9.x they seperate sshd and sshd-session due to solve the permission problem | TEST-PASSED 
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
#define RELATION_50 EMPTY
#define RELATION_51 EMPTY
#define RELATION_52 EMPTY
#define RELATION_53 EMPTY
#define RELATION_54 EMPTY
#define RELATION_55 EMPTY
#define RELATION_56 EMPTY

// --- BLOCKED PROCESSES (57-76) --- //
#define RELATION_57 "systemd-run", "bash", PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_58 "ruby", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_59 "lua", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_60 "node", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_61 "php", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_62 "tclsh", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_63 "expect", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_64 "r", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_65 "julia", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_66 "gdb", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_67 "strace", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_68 "ptrace", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_69 "netcat", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_70 "nmap", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_71 "socat", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_72 "perl", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_73 "ksh", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_74 "fish", PREFIX_NOCARE, PREFIX_NOCARE, REJECT, 0,0,0
#define RELATION_75 EMPTY
#define RELATION_76 EMPTY

// --- FREE SLOTS FOR REJECT RULES (77-108) --- //
#define RELATION_77 EMPTY
#define RELATION_78 EMPTY
#define RELATION_79 EMPTY
#define RELATION_80 EMPTY
#define RELATION_81 EMPTY
#define RELATION_82 EMPTY
#define RELATION_83 EMPTY
#define RELATION_84 EMPTY
#define RELATION_85 EMPTY
#define RELATION_86 EMPTY
#define RELATION_87 EMPTY
#define RELATION_88 EMPTY
#define RELATION_89 EMPTY
#define RELATION_90 EMPTY
#define RELATION_91 EMPTY
#define RELATION_92 EMPTY
#define RELATION_93 EMPTY
#define RELATION_94 EMPTY
#define RELATION_95 EMPTY
#define RELATION_96 EMPTY
#define RELATION_97 EMPTY
#define RELATION_98 EMPTY
#define RELATION_99 EMPTY
#define RELATION_100 EMPTY
#define RELATION_101 EMPTY
#define RELATION_102 EMPTY
#define RELATION_103 EMPTY
#define RELATION_104 EMPTY
#define RELATION_105 EMPTY
#define RELATION_106 EMPTY
#define RELATION_107 EMPTY
#define RELATION_108 EMPTY

// --- HOOK REDIRECTS (109-119) --- //
// These redirect specific syscall types to the protected zone for deep inspection
#define RELATION_109 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,290 ,0 ,19 // KILL SIG -> zone 290
#define RELATION_110 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,2 ,9 // INODE CREATE -> Prog 2
#define RELATION_111 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,3 ,15 // SOCKET CONNECT -> Prog 3
#define RELATION_112 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,4 ,16 // EXEC PROGRAM -> Prog 4
#define RELATION_113 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,5 ,3 // MEMORY PROTECT -> Prog 5
#define RELATION_114 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,6 ,31 // SOCKET ACCEPT -> Prog 6
#define RELATION_115 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,7 ,6 // FILE OPEN -> Prog 7
#define RELATION_116 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,8 ,32 // MODULE LOAD -> Prog 8
#define RELATION_117 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,9 ,30 // CRED PREPARE -> Prog 9
#define RELATION_118 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,10 ,33 // CAPABLE -> Prog 10
#define RELATION_119 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,121 ,11 ,29 // CRED FIX -> Prog 11

// --- END OF STATIC TABLE --- //

#define RELATION_120 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,END ,0 ,0 ,0 // End of static table, everything reaching here is accepted





// <<<>>> Protected Zone starts here (reached only via REDIRECT) //
// Pattern - 1 - HPC Comprehensive //
#define RELATION_121 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,DEBUG ,0 ,1 ,0

#define RELATION_122 "|slurmstepd", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_123 "|slurmd", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_124 "|containerd-shim", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_125 "|singularity", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_126 "|apptainer", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_127 "|runc", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_128 "|starter-suid", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0

// Shells (Symmetric)
#define RELATION_129 "|bash", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_130 "|sh", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_131 "|dash", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_132 "|zsh", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_133 "|csh", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_134 "|tcsh", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0

// Interpreters (Symmetric)
#define RELATION_135 "|python", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_136 "|python2", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_137 "|python3", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0

// HPC Utilities (Symmetric)
#define RELATION_138 "|mpirun", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_139 "|mpiexec", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_140 "|srun", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_141 "|sbatch", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0

// System Utilities (Symmetric)
#define RELATION_142 "|env", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_143 "|xargs", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_144 "|find", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_145 "|make", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_146 "|sudo", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_147 "|su", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0

// Editors (Symmetric)
#define RELATION_148 "|vim", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_149 "|vi", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_150 "|emacs", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_151 "|nano", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0

// SSH/Remote (Symmetric)
#define RELATION_152 "|sshd", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0

// Cron (Symmetric)
#define RELATION_153 "|cron", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0
#define RELATION_154 "|crond", PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,0 ,1 ,0

#define RELATION_155 PREFIX_INVALID_BINARY, PREFIX_INVALID_BINARY, PREFIX_INVALID_BINARY, RETURN, 0, 1, 0

// End of Pattern (self-redirect = accept)
#define RELATION_156 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,156 ,1 ,0

#define RELATION_157 EMPTY

#define RELATION_158 EMPTY

#define RELATION_159 EMPTY

#define RELATION_160 EMPTY

#define RELATION_161 EMPTY

#define RELATION_162 EMPTY

#define RELATION_163 EMPTY

#define RELATION_164 EMPTY

#define RELATION_165 EMPTY

#define RELATION_166 EMPTY

#define RELATION_167 EMPTY

#define RELATION_168 EMPTY

#define RELATION_169 EMPTY

#define RELATION_170 EMPTY

#define RELATION_171 EMPTY

#define RELATION_172 EMPTY

#define RELATION_173 EMPTY

#define RELATION_174 EMPTY

#define RELATION_175 EMPTY

#define RELATION_176 EMPTY

#define RELATION_177 EMPTY

#define RELATION_178 EMPTY

#define RELATION_179 EMPTY

#define RELATION_180 EMPTY

#define RELATION_181 EMPTY

#define RELATION_182 EMPTY

#define RELATION_183 EMPTY

#define RELATION_184 EMPTY

#define RELATION_185 EMPTY

#define RELATION_186 EMPTY

#define RELATION_187 EMPTY

#define RELATION_188 EMPTY

#define RELATION_189 EMPTY

#define RELATION_190 EMPTY

#define RELATION_191 EMPTY

#define RELATION_192 EMPTY

#define RELATION_193 EMPTY

#define RELATION_194 EMPTY

#define RELATION_195 EMPTY

#define RELATION_196 EMPTY

#define RELATION_197 EMPTY

#define RELATION_198 EMPTY

#define RELATION_199 EMPTY

#define RELATION_200 EMPTY

#define RELATION_201 EMPTY

#define RELATION_202 EMPTY

#define RELATION_203 EMPTY

#define RELATION_204 EMPTY

#define RELATION_205 EMPTY

#define RELATION_206 EMPTY

#define RELATION_207 EMPTY

#define RELATION_208 EMPTY

#define RELATION_209 EMPTY

#define RELATION_210 EMPTY

#define RELATION_211 EMPTY

#define RELATION_212 EMPTY

#define RELATION_213 EMPTY

#define RELATION_214 EMPTY

#define RELATION_215 EMPTY

#define RELATION_216 EMPTY

#define RELATION_217 EMPTY

#define RELATION_218 EMPTY

#define RELATION_219 EMPTY

#define RELATION_220 EMPTY

#define RELATION_221 EMPTY

#define RELATION_222 EMPTY

#define RELATION_223 EMPTY

#define RELATION_224 EMPTY

#define RELATION_225 EMPTY

#define RELATION_226 EMPTY

#define RELATION_227 EMPTY

#define RELATION_228 EMPTY

#define RELATION_229 EMPTY

#define RELATION_230 EMPTY

#define RELATION_231 EMPTY

#define RELATION_232 EMPTY

#define RELATION_233 EMPTY

#define RELATION_234 EMPTY

#define RELATION_235 EMPTY

#define RELATION_236 EMPTY

#define RELATION_237 EMPTY

#define RELATION_238 EMPTY

#define RELATION_239 EMPTY

#define RELATION_240 EMPTY

#define RELATION_241 EMPTY

#define RELATION_242 EMPTY

#define RELATION_243 EMPTY

#define RELATION_244 EMPTY

#define RELATION_245 EMPTY

#define RELATION_246 EMPTY

#define RELATION_247 EMPTY

#define RELATION_248 EMPTY

#define RELATION_249 EMPTY

#define RELATION_250 EMPTY

#define RELATION_251 EMPTY

#define RELATION_252 EMPTY

#define RELATION_253 EMPTY

#define RELATION_254 EMPTY

#define RELATION_255 EMPTY

#define RELATION_256 EMPTY

#define RELATION_257 EMPTY

#define RELATION_258 EMPTY

#define RELATION_259 EMPTY

#define RELATION_260 EMPTY

#define RELATION_261 EMPTY

#define RELATION_262 EMPTY

#define RELATION_263 EMPTY

#define RELATION_264 EMPTY

#define RELATION_265 EMPTY

#define RELATION_266 EMPTY

#define RELATION_267 EMPTY

#define RELATION_268 EMPTY

#define RELATION_269 EMPTY

#define RELATION_270 EMPTY

#define RELATION_271 EMPTY

#define RELATION_272 EMPTY

#define RELATION_273 EMPTY

#define RELATION_274 EMPTY

#define RELATION_275 EMPTY

#define RELATION_276 EMPTY

#define RELATION_277 EMPTY

#define RELATION_278 EMPTY

#define RELATION_279 EMPTY

#define RELATION_280 EMPTY

#define RELATION_281 EMPTY

#define RELATION_282 EMPTY

#define RELATION_283 EMPTY

#define RELATION_284 EMPTY

#define RELATION_285 EMPTY

#define RELATION_286 EMPTY

#define RELATION_287 EMPTY

#define RELATION_288 EMPTY

#define RELATION_289 EMPTY

#define RELATION_290 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,BYPASS ,0 ,1 ,19

#define RELATION_291 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,RETURN ,1 ,1 ,19

#define RELATION_292 PREFIX_NOCARE, PREFIX_NOCARE ,PREFIX_NOCARE ,REDIRECT ,292 ,1 ,19

#define RELATION_293 EMPTY

#define RELATION_294 EMPTY

#define RELATION_295 EMPTY

#define RELATION_296 EMPTY

#define RELATION_297 EMPTY

#define RELATION_298 EMPTY

#define RELATION_299 EMPTY

#endif