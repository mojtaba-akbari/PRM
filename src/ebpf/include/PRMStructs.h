#ifndef FILTERING_SYSCALL_FRAMEWORK_STRUCTS
#define FILTERING_SYSCALL_FRAMEWORK_STRUCTS

#include "../conf/PRM.h"
#include "baseheaders.h"
#include "BTFFunctions.h"

// Mojtaba :) , The Structures Notice never change till you know what you are doing here // ***
// Use Stack Programming To Design The Whole PRM //
// Stack Is Faster Than BFP Helper Calls For Allocating Data //
// Here The Structure Is Between 512 Byte Allocation , So I Would Prefer Develop It As Stack //
// Try to make hook enum because of any tasks comprise more than 2 or 3 differ syscalls , as well as differ linux distro //

#ifndef MAGIC_VALUE
    #define MAGIC_VALUE 0xDEADBEEF
#endif

#define MAX_CACHE_ENTRIES 5

#define RET_ACCEPT return 0;
#define RET_REJECT return 1;
#define RET_ACCEPT_FORCEFULLY return 2;

struct cache_entry{
    __u32 hash; // hash fingerprint
    bool is_valid: 1;
};

struct cache_record{
    __s8 direct_relation;
    bool is_valid_entries : 1;
    __u8 active_entries;
    __u8 prog_tb_id; // program table id
    struct cache_entry cache_entries[MAX_CACHE_ENTRIES];
};

enum PRM_DEBUG_LEVEL_ENUM{
    NOTHING = 0,
    LOWER = 1 << 0,
    NORMAL = 1 << 1,
    EXTERA = 1 << 2,
    HIGH = 1 << 3, 
    VERBOSE = 1 << 4
};

enum PRM_HOOK_ENUM{
    NONE_CELL,
    FILE_PERMISSION,
    FILE_IOCTL,
    FILE_MPROTECT,
    FILE_RECEIVE,
    FILE_SIGIOTASK,
    FILE_OPEN,
    SB_MOUNT,
    SHM_ALLOC,
    INODE_CREATE,
    INODE_PERMISSION,
    INODE_SETATTR,
    INODE_MKDIR,
    SYSLOG,
    SOCKET_CREATE,
    SOCKET_CONNECT,
    BPRM_SECURITY,
    BPF,
    SECURITY_CAPGET,
    TASK_KILL,
    TASK_ALLOC,
    TASK_MOVEMEMORY,
    TASK_PTRACE,
    TASK_SETPGID,
    TASK_GETGID,
    TASK_GETSID,
    TASK_PRLIMIT,
    TASK_SETPRLIMIT,
    TASK_SETIOPRIO,
    TASK_FIX_SETUID,
    CRED_PREPARE,
    SOCKET_ACCEPT,
    KERNEL_MODULE_REQUEST,
    CAPABLE
};

enum PRM_STATE_ENUM {
    UNLOADED,
    STARTUP,
    LOADED,
    BROKEN,
    TOO_MANY_ROLES,
    NON_OF_GENERAL_ROLE
};

struct SelfPID {
    __u32 pid; 
    __u64 magic;
};

struct taskUKey{
    __u64 tgid;
    char comm[LARGE_STR];
    __u64 startTime;
};

struct execPath{
    __s8 startIndex; // Improves performance 
    bool isContainerTask;
    bool isValidDirectory;
    char exec[MAX_DIR_ITR][MAX_STR]; // This array will be filled out from end ! make sure you point out the first index with StartIndex! Performance is so important! Mojjjak
    //char fullExecPath[MAX_DIR_ITR*MAX_STR]; // For fast access , improves performance , fix me in next iteration , i have no time for fixing this now !
};

struct UniqueKey {
    __u32 pid; // process id
    __u32 tpid; // thread id
    enum PRM_HOOK_ENUM hook; // syscall
    struct cache_record crecord; // cache records
};

// Do not forget , Add Context Struct for your Prog //
// Implement me more --> Mojtaba :)
struct args_inode_create_t {
    struct path *dir;
    struct dentry *dentry;
    int flags;
    umode_t mode;
};

struct args_socket_create_t{
    int family;
    int type;
    int protocol;
    int kern;
};

struct args_socket_connect_t{
    struct socket *sock;
    struct sockaddr *address;
    int addrlen;
};

struct args_file_open_t {
    struct file *file;
};

struct args_bprm_check_security_t{
    struct linux_binprm *bprm;
};

struct args_file_mprotect_t{
    struct vm_area_struct *vma;
    unsigned long reqprot;
    unsigned long prot;
};

struct args_task_kill_t{
    struct task_struct *task;
    struct kernel_siginfo *info;
    int sig;
    const struct cred *cred;
};

struct args_socket_accept_t{
    struct socket *sock;
    struct socket *newsock;
};

struct args_kernel_module_request_t{
    char *kmod_name;
};

struct args_cred_prepare_t{
    struct cred *new;
    struct cred *old;
    int flags;
};

struct args_capable_t{
    const struct cred *cred; 
    struct user_namespace *ns; 
    int cap;
    unsigned int opts;
};

struct args_task_fix_set_t{
    struct task_struct *task;
    const struct cred *old;
    const struct cred *new;
    unsigned int flags;
};

union lsm_args_u {
    struct args_file_open_t file_open;
    struct args_inode_create_t inode_create;
    struct args_task_kill_t task_kill;
    struct args_socket_create_t socket_create;
    struct args_socket_connect_t socket_connect;
    struct args_bprm_check_security_t bprm_check_security;
    struct args_file_mprotect_t file_mprotect;
    struct args_socket_accept_t socket_accept;
    struct args_kernel_module_request_t kernel_module_request;
    struct args_cred_prepare_t cred_prepare;
    struct args_capable_t capable;
    struct args_task_fix_set_t task_fix_set;
};

struct hooks_context_t{
    struct task_struct *task;
    struct task_struct *task_parent;
    struct task_struct *task_grandparent;

    struct taskUKey taskUKey;
    struct taskUKey taskUKeyParent;
    struct taskUKey taskUKeyGrandParent;
    
    struct UniqueKey key;

    __u32 uid;

    union lsm_args_u args;
};

struct prm_state {
    enum PRM_STATE_ENUM prm_state;
};

enum PROCESS_RELATION_ACTION_ENUM{
    NONE_ACTION,
    ACCEPT,
    REJECT,
    REDIRECT,
    PATTERN,
    DEBUG,
    BYPASS,
    RETURN,
    END
};

struct process_relation {
    char process[MAX_RELATION_PROCESSNAME];
    char parent[MAX_RELATION_PROCESSNAME];
    char grandparent[MAX_RELATION_PROCESSNAME];
    enum PROCESS_RELATION_ACTION_ENUM action;
    __u32 redirectIndex;
    int protectZone;
    enum PRM_HOOK_ENUM hookType;
    // Hash fields for fast comparison (added at end for compatibility)
    __u32 process_hash;
    __u32 parent_hash;
    __u32 grandparent_hash;
    bool is_symmetric : 1; // Symmetric rule flag
    __u32 symmetric_hash; // Single hash for symmetric matching
};

struct process_entry{
    __u32 pid;
    enum PRM_HOOK_ENUM hook;
};

struct empty_buffer{
    char _buff_[HUGE_STR];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_NUMBER_OF_RELATION);
    __type(key, u32);
    __type(value, struct process_relation);
} prm_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PRM_STATE);
    __type(key, __u32);
    __type(value, struct prm_state);
} prm_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SELF_PIDS);
    __type(key, u32);
    __type(value, struct {__u32 pid;__u64 magic;});
    __uint(map_flags, BPF_F_LOCK);
} self_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, ALLOWED_PIDS);  
    __type(key, struct UniqueKey);
    __type(value, struct cache_record); 
} process_list SEC(".maps");

// Blacklist for instant rejection - stores cache_record with hash fingerprints
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct UniqueKey);  // {pid, tpid, hook}
    __type(value, struct cache_record); // hash fingerprints like whitelist
} blacklist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 748);
    __type(key, struct taskUKey);
    __type(value, struct execPath); 
} execPath_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 748);
    __type(key, __u32);
    __type(value, struct empty_buffer);
} tmp_buffer_ SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 32);
    __type(key, __u32);
    __type(value, char[EXPLOSIVE_STR]);
} tmp_buffer_512B SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct hooks_context_t);
} _ctx_holder_ SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct cache_record);
} _cache_record_holder_ SEC(".maps");



// Lineage //
#define MAX_VECTOR_CELL 4
#define MAX_VECTORS 19


enum UID_VECTOR_ELEM{
    UIDROOT = 0,
    UIDEMPTYCELL = 1,
    UIDWILDCARD= 2,
    UIDMISMATCH = 3
};

enum UID_VECTOR_SEVERITY {
    EASY = 0,             // Not checked or not applicable
    BASE = 1,               // Normal base behavior
    BENIGN = 2,             // Expected, non-privileged action
    LOW_RISK = 3,           // Mildly uncommon, likely okay
    SUSPICIOUS = 4,         // Unusual pattern, worth watching
    ANOMALOUS = 5,          // Unexpected, but unclear intent
    ELEVATED = 6,           // Privilege escalation likely
    ESCALATED = 7,          // Confirmed setuid/sudo jump
    DANGEROUS = 8,          // Likely malicious behavior
    CRITICAL = 9,           // High-confidence exploit
    ROOT_COMPROMISED = 10   // Confirmed root takeover path
};

struct UIDVector {
    __u8 severity;
    __u8 val[MAX_VECTOR_CELL];
};

struct BaseDB {
    struct UIDVector entries[MAX_VECTORS];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VECTORS);
    __type(key, __u32);
    __type(value, struct UIDVector);
} uid_base_map SEC(".maps");


struct UIDVectorAncestors {
    __u8 val[MAX_ANCESTORS];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct UIDVectorAncestors);
} tmp_lineage SEC(".maps");


// Functions definations //
const struct cache_record _emptycacherecord_ SEC(".rodata") = {0};

const struct empty_buffer _emptybuffer_ SEC(".rodata") = {0};

const struct hooks_context_t _emptyctx_ SEC(".rodata") = {0};

const struct UIDVectorAncestors _emptylineage_ SEC(".rodata") = {0};

const struct execPath _emptyexecpath_ SEC(".rodata") = {.startIndex=-1,.isValidDirectory=0,.exec={0}};

static struct empty_buffer * char_memory_allocate(__u32 * ukey, char * data);

static struct empty_buffer * char_memory_read(__u32 * ukey);

static __u32 char_memory_delete(__u32 * ukey);

static struct empty_buffer * char_memory_big_allocate(__u32 * ukey, char * data);

static struct empty_buffer * char_memory_big_read(__u32 * ukey);

static __u32 char_memory_big_delete(__u32 * ukey);

static struct hooks_context_t * ctx_memory_allocate(__u32 * ukey);

static struct execPath * execPath_memory_allocate(struct taskUKey * uk);

static struct execPath * execPath_memory_read(struct taskUKey * uk);

static __u32 execPath_memory_delete(struct taskUKey * uk);

static struct UIDVectorAncestors * lineage_memory_allocate(__u32 * ukey, struct UIDVectorAncestors * data);

static struct UIDVectorAncestors * lineage_memory_read(__u32 *ukey);

static __u32 lineage_memory_delete(__u32 *ukey);

static struct cache_record * cache_record_memory_allocate(__u32 * ukey, struct cache_record * data);

static struct cache_record * cache_record_memory_read(__u32 *ukey);

static __u32 cache_record_memory_delete(__u32 *ukey);

static int init_relation_map();

static int init_uid_base_map();

static int Load_PRM();

static __u32 jenkinsHash(__u32 a, __u32 b, __u32 c);



// Pretrained Vectors //
const struct BaseDB base SEC(".rodata")= { .entries = {
        // Case: Normal root actions like daemon
        {.severity=EASY,
        .val={0, 0, 0, 0}
        },

        // Case: Normal root actions , root used another user ! <--- It depends on situation can be esclated
        // current space is root : sudo -u trustuser kill -9 PID , sudo -u trustuser bash -c "sudo kill -9 PID" ....
        {.severity=BASE,
        .val={0, 2, 0, 0}
        },

        // Case: consecutive actions as root after UID
        {.severity=ESCALATED,
        .val={0, 0, 0, 2}
        },

        // Case: consecutive actions as root after UID
        {.severity=ESCALATED,
        .val={0, 0, 2, 2}
        },

        // Case: consecutive actions as root after UID
        {.severity=ESCALATED,
        .val={0, 2, 2, 2}
        },

        // Case: consecutive actions as root after UID
        {.severity=ESCALATED,
        .val={0, 2, 0, 2}
        },

        // Case: UID Normal actions
        {.severity=LOW_RISK,
        .val={2, 2, 2, 2}
        },

        // Case: UID mismatch + root 
        {.severity=CRITICAL,
        .val={0, 2, 2, 3}
        },

        // Case: UID mismatch + root
        {.severity=CRITICAL,
        .val={0, 2, 3, 2}
        },

        // Case: UID mismatch + root
        {.severity=CRITICAL,
        .val={0, 3, 2, 2}
        },
        
        // Case: UID mismatch + root
        {.severity=CRITICAL,
        .val={0, 0, 3, 2}
        },

        // Case: UID mismatch + root
        {.severity=CRITICAL,
        .val={0, 0, 3, 3}
        },

        // Case: UID mismatch + root
        {.severity=CRITICAL,
        .val={0, 3, 3, 2}
        },

        // Case: UID mismatch + root
        {.severity=CRITICAL,
        .val={0, 3, 3, 3}
        },

        // Case: Mismatch at the end (post-spawn)
        {.severity=ANOMALOUS,
        .val={2, 2, 2, 3}
        },

        // Case: Mismatch + none root
        {.severity=ANOMALOUS,
        .val={2, 2, 3, 2}
        },

        // Case: Normal user → double root
        {.severity=ANOMALOUS,
        .val={2, 3, 2, 2}
        },

        // Case: Alternating mismatch & root
        {.severity=ANOMALOUS,
        .val={3, 2, 2, 2}
        },

        // Case: Syscalls come from Normal User / sometimes the last 0 is daemon
        {.severity=LOW_RISK,
        .val={2, 2, 2, 0}
        }
    }
};




// Relation Table //
const struct process_relation _prelation_empty_ SEC(".rodata") = {{0},{0},{0},NONE_ACTION,0,0,NONE_CELL};

const struct process_relation relation_data[MAX_NUMBER_OF_RELATION] SEC(".rodata") = {
    {RELATION_0},
    {RELATION_1},
    {RELATION_2},
    {RELATION_3},
    {RELATION_4},
    {RELATION_5},
    {RELATION_6},
    {RELATION_7},
    {RELATION_8},
    {RELATION_9},
    {RELATION_10},
    {RELATION_11},
    {RELATION_12},
    {RELATION_13},
    {RELATION_14},
    {RELATION_15},
    {RELATION_16},
    {RELATION_17},
    {RELATION_18},
    {RELATION_19},
    {RELATION_20},
    {RELATION_21},
    {RELATION_22},
    {RELATION_23},
    {RELATION_24},
    {RELATION_25},
    {RELATION_26},
    {RELATION_27},
    {RELATION_28},
    {RELATION_29},
    {RELATION_30},
    {RELATION_31},
    {RELATION_32},
    {RELATION_33},
    {RELATION_34},
    {RELATION_35},
    {RELATION_36},
    {RELATION_37},
    {RELATION_38},
    {RELATION_39},
    {RELATION_40},
    {RELATION_41},
    {RELATION_42},
    {RELATION_43},
    {RELATION_44},
    {RELATION_45},
    {RELATION_46},
    {RELATION_47},
    {RELATION_48},
    {RELATION_49},
    {RELATION_50},
    {RELATION_51},
    {RELATION_52},
    {RELATION_53},
    {RELATION_54},
    {RELATION_55},
    {RELATION_56},
    {RELATION_57},
    {RELATION_58},
    {RELATION_59},
    {RELATION_60},
    {RELATION_61},
    {RELATION_62},
    {RELATION_63},
    {RELATION_64},
    {RELATION_65},
    {RELATION_66},
    {RELATION_67},
    {RELATION_68},
    {RELATION_69},
    {RELATION_70},
    {RELATION_71},
    {RELATION_72},
    {RELATION_73},
    {RELATION_74},
    {RELATION_75},
    {RELATION_76},
    {RELATION_77},
    {RELATION_78},
    {RELATION_79},
    {RELATION_80},
    {RELATION_81},
    {RELATION_82},
    {RELATION_83},
    {RELATION_84},
    {RELATION_85},
    {RELATION_86},
    {RELATION_87},
    {RELATION_88},
    {RELATION_89},
    {RELATION_90},
    {RELATION_91},
    {RELATION_92},
    {RELATION_93},
    {RELATION_94},
    {RELATION_95},
    {RELATION_96},
    {RELATION_97},
    {RELATION_98},
    {RELATION_99},
    {RELATION_100},
    {RELATION_101},
    {RELATION_102},
    {RELATION_103},
    {RELATION_104},
    {RELATION_105},
    {RELATION_106},
    {RELATION_107},
    {RELATION_108},
    {RELATION_109},
    {RELATION_110},
    {RELATION_111},
    {RELATION_112},
    {RELATION_113},
    {RELATION_114},
    {RELATION_115},
    {RELATION_116},
    {RELATION_117},
    {RELATION_118},
    {RELATION_119},
    {RELATION_120},
    {RELATION_121},
    {RELATION_122},
    {RELATION_123},
    {RELATION_124},
    {RELATION_125},
    {RELATION_126},
    {RELATION_127},
    {RELATION_128},
    {RELATION_129},
    {RELATION_130},
    {RELATION_131},
    {RELATION_132},
    {RELATION_133},
    {RELATION_134},
    {RELATION_135},
    {RELATION_136},
    {RELATION_137},
    {RELATION_138},
    {RELATION_139},
    {RELATION_140},
    {RELATION_141},
    {RELATION_142},
    {RELATION_143},
    {RELATION_144},
    {RELATION_145},
    {RELATION_146},
    {RELATION_147},
    {RELATION_148},
    {RELATION_149},
    {RELATION_150},
    {RELATION_151},
    {RELATION_152},
    {RELATION_153},
    {RELATION_154},
    {RELATION_155},
    {RELATION_156},
    {RELATION_157},
    {RELATION_158},
    {RELATION_159},
    {RELATION_160},
    {RELATION_161},
    {RELATION_162},
    {RELATION_163},
    {RELATION_164},
    {RELATION_165},
    {RELATION_166},
    {RELATION_167},
    {RELATION_168},
    {RELATION_169},
    {RELATION_170},
    {RELATION_171},
    {RELATION_172},
    {RELATION_173},
    {RELATION_174},
    {RELATION_175},
    {RELATION_176},
    {RELATION_177},
    {RELATION_178},
    {RELATION_179},
    {RELATION_180},
    {RELATION_181},
    {RELATION_182},
    {RELATION_183},
    {RELATION_184},
    {RELATION_185},
    {RELATION_186},
    {RELATION_187},
    {RELATION_188},
    {RELATION_189},
    {RELATION_190},
    {RELATION_191},
    {RELATION_192},
    {RELATION_193},
    {RELATION_194},
    {RELATION_195},
    {RELATION_196},
    {RELATION_197},
    {RELATION_198},
    {RELATION_199},
    {RELATION_200},
    {RELATION_201},
    {RELATION_202},
    {RELATION_203},
    {RELATION_204},
    {RELATION_205},
    {RELATION_206},
    {RELATION_207},
    {RELATION_208},
    {RELATION_209},
    {RELATION_210},
    {RELATION_211},
    {RELATION_212},
    {RELATION_213},
    {RELATION_214},
    {RELATION_215},
    {RELATION_216},
    {RELATION_217},
    {RELATION_218},
    {RELATION_219},
    {RELATION_220},
    {RELATION_221},
    {RELATION_222},
    {RELATION_223},
    {RELATION_224},
    {RELATION_225},
    {RELATION_226},
    {RELATION_227},
    {RELATION_228},
    {RELATION_229},
    {RELATION_230},
    {RELATION_231},
    {RELATION_232},
    {RELATION_233},
    {RELATION_234},
    {RELATION_235},
    {RELATION_236},
    {RELATION_237},
    {RELATION_238},
    {RELATION_239},
    {RELATION_240},
    {RELATION_241},
    {RELATION_242},
    {RELATION_243},
    {RELATION_244},
    {RELATION_245},
    {RELATION_246},
    {RELATION_247},
    {RELATION_248},
    {RELATION_249},
    {RELATION_250},
    {RELATION_251},
    {RELATION_252},
    {RELATION_253},
    {RELATION_254},
    {RELATION_255},
    {RELATION_256},
    {RELATION_257},
    {RELATION_258},
    {RELATION_259},
    {RELATION_260},
    {RELATION_261},
    {RELATION_262},
    {RELATION_263},
    {RELATION_264},
    {RELATION_265},
    {RELATION_266},
    {RELATION_267},
    {RELATION_268},
    {RELATION_269},
    {RELATION_270},
    {RELATION_271},
    {RELATION_272},
    {RELATION_273},
    {RELATION_274},
    {RELATION_275},
    {RELATION_276},
    {RELATION_277},
    {RELATION_278},
    {RELATION_279},
    {RELATION_280},
    {RELATION_281},
    {RELATION_282},
    {RELATION_283},
    {RELATION_284},
    {RELATION_285},
    {RELATION_286},
    {RELATION_287},
    {RELATION_288},
    {RELATION_289},
    {RELATION_290},
    {RELATION_291},
    {RELATION_292},
    {RELATION_293},
    {RELATION_294},
    {RELATION_295},
    {RELATION_296},
    {RELATION_297},
    {RELATION_298},
    {RELATION_299}
};
#endif