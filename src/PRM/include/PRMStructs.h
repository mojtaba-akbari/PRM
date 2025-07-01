#ifndef FILTERING_SYSCALL_FRAMEWORK_STRUCTS
#define FILTERING_SYSCALL_FRAMEWORK_STRUCTS

#include "conf/PRM.h"
#include <include/baseheaders.h>
#include <include/BTFFunctions.h>

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
    CRED_PREPARE
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

union lsm_args_u {
    struct args_file_open_t file_open;
    struct args_inode_create_t inode_create;
    struct args_task_kill_t task_kill;
    struct args_socket_create_t socket_create;
    struct args_socket_connect_t socket_connect;
    struct args_bprm_check_security_t bprm_check_security;
    struct args_file_mprotect_t file_mprotect;
};

struct hooks_context_t{
    struct UniqueKey key;
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
    DEBUG,
    RETURN
};

struct process_relation {
    char process[MAX_RELATION_PROCESSNAME];
    char parent[MAX_RELATION_PROCESSNAME];
    char grandparent[MAX_RELATION_PROCESSNAME];
    enum PROCESS_RELATION_ACTION_ENUM action;
    __u32 redirectIndex;
    bool protectZone:1;
    enum PRM_HOOK_ENUM hookType;
};

struct process_entry{
    __u32 pid;
    enum PRM_HOOK_ENUM hook;
};

const struct process_relation _prelation_empty_ SEC(".rodata") = {{""},{""},{""},NONE_ACTION,0,0,NONE_CELL};

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
    {RELATION_149}
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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 120);
    __type(key, __u32);
    __type(value, char[HUGE_STR]);
} tmp_buffer_ SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct hooks_context_t);
} _ctx_holder_ SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct cache_record);
} _cache_record_holder_ SEC(".maps");

struct empty_buffer{
    char _buff_[HUGE_STR];
};

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

const struct cache_record _emptycacherecord_ SEC(".rodata") = {0};

const struct empty_buffer _emptybuffer_ SEC(".rodata") = {{0}};

const struct hooks_context_t _emptyctx_ SEC(".rodata") = {0};

const struct UIDVectorAncestors _emptylineage_ SEC(".rodata") = {0};

static char * char_memory_allocate(__u32 * ukey, char * data);

static char * char_memory_read(__u32 * ukey);

static __u32 char_memory_delete(__u32 * ukey);

static struct hooks_context_t * ctx_memory_allocate(__u32 * ukey);

static struct UIDVectorAncestors * lineage_memory_allocate(__u32 * ukey, struct UIDVectorAncestors * data);

static struct UIDVectorAncestors * lineage_memory_read(__u32 *ukey);

static __u32 lineage_memory_delete(__u32 *ukey);

static struct cache_record * cache_record_memory_allocate(__u32 * ukey, struct cache_record * data);

static struct cache_record * cache_record_memory_read(__u32 *ukey);

static __u32 cache_record_memory_delete(__u32 *ukey);

static void init_relation_map();

static void Load_PRM();

static __u32 jenkinsHash(__u32 a, __u32 b, __u32 c);

#endif