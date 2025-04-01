#ifndef FILTERING_SYSCALL_FRAMEWORK_STRUCTS
#define FILTERING_SYSCALL_FRAMEWORK_STRUCTS


// Mojtaba :) , The Structures Notice never change till you know what you are doing here // ***
// Use Stack Programming To Design The Whole PRM //
// Stack Is Faster Than BFP Helper Calls For Allocating Data //
// Here The Structure Is Between 512 Byte Allocation , So I Would Prefer Develop It As Stack //
// Try to make hook enum because of any tasks comprise more than 2 or 3 differ syscalls , as well as differ linux distro //
enum PRM_HOOK_ENUM{
    NONE_CELL, // ---> Mimic From Kernel Index 0 Always Nothing ;)
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
    TASK_SETIOPRIO
};

enum PRM_STATE_ENUM {
    UNLOADED,
    STARTUP,
    LOADED,
    BROKEN,
    TOO_MANY_ROLES,
    NON_OF_GENERAL_ROLE
};

struct prm_state {
    enum PRM_STATE_ENUM prm_state;
};

enum PROCESS_RELATION_ACTION_ENUM{
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
    int redirectIndex;
    bool protectZone;
    enum PRM_HOOK_ENUM hookType;
};

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
    {RELATION_99}
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
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
    __type(key, u32);           
    __type(value, struct process_relation *);         
} process_list SEC(".maps");

static void init_relation_map() {
    bpf_printk("Preparing PRM Relation Map...");
    __u32 _safeCounter_=0;

    for (int i = 0; i < MAX_NUMBER_OF_RELATION; i++) {
        _safeCounter_=i;
        bpf_map_update_elem(&prm_map, &_safeCounter_, &relation_data[_safeCounter_], BPF_ANY);
    }
}

static void Load_PRM(){
    bpf_printk("Preparing PRM...");
    __u32 _index_=0;
    struct prm_state currect_state={STARTUP};
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);

    init_relation_map();

    currect_state.prm_state=LOADED;
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);
}

#endif