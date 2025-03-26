#ifndef FILTERING_SYSCALL_FRAMEWORK_STRUCTS
#define FILTERING_SYSCALL_FRAMEWORK_STRUCTS


// Mojtaba , The Structures // ***

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

struct process_relation {
    char *process;
    char *parent;
    char *grandparent;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, PRM_STATE);
    __type(key, __u32);
    __type(value, struct prm_state);
} prm_state_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RELATION);
    __type(key, __u32);
    __type(value, struct process_relation);
} prm_map SEC(".rodata");

static void loadPRM(){
    bpf_printk("Preparing PRM...");
    __u32 _index_=0;
    struct prm_state currect_state={STARTUP};
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);
/*
       {NULL,PREFIX_BASH,NULL},
        {NULL,PREFIX_FISH,NULL},
        {NULL,PREFIX_SSH,NULL},
        {NULL,PREFIX_ZSH,NULL},
        {PREFIX_PYTHON, PREFIX_SH, "containerd-shim"},
        {PREFIX_PYTHON, PREFIX_BASH, "slurm_script"},
        {NULL, NULL, "containerd-shim"},
        {NULL, NULL, "slurm_script"}
        */
    const struct process_relation relation_list_static[] = {PRM};

    const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);

    __u32 _safeCounter_ =0;
    
    for (__u32 i = 0; i < RELATION_SIZE; i++) {
        _safeCounter_=i;
        char process[16] = {};
        char parent[16] = {};
        char grandparent[16] = {};

        bpf_probe_read_kernel_str(process, sizeof(process), relation_list_static[_safeCounter_].process);
        bpf_probe_read_kernel_str(parent, sizeof(parent), relation_list_static[_safeCounter_].parent);
        bpf_probe_read_kernel_str(grandparent, sizeof(grandparent), relation_list_static[_safeCounter_].grandparent);

        bpf_printk("Load PRM Relations %d..... {%s,%s,%s} ",_safeCounter_,process,parent,grandparent);
        bpf_map_update_elem(&prm_map, &_safeCounter_, &relation_list_static[_safeCounter_], BPF_ANY);
    }

    // Change State
    currect_state.prm_state=LOADED;
    bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);
}
#endif