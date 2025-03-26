#ifndef FILTERING_SYSCALL_FRAMEWORK_STRUCTS
#define FILTERING_SYSCALL_FRAMEWORK_STRUCTS


// Mojtaba , struct for getting pattern for harmfull chain of execution 
// I call it PRM Process Relation Map
struct process_relation {
    char *process;
    char *parent;
    char *grandparent;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RELATION);
    __type(key, __u32);
    __type(value, struct process_relation);
} relation_map SEC(".maps");

static void loadPRM(){
    bpf_printk("Preparing PRM...");

    const struct process_relation relation_list_static[] = {PRM};

    const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);

    __u32 _safeCounter_ =0;
    
    for (__u32 i = 0; i < RELATION_SIZE; i++) {
        _safeCounter_=i;
        bpf_printk("Load PRM Relations %d..... {%s,%s,%s} ",_safeCounter_,relation_list_static[_safeCounter_].process,relation_list_static[_safeCounter_].parent,relation_list_static[_safeCounter_].grandparent);
        bpf_map_update_elem(&relation_map, &_safeCounter_, &relation_list_static[_safeCounter_], BPF_ANY);
    }
}
#endif