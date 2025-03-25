#ifndef FILTERING_SYSCALL_FRAMEWORK_STRUCTS
#define FILTERING_SYSCALL_FRAMEWORK_STRUCTS


// Mojtaba , struct for getting pattern for harmfull chain of execution 
// I call it PRM Process Relation Map
struct process_relation {
    char *process;
    char *parent;
    char *grandparent;
};



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

#define MAX_RELATION 8 // 50 Roles , if you need more increase it and build project again *** Do not Forget to change this value
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RELATION);
    __type(key, __u32);
    __type(value, struct process_relation);
} relation_map SEC(".maps");

static void defineProcessRelation(){
    struct process_relation relation_list_static[] = {
        {NULL,PREFIX_BASH,NULL}, // direct hit
        {NULL,PREFIX_FISH,NULL}, // direct hit
        {NULL,PREFIX_SSH,NULL}, // direct hit
        {NULL,PREFIX_ZSH,NULL}, // direct hit
        {PREFIX_PYTHON, PREFIX_SH, "containerd-shim"}, // isolation level docker
        {PREFIX_PYTHON, PREFIX_BASH, "slurm_script"}, // isolation level slurm
        {NULL, NULL, "containerd-shim"}, // High Strict isolation level docker
        {NULL, NULL, "slurm_script"} // High Strict slurm script level
        // Add more relationships if needed
    };

    for (__u32 i = 0; i < (sizeof(relation_list_static) / sizeof(struct process_relation)); i++) {
        bpf_map_update_elem(&relation_map, &i, &relation_list_static[i], BPF_ANY);
    }
}
#endif