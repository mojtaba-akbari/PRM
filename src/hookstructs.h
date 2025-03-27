#ifndef FILTERING_SYSCALL_FRAMEWORK_STRUCTS
#define FILTERING_SYSCALL_FRAMEWORK_STRUCTS


// Mojtaba , The Structures // ***
// Use Stack Programming To Design The Whole PRM //
// Stack Is Faster Than BFP Helper Calls For Allocating Data //
// Here The Structure Is Between 512 Byte Allocation , So I Would Prefer Develop It As Stack //

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
    char process[MAX_RELATION_PROCESSNAME];
    char parent[MAX_RELATION_PROCESSNAME];
    char grandparent[MAX_RELATION_PROCESSNAME];
};

// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __uint(max_entries, MAX_RELATION);
//     __type(key, u32);
//     __type(value, struct process_relation);
// } relations_map SEC(".maps")


// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __uint(max_entries, PRM_STATE);
//     __type(key, __u32);
//     __type(value, struct prm_state);
// } prm_state_map SEC(".maps");


// static void loadPRM(){
//     bpf_printk("Preparing PRM...");
//     __u32 _index_=0;
//     struct prm_state currect_state={STARTUP};
//     bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);
//         /*
//        {PREFIX_NOCARE,PREFIX_BASH,PREFIX_NOCARE},
//         {PREFIX_NOCARE,PREFIX_FISH,PREFIX_NOCARE},
//         {PREFIX_NOCARE,PREFIX_SSH,PREFIX_NOCARE},
//         {PREFIX_NOCARE,PREFIX_ZSH,PREFIX_NOCARE},
//         {PREFIX_PYTHON, PREFIX_SH, "containerd-shim"},
//         {PREFIX_PYTHON, PREFIX_BASH, "slurm_script"},
//         {PREFIX_NOCARE, PREFIX_NOCARE, "containerd-shim"},
//         {PREFIX_NOCARE, PREFIX_NOCARE, "slurm_script"}
//         */
//     //const struct process_relation relation_list_static[] = {PRM};

//     //const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);

//     // __u32 _safeCounter_ =0;
    
//     // for (__u32 i = 0; i < MAX_RELATION; i++) {
//     //     _safeCounter_=i;
//     //     struct process_relation *temp;
//     //     temp = bpf_map_lookup_elem(&prm_map, &_safeCounter_);


//     //     bpf_printk("Load PRM Relations %d..... {%s,%s,%s}...",_safeCounter_,temp->process,temp->parent,temp->grandparent);
//     // }

//     // Change State
//     currect_state.prm_state=LOADED;
//     bpf_map_update_elem(&prm_state_map, &_index_, &currect_state, BPF_ANY);
// }
// #define CHECK_RELATIONS(comm , p_comm, grand_p_comm) (checkPRM_1(comm, p_comm, grand_p_comm) | \
//                                                          checkPRM_2(comm, p_comm, grand_p_comm) | \
//                                                          checkPRM_3(comm, p_comm, grand_p_comm) | \
//                                                          checkPRM_4(comm, p_comm, grand_p_comm) | \
//                                                             checkPRM_5(comm, p_comm, grand_p_comm) | \ 
//                                                             checkPRM_6(comm, p_comm, grand_p_comm) | \ 
//                                                             checkPRM_7(comm, p_comm, grand_p_comm) | \ 
//                                                             checkPRM_8(comm, p_comm, grand_p_comm))

int checkRelations(const struct process_relation * relation_list_static, __u32 relation_list_static_size, char * comm , char * p_comm, char * grand_p_comm){
    bpf_printk("I am going to Check Relations : ", relation_list_static_size);
    for (__u32 i = 0; i < relation_list_static_size; i++) {
        if(
            ((__builtin_strcmp(relation_list_static[i].process,PREFIX_NOCARE) == 0) ? true : (__builtin_strcmp(comm, relation_list_static[i].process) ==0? true : false))
            &&
            ((__builtin_strcmp(relation_list_static[i].parent, PREFIX_NOCARE) == 0) ? true : (__builtin_strcmp(p_comm, relation_list_static[i].parent) ==0? true : false)) 
            &&
            ((__builtin_strcmp(relation_list_static[i].grandparent, PREFIX_NOCARE) == 0) ? true : (__builtin_strcmp(grand_p_comm, relation_list_static[i].grandparent) ==0? true : false))
        ) 
        {
            // Debug //
            bpf_printk("Syscall Comes From: %s -> %s -> %s due to role : {%s,%s,%s}\n", comm, p_comm, grand_p_comm , relation_list_static[i].process , relation_list_static[i].parent, relation_list_static[i].grandparent);
            return 1;
        }
    }

    return 0;
}

static int checkPRM_1(char * comm , char * p_comm, char * grand_p_comm){
    #if defined(PRM_1)
        const struct process_relation relation_list_static[] = {PRM_1};
        const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);
        checkRelations(relation_list_static,RELATION_SIZE, comm, p_comm, grand_p_comm);
    #else
        return 0;
    #endif
}

static int checkPRM_2(char * comm , char * p_comm, char * grand_p_comm){
    #if defined(PRM_2)
        const struct process_relation relation_list_static[] = {PRM_2};
        const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);
        checkRelations(relation_list_static,RELATION_SIZE, comm, p_comm, grand_p_comm);
    #else
        return 0;
    #endif
}

static int checkPRM_3(char * comm , char * p_comm, char * grand_p_comm){
    #if defined(PRM_3) 
        const struct process_relation relation_list_static[] = {PRM_3};
        const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);
        checkRelations(relation_list_static,RELATION_SIZE, comm, p_comm, grand_p_comm);
    #else
        return 0;
    #endif
}

static int checkPRM_4(char * comm , char * p_comm, char * grand_p_comm){
    #if defined(PRM_4)
        const struct process_relation relation_list_static[] = {PRM_4};
        const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);
        checkRelations(relation_list_static,RELATION_SIZE, comm, p_comm, grand_p_comm);
    #else
        return 0;
    #endif
}

static int checkPRM_5(char * comm , char * p_comm, char * grand_p_comm){
    #if defined(PRM_5)
        const struct process_relation relation_list_static[] = {PRM_5};
        const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);
        checkRelations(relation_list_static,RELATION_SIZE, comm, p_comm, grand_p_comm);
    #else
        return 0;
    #endif
}

static int checkPRM_6(char * comm , char * p_comm, char * grand_p_comm){
    #if defined(PRM_6)
        const struct process_relation relation_list_static[] = {PRM_6};
        const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);
        checkRelations(relation_list_static,RELATION_SIZE, comm, p_comm, grand_p_comm);
    #else
        return 0;
    #endif
}

static int checkPRM_7(char * comm , char * p_comm, char * grand_p_comm){
    #if defined(PRM_7)
        const struct process_relation relation_list_static[] = {PRM_7};
        const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);
        checkRelations(relation_list_static,RELATION_SIZE, comm, p_comm, grand_p_comm);
    #else
        return 0;
    #endif
}

static int checkPRM_8(char * comm , char * p_comm, char * grand_p_comm){
    #if defined(PRM_8)
        const struct process_relation relation_list_static[] = {PRM_8};
        const __u32 RELATION_SIZE = sizeof(relation_list_static) / sizeof(struct process_relation);
        checkRelations(relation_list_static,RELATION_SIZE, comm, p_comm, grand_p_comm);
    #else
        return 0;
    #endif
}

static int checkPRM(char * comm , char * p_comm, char * grand_p_comm){
    int result = 0;
    result |= checkPRM_1(comm, p_comm, grand_p_comm);
    //result |= checkPRM_2(comm, p_comm, grand_p_comm);
    //result |= checkPRM_3(comm, p_comm, grand_p_comm);
    //result |= checkPRM_4(comm, p_comm, grand_p_comm);
    //result |= checkPRM_5(comm, p_comm, grand_p_comm);
    //result |= checkPRM_6(comm, p_comm, grand_p_comm);
    //result |= checkPRM_7(comm, p_comm, grand_p_comm);
    //result |= checkPRM_8(comm, p_comm, grand_p_comm);
    return result;
}

#endif