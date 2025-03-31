#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_Engine_H
#define FILTERING_SYSCALL_FRAMEWORK_PRM_Engine_H


// Mojtaba, Return cgroup of task 
// Sometimes i am going to use this cgroup because understanding patterin is difficult
static char * getCgroup(struct task_struct *task) {
    // Find the cgroup of SLURM JOB that is the best idea , otherwise you need check ENV variables which could be more than 10 //
    // Then Per Syscall Call All We Have Too Traverse Between Big Array // Mojtaba :)

    struct css_set *cgroups = BPF_CORE_READ(task, cgroups);
    struct cgroup_subsys_state *css;
    char buffer[128];
    int ret;

    if (!cgroups)
        return false;

    for (int i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
        bpf_probe_read_kernel(&css, sizeof(css), &cgroups->subsys[i]);

        if (!css)
            continue;

        struct cgroup *cgrp = BPF_CORE_READ(css, cgroup);
        const char *cgroup_name = BPF_CORE_READ(cgrp, kn, name);

        ret = bpf_probe_read_kernel_str(buffer, sizeof(buffer), cgroup_name);

        if (ret > 0) {
            return buffer;
        }
    }

    return false;
}

// Mojtaba, Retreive ENV From Current Process //
// Do not use it , till you need it emergency //
// Please Do not change this algorithm because of more complixity //
static void retreiveENVfromTask(struct task_struct * task, char * env, int env_len){
    // unsigned long env_start;
    // struct mm_struct *mm;
    // char env_buf[ENV_MAX_SIZE] = {}; // Mojtaba, The Maximum Char of a Simple ENV i assume it 64 KEY=VALUE

    // // Get memory mapping (mm_struct) from task
    // mm = task->mm;
    // if (!mm) {
    //     return 0;
    // }

    // // Read the environment start address
    // bpf_probe_read(&env_start, sizeof(env_start), &mm->env_start);

    // // Mojtaba, Scan environment variables for "SLURM_JOB_USER=" 
    // // Mojtaba , Put MAX_ITR because of long runing loop ofcurse this variable is part of first MAX_ITR //
    // // I assume MAX_ITR for the highest numbers of ENV , But Take Care it is pointer to address not CHAR //
    // for (int i = 0; i < MAX_ITR; i += sizeof(env_buf)) {

    //     if (bpf_probe_read_str(env_buf, sizeof(env_buf), (void *)(env_start + i)) < 0) {
    //         break; // take care close the loop if env address goes no where
    //     }__u32
        
    //     bpf_printk("ENV  %s\n", env_buf);

    //     if (memcmp(env_buf, env, env_len) == 0) {
    //         char *username = env_buf + 15; // Mojtaba , do not need to use memcp just point to the first char to \0
    //         bpf_probe_read_kernel_str(user_home + 6, sizeof(user_home) - 6, username);
    //         break;
    //     }
    // }
}

// Mojtaba, Verifier //
static int PRMVerifier(enum PRM_HOOK_ENUM hook_enum){
    struct task_struct *task = (struct task_struct *) bpf_get_current_task_btf();
    struct thread_info *tinfo = &task->thread_info;
    struct task_struct *parent;
    struct task_struct *grandparent;
    char comm[TASK_COMM_LEN], p_comm[TASK_COMM_LEN], grand_p_comm[TASK_COMM_LEN];

    if (!task) return 0;

    bpf_get_current_comm(comm, sizeof(comm));

    
    parent = task->real_parent;
    if (parent) {
        bpf_probe_read_kernel_str(p_comm, sizeof(p_comm), parent->comm);
    } else {
        return 0;
    }

    grandparent = parent->real_parent;
    // Some times we do not have grand
    if (!grandparent) {
        bpf_probe_read_kernel_str(grand_p_comm, sizeof(""), "");
    }

    bpf_probe_read_kernel_str(grand_p_comm, sizeof(grand_p_comm), grandparent->comm);

    bpf_printk("***Syscalls Come from: %d %s -> %s -> %s due to role : {%s,%s,%s,%d,%d,%d}\n", hook_enum, comm, p_comm, grand_p_comm);

    // Mojtaba, Get into roles
    // I customized the if clouse to be readable so put your roles there
    struct process_relation *prm;
    __u32 _safeCounter_=0;
    int _redirectIndex_=-1;
    for (__u32 i = 0; i < MAX_NUMBER_OF_RELATION; i++) {
        _safeCounter_=i;

        prm = bpf_map_lookup_elem(&prm_map, &_safeCounter_); // Retreive from user-space memory which was allocated in the libpbf load time , Mojtaba , 2 Hits to user-space memory
        if(prm){
            
            if(_redirectIndex_ > 0 && i < _redirectIndex_) continue;

            // Check EMPTY Roles //
            if(prm->process[0] == '\0' && prm->parent[0] == '\0' && prm->grandparent[0] == '\0') continue;

            // Check The Syscall number //
            if((prm->syscallNumber != hook_enum) && (prm->syscallNumber != NONE_CELL)) continue;

            if((prm->protectZone && _redirectIndex_ > 0) || !prm->protectZone)
            {
                bpf_printk("Syscall Comes From: %d %s -> %s -> %s due to role : {%s,%s,%s,%d,%d,%d}\n", hook_enum, comm, p_comm, grand_p_comm , prm->syscallNumber, prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone);

                __u32 mixedUP=1;
                if(strcmp(prm->process,PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0) mixedUP &= (strcmp(comm, prm->process, MAX_RELATION_PROCESSNAME) ==0);
                
                if(mixedUP && (strcmp(prm->parent, PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0)) mixedUP &=  (strcmp(p_comm, prm->parent, MAX_RELATION_PROCESSNAME) ==0);

                if(mixedUP && (strcmp(prm->grandparent, PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0)) mixedUP &=  (strcmp(grand_p_comm, prm->grandparent, MAX_RELATION_PROCESSNAME) ==0);

                if(mixedUP) 
                {
                    bpf_printk("Matched Relations : %s -> %s -> %s due to role : {%d,%s,%s,%s,%d,%d,%d}\n", comm, p_comm, grand_p_comm , prm->syscallNumber, prm->process , prm->parent, prm->grandparent,prm->action,prm->redirectIndex,prm->protectZone);
                    switch (prm->action)
                    {
                        case REJECT:
                            return 1;
                        case ACCEPT:
                            return 0;
                        case DEBUG:
                            bpf_printk("Matched Relations : %s -> %s -> %s due to role : {%d,%s,%s,%s,%d,%d,%d}\n", comm, p_comm, grand_p_comm , prm->syscallNumber, prm->process , prm->parent, prm->grandparent,prm->action,prm->redirectIndex,prm->protectZone);
                            break;
                        case REDIRECT:
                            if(prm->redirectIndex < MAX_NUMBER_OF_RELATION && prm->redirectIndex >= i){
                                if(prm->redirectIndex == i){
                                    return 0;
                                }
                                else{
                                    _redirectIndex_ = prm->redirectIndex;
                                    continue;
                                }
                            }
                            else {
                                bpf_printk("REDIRECT Role But With Wrong Index (Skip And Move on Next Role) : %s -> %s -> %s due to role : {%d,%s,%s,%s,%d,%d,%d}\n", comm, p_comm, grand_p_comm , prm->syscallNumber, prm->process , prm->parent, prm->grandparent,prm->action,prm->redirectIndex,prm->protectZone);
                            }
                            break;
                        case RETURN:
                            PRM_PROG_Dispatcher(prm->redirectIndex);
                            break;
                    }
                }
            }
        }
    }
    

    return 0;
}

// Mojtaba , define as inline
static int detectSyscallRelations(enum PRM_HOOK_ENUM hook_enum) {
    // Load Process Relation Table Roles //
    struct prm_state *prm_state;
    __u32 key = 0; // Static relation list location by key
    prm_state = bpf_map_lookup_elem(&prm_state_map, &key);
    if (!prm_state) {
        bpf_printk("There is no PRM , I am going to Prepare...");
        Load_PRM();
    }
    else if (prm_state->prm_state == UNLOADED){
        bpf_printk("PRM has been UNLOADED, I am going to load it up...");
        Load_PRM();
    }

    return PRMVerifier(hook_enum);
}

static __always_inline int entryStartPoint(enum PRM_HOOK_ENUM hook_enum){
    __u32 key=0;
    __u32 currentPid=bpf_get_current_pid_tgid() >> 32;
    struct {__u32 pid; __u64 magic;} *value= bpf_map_lookup_elem(&self_pids, &key);
    if (value && value->pid == currentPid && value->magic==MAGIC_VALUE) return 0; 

    if(detectSyscallRelations(hook_enum)){
        return -EPERM;
    }

    // Allow the write operations
    return 0;
}

static __always_inline int saveSelfPID(){
    __u32 key=0;
    __u32 currentPid = bpf_get_current_pid_tgid() >> 32;
    struct {__u32 pid; __u64 magic;} *value = bpf_map_lookup_elem(&self_pids, &key);
    if(!value){
        struct {__u32 pid; __u64 magic;} currentValue = {.pid=currentPid,.magic=MAGIC_VALUE};
        bpf_printk("PRM has been loading up with PID : %d",currentPid);
        bpf_map_update_elem(&self_pids, &key, &currentValue, BPF_NOEXIST);
    }
}
#endif // FILTERING_SYSCALL_FRAMEWORK_HELPERS_H