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
    // Implement ME
}

static void addLRUCache(__u32 * processID, struct process_relation * prmRelation){
    __u32 pid=*processID; // do not laugh to me :) i know what i am doing , maybe this pointer comes from another Maps , so first get value ;) trust me
    FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH | EXTERA | NORMAL,bpf_printk("Hook Received: PID(%d) Matched with relation (maybe relation is EMPTY) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", pid, 
                                                prmRelation->process , prmRelation->parent, prmRelation->grandparent, prmRelation->action, prmRelation->redirectIndex,prmRelation->protectZone, prmRelation->hookType));
    struct process_relation processTmpx={0};
    memcmp(&processTmpx,prmRelation,sizeof(struct process_relation));
    bpf_map_update_elem(&process_list, &pid, &processTmpx, BPF_ANY);
}

static struct process_relation * getLRUCache(__u32 * processID,enum PRM_HOOK_ENUM hook){
    __u32 pid=*processID;
    struct process_relation *processTmpx=bpf_map_lookup_elem(&process_list, &pid);
    if(processTmpx){
        if(processTmpx->action == NONE_ACTION || processTmpx->hookType == NONE_CELL) // It comes with out PRM (daemon and background allowed services) Or check the process Hook type with the while list one
        {
            return processTmpx;
        }
        else{
            if(processTmpx->hookType == hook)
                return processTmpx;
        }
    }
    
    return NULL;
}

// Mojtaba, Verifier //
static int PRMVerifier(enum PRM_HOOK_ENUM hook, __u32 * PID){
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

    FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH,bpf_printk("***Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} \n", hook,*PID, comm, p_comm, grand_p_comm));

    // Mojtaba, Get into roles
    // I customized the if clouse to be readable so put your roles there
    struct process_relation *prm;
    __u32 _safeCounter_=0;
    int _redirectIndex_=-1;
    for (__u32 i = 0; i < MAX_NUMBER_OF_RELATION; i++) {
        _safeCounter_=i;

        if(_redirectIndex_ > 0 && _safeCounter_ < _redirectIndex_) continue;

        prm = bpf_map_lookup_elem(&prm_map, &_safeCounter_); // Retreive from user-space memory which was allocated in the libpbf load time , Mojtaba , 2 Hits to user-space memory
        if(prm){
            if(prm->process[0] == '\0' || prm->parent[0] == '\0' || prm->grandparent[0] == '\0' || prm->action == NONE_ACTION) continue;

            if((prm->hookType != NONE_CELL) && (prm->hookType != hook)) continue;

            if((prm->protectZone==1 && _redirectIndex_ >= 0) || (prm->protectZone==0 && _redirectIndex_ < 0))
            {
                FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH | EXTERA,bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Check the relation : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook, *PID,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));

                __u32 mixedUP=1;
                if(strcmp(prm->process,PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0) mixedUP &= (strcmp(comm, prm->process, MAX_RELATION_PROCESSNAME) ==0);
                
                if(mixedUP && (strcmp(prm->parent, PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0)) mixedUP &=  (strcmp(p_comm, prm->parent, MAX_RELATION_PROCESSNAME) ==0);

                if(mixedUP && (strcmp(prm->grandparent, PREFIX_NOCARE, MAX_RELATION_PROCESSNAME) != 0)) mixedUP &=  (strcmp(grand_p_comm, prm->grandparent, MAX_RELATION_PROCESSNAME) ==0);

                if(mixedUP)
                {
                    FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH | EXTERA | NORMAL,bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook, *PID,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                    switch (prm->action)
                    {
                        case REJECT:
                            return 1;
                        case ACCEPT:
                            addLRUCache(PID,prm);
                            return 0;
                        case DEBUG:
                            FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING,bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (Debug Action) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook, *PID,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                            return 0;
                        case REDIRECT:
                            if(prm->redirectIndex < MAX_NUMBER_OF_RELATION && prm->redirectIndex >= _safeCounter_){
                                if(prm->redirectIndex == _safeCounter_){
                                    _redirectIndex_= -1;
                                    continue;
                                }
                                else{
                                    _redirectIndex_ = prm->redirectIndex;
                                    continue;
                                }
                            }
                            else {
                                FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING,bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (Redirect Action) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook, *PID,comm, p_comm, grand_p_comm , 
                                                prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                                continue;
                            }
                            break;
                        case RETURN:
                            return PRM_PROG_Dispatcher(prm->redirectIndex);
                        default:
                            continue;
                    }
                }
            }
        }
    }
    
    FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NONE,bpf_printk("Unknown Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Not Matched any relations (Count as White Process - Or Add Role) \n", hook, *PID,comm, p_comm, grand_p_comm));

    struct process_relation processTmpx={0};
    addLRUCache(PID,&processTmpx);

    return 0;
}

// Mojtaba , define as inline
static int detectSyscallRelations(enum PRM_HOOK_ENUM hook, __u32 * PID) {
    // If you want to inject any driver or filters , here you can inject //
    return PRMVerifier(hook, PID);
}

static int entryStartPoint(enum PRM_HOOK_ENUM hook){
    __u32 key=0;
    __u32 currentPid=bpf_get_current_pid_tgid() >> 32;
    struct {__u32 pid; __u64 magic;} *value= bpf_map_lookup_elem(&self_pids, &key);

    if (value && value->pid == currentPid && value->magic==MAGIC_VALUE) {
         FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH,bpf_printk("Hook Received: Hook(%d)-PID(%d) Self-PID , Internal Hooks \n", hook, currentPid));
        return 0;
    } 

    if(getLRUCache(&currentPid,hook)) {
        FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH,bpf_printk("Hook Received: Hook(%d)-PID(%d) Matched with process white list \n", hook, currentPid));
        return 0;
    }

    if(detectSyscallRelations(hook, &currentPid)){
        return -EPERM;
    }

    // Allow the write operations
    return 0;
}

static int saveSelfPID(){
    __u32 key=0;
    __u32 currentPid = bpf_get_current_pid_tgid() >> 32;
    
    struct {__u32 pid; __u64 magic;} *value = bpf_map_lookup_elem(&self_pids, &key);

    if(value && value->pid == EMPTY && value->magic == EMPTY){
        struct {__u32 pid; __u64 magic;} currentValue = {.pid=currentPid,.magic=MAGIC_VALUE};

        FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING,bpf_printk("PRM verifier is setting up itself PID : %d",currentPid));
        
        bpf_map_update_elem(&self_pids, &key, &currentValue, BPF_ANY);

        // Load Process Relation Table Roles //
        struct prm_state *prm_state;
        __u32 key = 0; // Static relation list location by key
        prm_state = bpf_map_lookup_elem(&prm_state_map, &key);
        if (!prm_state) {
            FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING,bpf_printk("PRM is loading up PID : %d",currentPid));
            Load_PRM();
        }
        else if (prm_state->prm_state == UNLOADED){
            FULLY_DEBUG(__DEBUG__,VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING,bpf_printk("PRM has been unloaded , PRM is loading up again PID : %d",currentPid));
            Load_PRM();
        }

        return 0;
    }

    return 1;
}
#endif // FILTERING_SYSCALL_FRAMEWORK_HELPERS_H