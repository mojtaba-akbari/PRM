#include "../include/conf/PRM.h"
#include "../include/conf/PRMConfig.h"
#include "../include/PRMStructs.h"
#include "../include/PRMProgStructs.h"
#include "../include/PRMCacheService.h"
#include "../include/PRMVerifier.h"
#include "../include/PRMProgDispatcher.h"
#include "../include/PRMFilters.h"
#include "PRMStructs.c"
#include "PRMFilters.c"
#include "PRMProgEntry.c"
#include "PRMProgDispatcher.c"
#include "PRMCacheService.c"

// Mojtaba, Verifier //
static int PRMVerifier(struct hooks_context_t *hook_ctx){
    if(!hook_ctx) RET_ACCEPT

    struct task_struct *task = hook_ctx->task;
        
    if (!task) RET_ACCEPT

    struct task_struct *parent;
    struct task_struct *grandparent;

    __u32 comm_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 333;
    struct empty_buffer *comm_buf = char_memory_allocate(&comm_key, NULL);
    if (!comm_buf) {
        char_memory_delete(&comm_key);
        RET_REJECT
    }



    __u32 p_comm_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 334;
    struct empty_buffer *p_comm_buf = char_memory_allocate(&p_comm_key, NULL);
    if (!p_comm_buf) {
        char_memory_delete(&comm_key);
        char_memory_delete(&p_comm_key);
        RET_REJECT
    }


    __u32 grand_p_comm_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 335;
    struct empty_buffer *grand_p_comm_buf = char_memory_allocate(&grand_p_comm_key, NULL);
    if (!grand_p_comm_buf) {
        char_memory_delete(&comm_key);
        char_memory_delete(&p_comm_key);
        char_memory_delete(&grand_p_comm_key);
        RET_REJECT
    }

    bpf_get_current_comm(comm_buf->_buff_, TASK_COMM_LEN);

    parent = BPF_CORE_READ(task,real_parent);
    if (parent) {
        bpf_probe_read_kernel_str(p_comm_buf->_buff_, TASK_COMM_LEN, parent->comm);
    }

    grandparent = BPF_CORE_READ(parent,real_parent);
    if (grandparent) {
        bpf_probe_read_kernel_str(grand_p_comm_buf->_buff_, TASK_COMM_LEN, grandparent->comm);
    }

    if(comm_buf->_buff_[0] == '\0' || p_comm_buf->_buff_[0] == '\0' || grand_p_comm_buf->_buff_[0] == '\0') {
        char_memory_delete(&comm_key);
        char_memory_delete(&p_comm_key);
        char_memory_delete(&grand_p_comm_key);
        FULLY_DEBUG(__DEBUG__,
                            (VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("*** Something wrong (unknown #1) with comms %s, parent %s, gparent %s  [%d,%d]***\n", comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_,hook_ctx->key.hook, hook_ctx->key.pid));
        RET_REJECT
    }

    struct execPath * ePath = getExecPath(task,createTaskUKey(task,&hook_ctx->taskUKey));
    if(!ePath) {
        FULLY_DEBUG(__DEBUG__,
                            (VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("*** Lack of Process Execution Address, Reject Directly ***\n", hook_ctx->key.hook, hook_ctx->key.pid));
        RET_REJECT
    }

    struct execPath * parent_ePath = getExecPath(parent, createTaskUKey(parent, &hook_ctx->taskUKeyParent));

    if(!parent_ePath) {
        FULLY_DEBUG(__DEBUG__,
                            (VERBOSE | HIGH | EXTERA),bpf_printk("*** Lack of Parent Execution Address, Assign Process to Parent ***\n", hook_ctx->key.hook, hook_ctx->key.pid));
        parent_ePath = ePath;
    }

    struct execPath * grandparent_ePath = getExecPath(parent, createTaskUKey(grandparent, &hook_ctx->taskUKeyGrandParent));
    if(!grandparent_ePath){
        FULLY_DEBUG(__DEBUG__,
                            (VERBOSE | HIGH | EXTERA),bpf_printk("*** Lack of Grand-Parent Execution Address, Assign Parent to Grand ***\n", hook_ctx->key.hook, hook_ctx->key.pid));
        grandparent_ePath = parent_ePath;
    }

    hook_ctx->task_grandparent = grandparent;
    hook_ctx->task_parent = parent;

    // Compute hashes once for fast comparison
    __u32 comm_hash = str_to_u32(comm_buf->_buff_);
    __u32 parent_hash = str_to_u32(p_comm_buf->_buff_);
    __u32 grandparent_hash = str_to_u32(grand_p_comm_buf->_buff_);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("***Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} \n", hook_ctx->key.hook,hook_ctx->key.pid, comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_));

    struct process_relation *prm;
    __u32 _safeCounter_=0;
    int _redirectIndex_=-1;
    int _pattern_prog_number_=-1;

    for (__u32 i = 0; i < MAX_NUMBER_OF_RELATION; i++) {
        _safeCounter_=i;

        if(_redirectIndex_ > 0 && _safeCounter_ < _redirectIndex_) continue;

        prm = bpf_map_lookup_elem(&prm_map, &_safeCounter_);

        if(prm){

            if(prm->process[0] == '\0' || prm->parent[0] == '\0' || prm->grandparent[0] == '\0' || prm->action == NONE_ACTION) continue;

            if((prm->hookType != NONE_CELL) && (prm->hookType != hook_ctx->key.hook)) continue;

            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Check the relation : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,&comm_buf->_buff_[0], &p_comm_buf->_buff_[0], &grand_p_comm_buf->_buff_[0] , 
                                            prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType)); 
            
            // Symmetric rule: check if hash matches any position
            if(prm->is_symmetric) {
                if(prm->symmetric_hash != comm_hash && 
                   prm->symmetric_hash != parent_hash && 
                   prm->symmetric_hash != grandparent_hash) {
                    continue;
                }
            } else {
                // Normal rule: check each field individually
                if(prm->process[0] != PREFIX_NOCARE[0] && prm->process[0] != PREFIX_INVALID_BINARY[0]) {
                    if(prm->process_hash != comm_hash) continue;
                } else if(prm->process[0] == PREFIX_INVALID_BINARY[0] && ePath->isValidDirectory == 1) {
                    continue;
                }

                if(prm->parent[0] != PREFIX_NOCARE[0] && prm->parent[0] != PREFIX_INVALID_BINARY[0]) {
                    if(prm->parent_hash != parent_hash) continue;
                } else if(prm->parent[0] == PREFIX_INVALID_BINARY[0] && parent_ePath->isValidDirectory == 1) {
                    continue;
                }

                if(prm->grandparent[0] != PREFIX_NOCARE[0] && prm->grandparent[0] != PREFIX_INVALID_BINARY[0]) {
                    if(prm->grandparent_hash != grandparent_hash) continue;
                } else if(prm->grandparent[0] == PREFIX_INVALID_BINARY[0] && grandparent_ePath->isValidDirectory == 1) {
                    continue;
                }
            }

            
            FULLY_DEBUG(__DEBUG__,
                (VERBOSE | HIGH | EXTERA ),
                bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,
                    comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_ , 
                                        prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType)
                                    );
            switch (prm->action)
            {
                case ACCEPT:
                    
                    if((prm->process[0] == PREFIX_NOCARE[0] && prm->parent[0] == PREFIX_NOCARE[0] && prm->grandparent[0] == PREFIX_NOCARE[0])){
                        FULLY_DEBUG(__DEBUG__,
                        (VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("*** INVALID ACCEPT ROLE , FULL PREFIX , Role#%d ***\n",_safeCounter_));
                        RET_REJECT
                    }

                    if(ePath->isValidDirectory == 0 || parent_ePath->isValidDirectory == 0 || grandparent_ePath->isValidDirectory == 0) {
                        
                        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d) Matched the relation with ACCEPT action , (REJECT) (Invalid rules due to invalid directory)\n", hook_ctx->key.hook, hook_ctx->key.pid));
                        RET_REJECT
                    }
                    
                    if(ePath->isContainerTask == 1 || parent_ePath->isContainerTask == 1 || grandparent_ePath->isContainerTask == 1) {
                        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d) Matched the relation with ACCEPT action , (REJECT) (Invalid rules due to comeing from Container)\n", hook_ctx->key.hook, hook_ctx->key.pid));
                        RET_REJECT
                    }

                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (ACCEPT) (Added to Cache) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid, comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_ , 
                                        prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));

                    hook_ctx->key.crecord.direct_relation=_safeCounter_;
                    addLRUCache(&hook_ctx->key);
                    RET_ACCEPT
                case REJECT:
                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (REJECT) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_ , 
                                        prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                    RET_REJECT
                case REDIRECT:
                    if(prm->redirectIndex < MAX_NUMBER_OF_RELATION && prm->redirectIndex >= _safeCounter_){
                        if(prm->redirectIndex == _safeCounter_){
                            _redirectIndex_= -1;
                            _pattern_prog_number_ = -1;
                            addLRUCache(&hook_ctx->key);
                            RET_ACCEPT
                        }
                        else{
                            _redirectIndex_ = prm->redirectIndex;
                            if(prm->protectZone != 1 && prm->protectZone != 0){
                                _pattern_prog_number_ = prm->protectZone;
                            }
                            continue;
                        }
                    }
                    else {
                        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (Redirect Action - Wrong Zone - Wrong Redirect Index) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_ , 
                                        prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                        continue;
                    }
                    break;
                case DEBUG:
                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (Debug Action) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_ , 
                                        prm->process , prm->parent, prm->grandparent, prm->action, prm->redirectIndex,prm->protectZone, prm->hookType));
                    continue;
                case BYPASS:
                    continue;
                case RETURN:
                    _pattern_prog_number_= (_pattern_prog_number_== -1 ? prm->redirectIndex: _pattern_prog_number_);

                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (Return Action) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_ , 
                                        prm->process , prm->parent, prm->grandparent, prm->action, _pattern_prog_number_,prm->protectZone, prm->hookType));
                    
                    if(
                        (hook_ctx->key.crecord.active_entries >= 0 && hook_ctx->key.crecord.active_entries < MAX_CACHE_ENTRIES)

                        && 

                        (_pattern_prog_number_ >=0 && _pattern_prog_number_ < PROG_Numbers)
                    )
                    {
                        hook_ctx->key.crecord.direct_relation= _safeCounter_;
                        hook_ctx->key.crecord.is_valid_entries= 1;
                        hook_ctx->key.crecord.prog_tb_id= _pattern_prog_number_;
                    }
                    else RET_ACCEPT

                    switch (PRM_PROG_Dispatcher(hook_ctx, _pattern_prog_number_, PROG)) {
                        case 0:
                            addLRUCache(&hook_ctx->key);
                            RET_ACCEPT
                        case 1:
                            char_memory_delete(&comm_key);
                            char_memory_delete(&p_comm_key);
                            char_memory_delete(&grand_p_comm_key);
                            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("PROG: Hook(%d)-PID(%d) {%s -> %s -> %s} Matched the relation (REJECT) : {%s,%s,%s, Action=%d, RedirectIndex=%d, Zone=%d, Hook=%d}\n", hook_ctx->key.hook, hook_ctx->key.pid,comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_ , 
                                        prm->process , prm->parent, prm->grandparent, prm->action, _pattern_prog_number_,prm->protectZone, prm->hookType));
                            RET_REJECT
                        case 2:
                            char_memory_delete(&comm_key);
                            char_memory_delete(&p_comm_key);
                            char_memory_delete(&grand_p_comm_key);
                            RET_ACCEPT
                        default:
                            char_memory_delete(&comm_key);
                            char_memory_delete(&p_comm_key);
                            char_memory_delete(&grand_p_comm_key);
                            RET_REJECT
                    }
                case END:
                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("<<<END>>>: Hook(%d)-PID(%d) {%s -> %s -> %s} Not being Matched with any relations (Take it as White Process - Or Add Role) \n", hook_ctx->key.hook, hook_ctx->key.pid,comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_));

                    addLRUCache(&hook_ctx->key);

                    RET_ACCEPT
            }
        }
    }
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Unknown Hook Received: Hook(%d)-PID(%d) {%s -> %s -> %s} Not being Matched any relations (Take it as White Process - Or Add Role) \n", hook_ctx->key.hook, hook_ctx->key.pid,comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_));

    addLRUCache(&hook_ctx->key);

    RET_ACCEPT
}

static int detectSyscallRelations(struct hooks_context_t *hook_ctx) {
    __u32 output=0;
    __u32 input=0;

    __INJECT_FILTERS__(hook_ctx,input,output)
}

static int entryStartPoint(struct hooks_context_t *hook_ctx){
    __u32 key=0;
    struct SelfPID *value= bpf_map_lookup_elem(&self_pids, &key);

    if (value && value->pid == hook_ctx->key.pid && value->magic==MAGIC_VALUE) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("Hook Received: Hook(%d)-PID(%d) Self-PID , Internal Hooks \n", hook_ctx->key.hook, hook_ctx->key.pid));
        return 0;
    }

    // Check blacklist first - instant rejection with hash fingerprint matching
    struct cache_record *blacklisted = bpf_map_lookup_elem(&blacklist, &hook_ctx->key);
    if (blacklisted) {
        // Compute current fingerprints and compare
        if(blacklisted->is_valid_entries == 1) {
            PRM_PROG_Dispatcher(hook_ctx, blacklisted->prog_tb_id, FINGER);
            
            // Check if fingerprints match
            bool match = true;
            for(int i=0; i < MAX_CACHE_ENTRIES; i++) {
                if(blacklisted->cache_entries[i].is_valid == 1 && hook_ctx->key.crecord.cache_entries[i].is_valid == 1) {
                    if(blacklisted->cache_entries[i].hash != hook_ctx->key.crecord.cache_entries[i].hash) {
                        match = false;
                        break;
                    }
                }
            }
            
            if(match) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d)-TPID(%d) BLACKLISTED - Fingerprint Match - Instant Reject\n", hook_ctx->key.hook, hook_ctx->key.pid, hook_ctx->key.tpid));
                return -EPERM;
            }
        } else {
            // No fingerprints, reject all
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d)-TPID(%d) BLACKLISTED - Instant Reject\n", hook_ctx->key.hook, hook_ctx->key.pid, hook_ctx->key.tpid));
            return -EPERM;
        }
    }

    if(!checkLRUCache(hook_ctx)) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("Hook Received: Hook(%d)-PID(%d) Matched with process white list \n", hook_ctx->key.hook, hook_ctx->key.pid));
        return 0;
    }

    if(detectSyscallRelations(hook_ctx) && PRMVerifier(hook_ctx)){
        // Add to blacklist on rejection with hash fingerprints
        if(hook_ctx->key.crecord.is_valid_entries == 1) {
            __u32 crecord_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 500;
            struct cache_record *crecord = cache_record_memory_allocate(&crecord_key, NULL);
            if (crecord) {
                bpf_probe_read(crecord, sizeof(*crecord), &hook_ctx->key.crecord);
                bpf_map_update_elem(&blacklist, &hook_ctx->key, crecord, BPF_ANY);
                cache_record_memory_delete(&crecord_key);
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d)-TPID(%d) REJECTED - Added to Blacklist with Fingerprints\n", hook_ctx->key.hook, hook_ctx->key.pid, hook_ctx->key.tpid));
            }
        } else {
            // No fingerprints, blacklist all
            bpf_map_update_elem(&blacklist, &hook_ctx->key, &hook_ctx->key.crecord, BPF_ANY);
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("Hook Received: Hook(%d)-PID(%d)-TPID(%d) REJECTED - Added to Blacklist\n", hook_ctx->key.hook, hook_ctx->key.pid, hook_ctx->key.tpid));
        }
        
        return -EPERM;
    }

    return 0;
}

static int saveSelfPID(struct hooks_context_t * hook_ctx){
    __u32 key=0;
    
    struct SelfPID *value = bpf_map_lookup_elem(&self_pids, &key);
    
    if(value && value->pid == EMPTY && value->magic == EMPTY){
        struct SelfPID currentValue = {.pid=hook_ctx->key.pid,.magic=MAGIC_VALUE};

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("PRM verifier is setting up its PID : %d",hook_ctx->key.pid));
        
        bpf_map_update_elem(&self_pids, &key, &currentValue, BPF_ANY);

        struct prm_state *prm_state;
        __u32 key = 0;
        prm_state = bpf_map_lookup_elem(&prm_state_map, &key);
        if (!prm_state) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("PRM is loading up PID : %d",hook_ctx->key.pid));
            return Load_PRM();
        }
        else if (prm_state->prm_state == UNLOADED){
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("PRM has been unloaded , PRM is loading up again PID : %d",hook_ctx->key.pid));
            return Load_PRM();
        }

        return 0;
    }
    else if (value && value->pid == hook_ctx->key.pid && value->magic==MAGIC_VALUE) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("Hook Received: Hook(%d)-PID(%d) Self-PID , Internal Hooks \n", hook_ctx->key.hook, hook_ctx->key.pid));
        return 0;
    }
    else {
        struct task_struct *task = bpf_get_current_task_btf();
        if (!task) return -EPERM;
        
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(comm, sizeof(comm));
        
        bool process_valid = false;
        checkValidElemConfigSTR(comm, HookValidList, process_valid = true;)
        
        if (process_valid) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Process %s found in HookValidList - accepting", comm));
            return 0;
        } else {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Process %s not in HookValidList - rejecting", comm));
            return -EPERM;
        }
    }
}

static int kernelThreadCheck(struct hooks_context_t *hook_ctx){
    struct task_struct *_task_ =  hook_ctx->task;
    if ((!_task_))
    {
        FULLY_DEBUG(__DEBUG__, (VERBOSE | HIGH | EXTERA), bpf_printk("There is no TASK !!!! ****PID(%d)\n", hook_ctx->key.pid));
        return 1;
    }
    if ((BPF_CORE_READ(_task_, flags) & PF_KTHREAD))
    {
        FULLY_DEBUG(__DEBUG__, (VERBOSE | HIGH | EXTERA), bpf_printk("Skipping kernel thread PID(%d)\n", hook_ctx->key.pid));
        return 1;
    }
    struct mm_struct *_mm_ = BPF_CORE_READ(_task_, mm);
    if ((!_mm_))
    {
        FULLY_DEBUG(__DEBUG__, (VERBOSE | HIGH | EXTERA), bpf_printk("Skipping kernel process with NULL mm PID(%d)\n", hook_ctx->key.pid));
        return 1;
    }

    return 0;
}
static struct taskUKey * createTaskUKey(struct task_struct *etask, struct taskUKey * taskUKey){
    if (!etask || !taskUKey) return 0;
    
    bpf_core_read_str(taskUKey->comm, sizeof(taskUKey->comm), &(etask->comm));

    taskUKey->tgid = BPF_CORE_READ(etask, tgid);
    
    bpf_core_read(&taskUKey->startTime, sizeof(taskUKey->startTime), &(etask->start_time));
    
    return taskUKey;
}
static struct execPath * getExecPath(struct task_struct * task, struct taskUKey * taskUKey){
    struct task_struct *_task_ =  task;
    if (!_task_ || !taskUKey)
    {
        return 0;
    }
    struct mm_struct *_mm_ = BPF_CORE_READ(_task_, mm);
    if ((!_mm_))
    {
        return 0;
    }

    struct execPath *path = execPath_memory_allocate(taskUKey);

    if(path && path->startIndex == -1){
            struct file *exe_file = BPF_CORE_READ(_mm_, exe_file);
            if (exe_file)
            {
                struct dentry *current = BPF_CORE_READ(exe_file, f_path.dentry);

                if (!current) return 0;

                char *ptr_name;
                int i = 0;

                for (i = 0; i <= MAX_DIR_ITR*3; i++)
                {

                    if (!current || current == BPF_CORE_READ(current, d_parent))
                    {
                        break;
                    }

                    current = BPF_CORE_READ(current, d_parent);
                }

                current = BPF_CORE_READ(exe_file, f_path.dentry);
                if (!current || i >= MAX_DIR_ITR*3) return 0;

                for (int j = i; j >= 0; j--)
                {
                    if (j >= MAX_DIR_ITR)
                    {
                        current = BPF_CORE_READ(current, d_parent);
                    }
                    else if (j < MAX_DIR_ITR)
                    {
                        ptr_name = BPF_CORE_READ(current, d_name.name);
                        if (ptr_name)
                        {
                            bpf_probe_read_kernel(path->exec[j], sizeof(MAX_STR), ptr_name);
                        }

                        current = BPF_CORE_READ(current, d_parent);
                    }
                }

                path->startIndex = i;
            }

            if(path->startIndex >=1){
                checkValidElemConfigSTR(path->exec[1],BinaryHomeDirectory,path->isValidDirectory=1;)
            }
        
        path->isContainerTask = is_containerized_root(_task_);
    }

    return path;
}