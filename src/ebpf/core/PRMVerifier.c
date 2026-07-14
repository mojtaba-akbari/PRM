#include "../conf/PRM.h"
#include "../conf/PRMConfig.h"
#include "../include/PRMStructs.h"
#include "../include/PRMProgStructs.h"
#include "../include/PRMCacheService.h"
#include "../include/PRMVerifier.h"
#include "../include/PRMProgDispatcher.h"
#include "../include/PRMFilters.h"
#include "PRMStructs.c"
#include "PRMFilters.c"
#include "../progs/PRMProgEntry.c"
#include "PRMProgDispatcher.c"
#include "PRMCacheService.c"

// Mojtaba, Verifier //

struct prm_loop_ctx {
    struct hooks_context_t *hook_ctx;
    struct execPath *ePath;
    struct execPath *parent_ePath;
    struct execPath *grandparent_ePath;
    struct empty_buffer *comm_buf;
    struct empty_buffer *p_comm_buf;
    struct empty_buffer *grand_p_comm_buf;
    __u32 comm_key;
    __u32 p_comm_key;
    __u32 grand_p_comm_key;
    __u32 comm_hash;
    __u32 parent_hash;
    __u32 grandparent_hash;
    int redirect_index;
    int pattern_prog_number;
    int result; // -1 = continue, 0 = accept, 1 = reject
};

static int prm_loop_callback(__u32 i, struct prm_loop_ctx *ctx) {
    if (ctx->result >= 0) return 1; // already decided, stop

    if (ctx->redirect_index > 0 && (__s32)i < ctx->redirect_index) return 0; // skip

    __u32 idx = i;
    struct process_relation *prm = bpf_map_lookup_elem(&prm_map, &idx);
    if (!prm) return 0;

    if (prm->process[0] == '\0' || prm->parent[0] == '\0' || prm->grandparent[0] == '\0' || prm->action == NONE_ACTION)
        return 0;

    if ((prm->hookType != NONE_CELL) && (prm->hookType != ctx->hook_ctx->key.hook))
        return 0;

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Checking rule for process ancestry: %s (child of %s, grandchild of %s) PID %d\n",
        prm->process, prm->parent, prm->grandparent, ctx->hook_ctx->key.pid));

    // matching
    if (prm->is_symmetric) {
        if (prm->symmetric_hash != ctx->comm_hash &&
            prm->symmetric_hash != ctx->parent_hash &&
            prm->symmetric_hash != ctx->grandparent_hash)
            return 0;
    } else {
        bool skip = false;

        char p0 = prm->process[0];
        if (p0 == PREFIX_INVALID_BINARY[0])
            skip = (ctx->ePath->isValidDirectory == 1);
        else if (p0 != PREFIX_NOCARE[0])
            skip = (prm->process_hash != ctx->comm_hash);

        if (!skip) {
            char pp0 = prm->parent[0];
            if (pp0 == PREFIX_INVALID_BINARY[0])
                skip = (ctx->parent_ePath->isValidDirectory == 1);
            else if (pp0 != PREFIX_NOCARE[0])
                skip = (prm->parent_hash != ctx->parent_hash);
        }

        if (!skip) {
            char gp0 = prm->grandparent[0];
            if (gp0 == PREFIX_INVALID_BINARY[0])
                skip = (ctx->grandparent_ePath->isValidDirectory == 1);
            else if (gp0 != PREFIX_NOCARE[0])
                skip = (prm->grandparent_hash != ctx->grandparent_hash);
        }

        if (skip) return 0;
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Rule matched for PID %d (action=%d, redirect=%d, zone=%d)\n",
        ctx->hook_ctx->key.pid, prm->action, prm->redirectIndex, prm->protectZone));

    switch (prm->action) {
    case ACCEPT:
        if (prm->process[0] == PREFIX_NOCARE[0] && prm->parent[0] == PREFIX_NOCARE[0] && prm->grandparent[0] == PREFIX_NOCARE[0]) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: Rule #%d tried to accept all processes (wildcard accept is not allowed) UID %d\n", i, ctx->hook_ctx->uid));
            ctx->result = 1;
            return 1;
        }
        if (ctx->ePath->isValidDirectory == 0 || ctx->parent_ePath->isValidDirectory == 0 || ctx->grandparent_ePath->isValidDirectory == 0) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: PID %d UID %d runs from an untrusted directory, access denied\n", ctx->hook_ctx->key.pid, ctx->hook_ctx->uid));
            ctx->result = 1;
            return 1;
        }
        if (ctx->ePath->isContainerTask == 1 || ctx->parent_ePath->isContainerTask == 1 || ctx->grandparent_ePath->isContainerTask == 1) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: PID %d UID %d originates from a container, access denied\n", ctx->hook_ctx->key.pid, ctx->hook_ctx->uid));
            ctx->result = 1;
            return 1;
        }
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | NOTHING),bpf_printk("ALLOWED: Process '%s' (child of '%s', grandchild of '%s') PID %d UID %d — decision cached\n",
            ctx->comm_buf->_buff_, ctx->p_comm_buf->_buff_, ctx->grand_p_comm_buf->_buff_, ctx->hook_ctx->key.pid, ctx->hook_ctx->uid));
        ctx->hook_ctx->key.crecord.direct_relation = i;
        addLRUCache(&ctx->hook_ctx->key);
        ctx->result = 0;
        return 1;

    case REJECT:
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: Process '%s' (child of '%s', grandchild of '%s') PID %d UID %d — rejected by security rule\n",
            ctx->comm_buf->_buff_, ctx->p_comm_buf->_buff_, ctx->grand_p_comm_buf->_buff_, ctx->hook_ctx->key.pid, ctx->hook_ctx->uid));
        ctx->result = 1;
        return 1;

    case REDIRECT:
        if (prm->redirectIndex < MAX_NUMBER_OF_RELATION && prm->redirectIndex >= i) {
            if (prm->redirectIndex == i) {
                ctx->redirect_index = -1;
                ctx->pattern_prog_number = -1;
                addLRUCache(&ctx->hook_ctx->key);
                ctx->result = 0;
                return 1;
            } else {
                ctx->redirect_index = prm->redirectIndex;
                if (prm->protectZone != 1 && prm->protectZone != 0)
                    ctx->pattern_prog_number = prm->protectZone;
                return 0; // continue
            }
        }
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("WARNING: PID %d hit a redirect rule with invalid target, skipping\n", ctx->hook_ctx->key.pid));
        return 0; // continue

    case DEBUG:
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | NOTHING),bpf_printk("DEBUG: Process '%s' (child of '%s', grandchild of '%s') PID %d — entered deep inspection zone\n",
            ctx->comm_buf->_buff_, ctx->p_comm_buf->_buff_, ctx->grand_p_comm_buf->_buff_, ctx->hook_ctx->key.pid));
        return 0;

    case BYPASS:
        return 0;

    case RETURN: {
        int prog_num = (ctx->pattern_prog_number == -1 ? prm->redirectIndex : ctx->pattern_prog_number);

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("INSPECT: PID %d UID %d forwarded to security handler #%d for deep analysis\n",
            ctx->hook_ctx->key.pid, ctx->hook_ctx->uid, prog_num));

        if ((ctx->hook_ctx->key.crecord.active_entries >= 0 && ctx->hook_ctx->key.crecord.active_entries < MAX_CACHE_ENTRIES)
            && (prog_num >= 0 && prog_num < PROG_Numbers)) {
            ctx->hook_ctx->key.crecord.direct_relation = i;
            ctx->hook_ctx->key.crecord.is_valid_entries = 1;
            ctx->hook_ctx->key.crecord.prog_tb_id = prog_num;
        } else {
            ctx->result = 0;
            return 1;
        }

        switch (PRM_PROG_Dispatcher(ctx->hook_ctx, prog_num, PROG)) {
        case 0:
            addLRUCache(&ctx->hook_ctx->key);
            ctx->result = 0;
            return 1;
        case 1:
            char_memory_delete(&ctx->comm_key);
            char_memory_delete(&ctx->p_comm_key);
            char_memory_delete(&ctx->grand_p_comm_key);
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: PID %d UID %d rejected by security handler #%d\n",
                ctx->hook_ctx->key.pid, ctx->hook_ctx->uid, prog_num));
            ctx->result = 1;
            return 1;
        case 2:
            char_memory_delete(&ctx->comm_key);
            char_memory_delete(&ctx->p_comm_key);
            char_memory_delete(&ctx->grand_p_comm_key);
            ctx->result = 0;
            return 1;
        default:
            char_memory_delete(&ctx->comm_key);
            char_memory_delete(&ctx->p_comm_key);
            char_memory_delete(&ctx->grand_p_comm_key);
            ctx->result = 1;
            return 1;
        }
    }

    case END:
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("ALLOWED: Process '%s' (child of '%s', grandchild of '%s') PID %d UID %d — no matching rule, treated as trusted\n",
            ctx->comm_buf->_buff_, ctx->p_comm_buf->_buff_, ctx->grand_p_comm_buf->_buff_, ctx->hook_ctx->key.pid, ctx->hook_ctx->uid));
        addLRUCache(&ctx->hook_ctx->key);
        ctx->result = 0;
        return 1;
    }

    return 0;
}

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
                            (VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("ERROR: Could not read process names for PID %d, blocking for safety\n", hook_ctx->key.pid));
        RET_REJECT
    }

    struct execPath * ePath = getExecPath(task,createTaskUKey(task,&hook_ctx->taskUKey));
    if(!ePath) {
        FULLY_DEBUG(__DEBUG__,
                            (VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: PID %d UID %d has no known binary path, rejected for safety\n", hook_ctx->key.pid, hook_ctx->uid));
        RET_REJECT
    }

    struct execPath * parent_ePath = getExecPath(parent, createTaskUKey(parent, &hook_ctx->taskUKeyParent));

    if(!parent_ePath) {
        FULLY_DEBUG(__DEBUG__,
                            (VERBOSE | HIGH | EXTERA),bpf_printk("INFO: PID %d parent binary path unknown, inheriting from child\n", hook_ctx->key.pid));
        parent_ePath = ePath;
    }

    struct execPath * grandparent_ePath = getExecPath(parent, createTaskUKey(grandparent, &hook_ctx->taskUKeyGrandParent));
    if(!grandparent_ePath){
        FULLY_DEBUG(__DEBUG__,
                            (VERBOSE | HIGH | EXTERA),bpf_printk("INFO: PID %d grandparent binary path unknown, inheriting from parent\n", hook_ctx->key.pid));
        grandparent_ePath = parent_ePath;
    }

    hook_ctx->task_grandparent = grandparent;
    hook_ctx->task_parent = parent;

    // Compute hashes once for fast comparison
    __u32 comm_hash = str_to_u32(comm_buf->_buff_);
    __u32 parent_hash = str_to_u32(p_comm_buf->_buff_);
    __u32 grandparent_hash = str_to_u32(grand_p_comm_buf->_buff_);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("SCAN: Process '%s' (child of '%s', grandchild of '%s') PID %d UID %d — evaluating security rules\n", comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_, hook_ctx->key.pid, hook_ctx->uid));

    struct prm_loop_ctx lctx = {
        .hook_ctx            = hook_ctx,
        .ePath               = ePath,
        .parent_ePath        = parent_ePath,
        .grandparent_ePath   = grandparent_ePath,
        .comm_buf            = comm_buf,
        .p_comm_buf          = p_comm_buf,
        .grand_p_comm_buf    = grand_p_comm_buf,
        .comm_key            = comm_key,
        .p_comm_key          = p_comm_key,
        .grand_p_comm_key    = grand_p_comm_key,
        .comm_hash           = comm_hash,
        .parent_hash         = parent_hash,
        .grandparent_hash    = grandparent_hash,
        .redirect_index      = -1,
        .pattern_prog_number = -1,
        .result              = -1,
    };

    bpf_loop(MAX_NUMBER_OF_RELATION, prm_loop_callback, &lctx, 0);

    if (lctx.result == 0) RET_ACCEPT
    if (lctx.result == 1) RET_REJECT

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("ALLOWED: Process '%s' (child of '%s', grandchild of '%s') PID %d UID %d — no matching rule found, treated as trusted\n",
        comm_buf->_buff_, p_comm_buf->_buff_, grand_p_comm_buf->_buff_, hook_ctx->key.pid, hook_ctx->uid));

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
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("SKIP: PID %d UID %d is PRM itself, allowing internal operation\n", hook_ctx->key.pid, hook_ctx->uid));
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
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: PID %d UID %d is blacklisted (fingerprint matched previous violation)\n", hook_ctx->key.pid, hook_ctx->uid));
                return -EPERM;
            }
        } else {
            // No fingerprints, reject all
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: PID %d UID %d is blacklisted from a previous violation\n", hook_ctx->key.pid, hook_ctx->uid));
            return -EPERM;
        }
    }

    if(!checkLRUCache(hook_ctx)) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("ALLOWED: PID %d UID %d found in cache (previously approved)\n", hook_ctx->key.pid, hook_ctx->uid));
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
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: PID %d UID %d rejected and added to blacklist (future calls will be instantly denied)\n", hook_ctx->key.pid, hook_ctx->uid));
            }
        } else {
            // No fingerprints, blacklist all
            bpf_map_update_elem(&blacklist, &hook_ctx->key, &hook_ctx->key.crecord, BPF_ANY);
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER | NOTHING),bpf_printk("BLOCKED: PID %d UID %d rejected and blacklisted\n", hook_ctx->key.pid, hook_ctx->uid));
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

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | NOTHING),bpf_printk("STARTUP: PRM registering itself as PID %d\n", hook_ctx->key.pid));
        
        bpf_map_update_elem(&self_pids, &key, &currentValue, BPF_ANY);

        struct prm_state *prm_state;
        __u32 key = 0;
        prm_state = bpf_map_lookup_elem(&prm_state_map, &key);
        if (!prm_state) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | NOTHING),bpf_printk("STARTUP: PRM loading security rules (PID %d)\n", hook_ctx->key.pid));
            return Load_PRM();
        }
        else if (prm_state->prm_state == UNLOADED){
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | NOTHING),bpf_printk("STARTUP: PRM was unloaded, reloading security rules (PID %d)\n", hook_ctx->key.pid));
            return Load_PRM();
        }

        return 0;
    }
    else if (value && value->pid == hook_ctx->key.pid && value->magic==MAGIC_VALUE) {
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH),bpf_printk("SKIP: PID %d is PRM itself, allowing\n", hook_ctx->key.pid));
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
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("ALLOWED: Process '%s' is a trusted system service\n", comm));
            return 0;
        } else {
            FULLY_DEBUG(__DEBUG__,(NOTHING | LOWER),bpf_printk("BLOCKED: Process '%s' is not a trusted system service\n", comm));
            return -EPERM;
        }
    }
}

static int kernelThreadCheck(struct hooks_context_t *hook_ctx){
    struct task_struct *_task_ =  hook_ctx->task;
    if ((!_task_))
    {
        FULLY_DEBUG(__DEBUG__, (VERBOSE | HIGH | EXTERA), bpf_printk("SKIP: PID %d has no task structure (kernel internal)\n", hook_ctx->key.pid));
        return 1;
    }
    if ((BPF_CORE_READ(_task_, flags) & PF_KTHREAD))
    {
        FULLY_DEBUG(__DEBUG__, (VERBOSE | HIGH | EXTERA), bpf_printk("SKIP: PID %d is a kernel thread, not monitored\n", hook_ctx->key.pid));
        return 1;
    }
    struct mm_struct *_mm_ = BPF_CORE_READ(_task_, mm);
    if ((!_mm_))
    {
        FULLY_DEBUG(__DEBUG__, (VERBOSE | HIGH | EXTERA), bpf_printk("SKIP: PID %d is a kernel process (no user memory), not monitored\n", hook_ctx->key.pid));
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