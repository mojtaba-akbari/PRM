#include "../include/PRMFilters.h"
#include "../conf/PRM.h"
#include "../include/PRMStructs.h"

// Filter1 Protect PRM from any GID , UID which is matched with Config File //
// If you put config file as empty items then this filter would be just a bypass filter //
// Always UID is more important than GID //
static __u32 filter1(struct hooks_context_t * hook, __u32 input)
{
    struct task_struct *task = bpf_get_current_task_btf();
    if (!task) return 1;
    
    __u32 real_gid = BPF_CORE_READ(task, cred, gid.val);
    __u32 real_uid = BPF_CORE_READ(task, cred, uid.val);
    
    bool isInvalidGID=0;
    bool isValidUID=0;

    checkValidElemConfigNUMBER(real_gid, UnSafeGID, isInvalidGID=1;)
    
    checkValidElemConfigNUMBER(real_uid, SafeUID, isValidUID=1;)

    if(isValidUID){
        return 0;
    }else if(isInvalidGID){
        FULLY_DEBUG(__DEBUG__, (VERBOSE | HIGH | EXTERA | NORMAL | LOWER), bpf_printk("INFO: User (GID=%d, UID=%d) is not in a trusted group", real_gid, real_uid));
        return 1; // redirect to verifier 
    }
    else return 1; // redirect to verifier
}
