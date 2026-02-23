#include "../include/conf/PRM.h"
#include "../include/PRMStructs.h"
#include "../include/PRMProgStructs.h"

static __u32 jenkinsHash(__u32 a, __u32 b, __u32 c) {
    /*
        | Input                 | Behavior / Output                   | Explanation                                                       |
| --------------------- | ----------------------------------- | ----------------------------------------------------------------- |
| `a = 0, b = 0, c = 0` | `0`                                 | All operations are deterministic with no entropy to mix.          |
| `a = 0, b = 0, c = X` | Non-zero hash (unless X is small) | Mixing still happens due to presence of entropy in `c`.           |
| `a = 0, b = X, c = 0` | Non-zero hash                     | Same as above.                                                    |
| `a = X, b = 0, c = 0` | Non-zero hash                     | Again, as long as one value carries entropy, the result is mixed. |
| Any one value ≠ 0     | Still produces a useful hash      | Entropy propagates.                                               |
| All three values ≠ 0  | Best mixing, low collision risk   | Ideal usage.                                                      |

    */

    // If you need to pass char * to function , first convert string to __u32 with str_to_u32(char *) then pass it to jenkins
    a -= b; a -= c; a ^= (c >> 13);
    b -= c; b -= a; b ^= (a << 8);
    c -= a; c -= b; c ^= (b >> 13);
    a -= b; a -= c; a ^= (c >> 12);
    b -= c; b -= a; b ^= (a << 16);
    c -= a; c -= b; c ^= (b >> 5);
    a -= b; a -= c; a ^= (c >> 3);
    b -= c; b -= a; b ^= (a << 10);
    c -= a; c -= b; c ^= (b >> 15);
    return c;
}

static int init_relation_map() {
    bpf_printk("Preparing PRM Relation Map...");
    __u32 _safeCounter_=0;

    struct process_relation *processTmpx;

    for (int i = 0; i < MAX_NUMBER_OF_RELATION; i++) {
        _safeCounter_=i;
        processTmpx = &relation_data[_safeCounter_];
        
        if(processTmpx->process[0]=='\0' || processTmpx->parent[0]=='\0' || processTmpx->grandparent[0]=='\0')
        {
            bpf_printk("Role#%d Have been found fully EMPTY",_safeCounter_);
            processTmpx = & _prelation_empty_;
        }
        else{
            ASSERT_RUNTIME(strlen(processTmpx->process,MAX_RELATION_PROCESSNAME) > 0 , bpf_printk("Role#%d wrong process name",_safeCounter_));
            ASSERT_RUNTIME(strlen(processTmpx->parent,MAX_RELATION_PROCESSNAME) > 0 , bpf_printk("Role#%d wrong parent name",_safeCounter_));
            ASSERT_RUNTIME(strlen(processTmpx->grandparent,MAX_RELATION_PROCESSNAME) > 0 , bpf_printk("Role#%d wrong grand name",_safeCounter_));

            ASSERT_RUNTIME((processTmpx->action>=0) && (processTmpx->action<=5) , bpf_printk("Role#%d wrong action",_safeCounter_));
            //ASSERT_RUNTIME((processTmpx->action==6)&&(processTmpx->redirectIndex>=0) && (processTmpx->redirectIndex<=PROG_Numbers-1) , bpf_printk("Role#%d wrong Prog Numbers",_safeCounter_));
            ASSERT_RUNTIME((processTmpx->hookType>=0) && (processTmpx->hookType<=29) , bpf_printk("Role#%d wrong hook type",_safeCounter_)); // Fix me wrong boundry
            ASSERT_RUNTIME((processTmpx->redirectIndex>=0) && (processTmpx->redirectIndex<=MAX_NUMBER_OF_RELATION-1) , bpf_printk("Role#%d wrong redirect index",_safeCounter_));
            ASSERT_RUNTIME((processTmpx->protectZone >= 0 || processTmpx->protectZone <= MAX_NUMBER_OF_RELATION-1) , bpf_printk("Role#%d wrong protect zone flag index",_safeCounter_)); // Fix me wrong boundry
        }
        
        bpf_printk("Role Number #%d {(process=%s),(parent=%s),(grand=%s),(hookType=%d),(action=%d),(redirectIndex=%d),(protectZone=%d)} Loaded Up",_safeCounter_,processTmpx->process,
                        processTmpx->parent,processTmpx->grandparent,processTmpx->hookType,processTmpx->action,processTmpx->redirectIndex,processTmpx->protectZone);

        bpf_map_update_elem(&prm_map, &_safeCounter_, processTmpx, BPF_ANY);
    }

    return 0;
}

static int init_uid_base_map(){
    __u32 _safeCounter_ = 0;
    for (int i = 0; i < MAX_VECTORS; i++) {
        _safeCounter_=i;
        const struct UIDVector *vector = &base.entries[_safeCounter_];
        
        bpf_printk("UID vector loaded up : %d , severity %d",_safeCounter_,vector->severity);

        bpf_map_update_elem(&uid_base_map, &_safeCounter_, vector, BPF_ANY);
    }
    return 0;
}

static int Load_PRM(){
    bpf_printk("******Preparing PRM******");
    __u32 _index_=0;
    struct prm_state startup_state={STARTUP};
    struct prm_state loaded_state={LOADED};
    
    bpf_map_update_elem(&prm_state_map, &_index_, &startup_state, BPF_ANY);
    if(init_relation_map()) return 1;
    if(init_uid_base_map()) return 1;
    bpf_map_update_elem(&prm_state_map, &_index_, &loaded_state, BPF_ANY);
    return 0;
}

static struct empty_buffer * char_memory_allocate(__u32 * ukey, char * data){
    if(data) {
        if(bpf_map_update_elem(&tmp_buffer_, ukey, &_emptybuffer_, BPF_ANY) == 0){
                
            struct empty_buffer * eb = bpf_map_lookup_elem(&tmp_buffer_, ukey);
            if(eb){
                bpf_probe_read_kernel_str(eb->_buff_, HUGE_STR, data);

                return eb;
            }

            return NULL;
        }
    } else {
        if(bpf_map_update_elem(&tmp_buffer_, ukey, &_emptybuffer_, BPF_ANY) == 0)
            return bpf_map_lookup_elem(&tmp_buffer_, ukey);
    }
    return NULL;
}

static struct empty_buffer * char_memory_read(__u32 *ukey){
    return bpf_map_lookup_elem(&tmp_buffer_, ukey);
}

static __u32 char_memory_delete(__u32 *ukey){
    bpf_map_delete_elem(&tmp_buffer_, ukey);
    return 0;
}

static struct empty_buffer * char_memory_big_allocate(__u32 * ukey, char * data){
    if(data) {
        struct empty_buffer temp_buf = {0};
        bpf_probe_read_kernel_str(temp_buf._buff_, HUGE_STR, data);
        if(bpf_map_update_elem(&tmp_buffer_512B, ukey, &temp_buf, BPF_ANY) == 0)
            return bpf_map_lookup_elem(&tmp_buffer_512B, ukey);
    } else {
        if(bpf_map_update_elem(&tmp_buffer_512B, ukey, &_emptybuffer_, BPF_ANY) == 0)
            return bpf_map_lookup_elem(&tmp_buffer_512B, ukey);
    }
    return NULL;
}

static struct empty_buffer * char_memory_big_read(__u32 *ukey){
    return bpf_map_lookup_elem(&tmp_buffer_512B, ukey);
}

static __u32 char_memory_big_delete(__u32 *ukey){
    bpf_map_delete_elem(&tmp_buffer_512B, ukey);
    return 0;
}

static struct hooks_context_t * ctx_memory_allocate(__u32 * ukey){
    if(bpf_map_update_elem(&_ctx_holder_, ukey, &_emptyctx_, BPF_ANY) == 0)
        return bpf_map_lookup_elem(&_ctx_holder_, ukey);
    return NULL;
}

static struct execPath * execPath_memory_allocate(struct taskUKey * uk){
    struct execPath * path = bpf_map_lookup_elem(&execPath_list, uk);
    if(path) return path;

    if(bpf_map_update_elem(&execPath_list, uk, &_emptyexecpath_, BPF_ANY) == 0){
        return bpf_map_lookup_elem(&execPath_list, uk);
    }
    return NULL;
}

static struct execPath * execPath_memory_read(struct taskUKey * uk){
    if(!uk) return NULL;
    return bpf_map_lookup_elem(&execPath_list, uk);
}

static __u32 execPath_memory_delete(struct taskUKey * uk){
    bpf_map_delete_elem(&execPath_list, uk);
    return 0;
}

static struct UIDVectorAncestors * lineage_memory_allocate(__u32 * ukey, struct UIDVectorAncestors * data){
    if(data) {
        if(bpf_map_update_elem(&tmp_lineage, ukey, data, BPF_ANY) == 0)
            return bpf_map_lookup_elem(&tmp_lineage, ukey);
    } else {
        if(bpf_map_update_elem(&tmp_lineage, ukey, &_emptylineage_, BPF_ANY) == 0)
            return bpf_map_lookup_elem(&tmp_lineage, ukey);
    }
    return NULL;
}

static struct UIDVectorAncestors * lineage_memory_read(__u32 *ukey){
    return bpf_map_lookup_elem(&tmp_lineage, ukey);
}

static __u32 lineage_memory_delete(__u32 *ukey){
    bpf_map_delete_elem(&tmp_lineage, ukey);
    return 0;
}

static struct cache_record * cache_record_memory_allocate(__u32 * ukey, struct cache_record * data){
    if(data) {
        if(bpf_map_update_elem(&_cache_record_holder_, ukey, data, BPF_ANY) == 0)
            return bpf_map_lookup_elem(&_cache_record_holder_, ukey);
    } else {
        if(bpf_map_update_elem(&_cache_record_holder_, ukey, &_emptycacherecord_, BPF_ANY) == 0)
            return bpf_map_lookup_elem(&_cache_record_holder_, ukey);
    }
    return NULL;
}

static struct cache_record * cache_record_memory_read(__u32 *ukey){
    return bpf_map_lookup_elem(&_cache_record_holder_, ukey);
}

static __u32 cache_record_memory_delete(__u32 *ukey){
    bpf_map_delete_elem(&_cache_record_holder_, ukey);
    return 0;
}