#include "../include/PRMCacheService.h"

static int addLRUCache(struct UniqueKey * key){
    if(!key) RET_REJECT

    if(key->crecord.is_valid_entries == 1){
        __u32 crecord_key = generate_tmp_ukey(key->pid, key->tpid) + 400;
        struct cache_record *crecord = cache_record_memory_allocate(&crecord_key, NULL);
        if (!crecord) {
            cache_record_memory_delete(&crecord_key);
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("*** Warning , Cache Record Heap ERROR ***\n"));
            RET_REJECT
        }
        

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Adding to cache , Comes from Prog: Hook(%d)-PID(%d) {%d Prog}} \n",key->hook, key->pid, key->crecord.direct_relation));

        bpf_probe_read(crecord, sizeof(*crecord), &key->crecord);
        CLEAN_CACHE_RECORD(key)
        bpf_map_update_elem(&process_list, key, crecord, BPF_ANY);
        
        cache_record_memory_delete(&crecord_key);
    }
    else{
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Adding to cache , Comes from None-Prog: Hook(%d)-PID(%d) {%d Prog}} \n",key->hook, key->pid, key->crecord.direct_relation));
        bpf_map_update_elem(&process_list, key, &key->crecord, BPF_ANY);
    }

    RET_ACCEPT
}

static int checkLRUCache(struct hooks_context_t *hook_ctx){
    if(!hook_ctx) RET_REJECT
    
    struct cache_record *crecord = bpf_map_lookup_elem(&process_list, &hook_ctx->key);
    if(!crecord) RET_REJECT

    if(crecord->direct_relation != -1){
        struct process_relation *processTmpx=bpf_map_lookup_elem(&prm_map, &crecord->direct_relation);
        if(processTmpx){
            if(processTmpx->hookType == NONE_CELL || processTmpx->hookType == hook_ctx->key.hook){
                if(crecord->is_valid_entries == 1){
                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Asking for Cache fingerprints check {pid(%d) tpid(%d) hook(%d)}\n", hook_ctx->key.pid, hook_ctx->key.tpid, hook_ctx->key.hook));
                    return checkCacheEntries(hook_ctx, crecord);
                }
                else {
                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Checked cache: Hook(%d)-PID(%d) {%d Prog} --- direct-relation %d} \n",hook_ctx->key.hook, hook_ctx->key.pid, hook_ctx->key.crecord.direct_relation));
                    RET_ACCEPT
                }
            }
            else RET_REJECT
        }
    }
    else{
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("Checked cache: Hook(%d)-PID(%d) --- None-relation} \n",hook_ctx->key.hook, hook_ctx->key.pid));
        RET_ACCEPT
    }

    RET_REJECT
}

static int checkCacheEntries(struct hooks_context_t *hook_ctx, struct cache_record *crecord){
    if(!hook_ctx || !crecord) RET_REJECT

    PRM_PROG_Dispatcher(hook_ctx, crecord->prog_tb_id, FINGER); // We can use ctx memory to calculate new hashes //

    for(int i=0;i< MAX_CACHE_ENTRIES;i++){
        if(crecord->cache_entries[i].is_valid == 1 && hook_ctx->key.crecord.cache_entries[i].is_valid == 1) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Checking fingerprint for PID(%d) Hook(%d) {offset(%d) %x ?= %x}\n", hook_ctx->key.pid, hook_ctx->key.hook, i, crecord->cache_entries[i].hash, hook_ctx->key.crecord.cache_entries[i].hash));
            if(crecord->cache_entries[i].hash != hook_ctx->key.crecord.cache_entries[i].hash){

                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("Miss-Matched fingerprint for PID(%d) Hook(%d) {offset(%d) %x != %x}\n", hook_ctx->key.pid, hook_ctx->key.hook, i, crecord->cache_entries[i].hash, hook_ctx->key.crecord.cache_entries[i].hash));
                RET_REJECT
            }
        }
    }

    RET_ACCEPT
}