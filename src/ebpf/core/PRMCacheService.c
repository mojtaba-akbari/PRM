#include "../include/PRMCacheService.h"

static int addLRUCache(struct UniqueKey * key){
    if(!key) RET_REJECT

    if(key->crecord.direct_relation != -1){
        __u32 crecord_key = generate_tmp_ukey(key->pid, key->tpid) + 400;
        struct cache_record *crecord = cache_record_memory_allocate(&crecord_key, NULL);
        if (!crecord) {
            cache_record_memory_delete(&crecord_key);
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("ERROR: Cache memory allocation failed\n"));
            RET_REJECT
        }
        

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("CACHE: Storing decision for PID %d (from security handler, rule #%d)\n",key->hook, key->pid, key->crecord.direct_relation));

        bpf_probe_read(crecord, sizeof(*crecord), &key->crecord);
        CLEAN_CACHE_RECORD(key)
        bpf_map_update_elem(&process_list, key, crecord, BPF_ANY);
        
        cache_record_memory_delete(&crecord_key);
    }
    else{
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("CACHE: Storing decision for PID %d (direct rule match)\n",key->hook, key->pid));
        CLEAN_CACHE_RECORD(key)
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
                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("CACHE: Verifying cached fingerprint for PID %d\n", hook_ctx->key.pid, hook_ctx->key.tpid, hook_ctx->key.hook));
                    return checkCacheEntries(hook_ctx, crecord);
                }
                else {
                    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("CACHE: PID %d matched cached rule #%d\n",hook_ctx->key.hook, hook_ctx->key.pid, hook_ctx->key.crecord.direct_relation));
                    RET_ACCEPT
                }
            }
            else RET_REJECT
        }
    }
    else{
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("CACHE: PID %d found in cache (no specific rule)\n",hook_ctx->key.hook, hook_ctx->key.pid));
        RET_ACCEPT
    }

    RET_REJECT
}

static int checkCacheEntries(struct hooks_context_t *hook_ctx, struct cache_record *crecord){
    if(!hook_ctx || !crecord) RET_REJECT

    PRM_PROG_Dispatcher(hook_ctx, crecord->prog_tb_id, FINGER); // We can use ctx memory to calculate new hashes //

    for(int i=0;i< MAX_CACHE_ENTRIES;i++){
        if(crecord->cache_entries[i].is_valid == 1 && hook_ctx->key.crecord.cache_entries[i].is_valid == 1) {
            FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("CACHE: Comparing fingerprint for PID %d (slot %d: %x vs %x)\n", hook_ctx->key.pid, hook_ctx->key.hook, i, crecord->cache_entries[i].hash, hook_ctx->key.crecord.cache_entries[i].hash));
            if(crecord->cache_entries[i].hash != hook_ctx->key.crecord.cache_entries[i].hash){

                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("CACHE: Fingerprint mismatch for PID %d (slot %d: %x != %x), re-evaluating\n", hook_ctx->key.pid, hook_ctx->key.hook, i, crecord->cache_entries[i].hash, hook_ctx->key.crecord.cache_entries[i].hash));
                RET_REJECT
            }
        }
    }

    RET_ACCEPT
}