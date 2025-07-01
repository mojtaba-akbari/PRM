#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_CACHE_STRUCT
#define FILTERING_SYSCALL_FRAMEWORK_PRM_CACHE_STRUCT

#include "../../include/baseheaders.h"
#include "../../include/BTFFunctions.h"
#include "PRMStructs.h"
#include "PRMProgStructs.h"







static inline int addLRUCache(struct UniqueKey * key);

static inline int checkLRUCache(struct hooks_context_t *hook_ctx);

static inline int checkCacheEntries(struct hooks_context_t *hook_ctx, struct cache_record *crecord);

#define NEW_CACHE_RECORD() ((struct cache_record))
#define UNIQUEKEY(pid_tgid,hooktype) ((struct UniqueKey){ .pid = (pid_tgid >> 32), .tpid = (pid_tgid << 0xFFFFFFFF), .hook = hooktype , .crecord = (struct cache_record){.direct_relation = -1, .is_valid_entries = 0, .active_entries = 0, .prog_tb_id=0, .cache_entries = {0} }})
#define FLAG_FOR_HASH(hook_ctx_ptr, a1 , a2 , a3) \
    if (hook_ctx_ptr->key.crecord.active_entries < MAX_CACHE_ENTRIES){ \
        hook_ctx_ptr->key.crecord.cache_entries[hook_ctx_ptr->key.crecord.active_entries].hash = jenkinsHash(a1,a2,a3); \
        hook_ctx_ptr->key.crecord.cache_entries[hook_ctx_ptr->key.crecord.active_entries].is_valid=1; \
        hook_ctx_ptr->key.crecord.active_entries++; \
    }
#define TAKE_HASH(a1 , a2 , a3) return jenkinsHash(a1, a2, a3);
#define CLEAN_CACHE_RECORD(UniqueKey) memset(&UniqueKey->crecord, 0, sizeof(struct cache_record)); UniqueKey->crecord.direct_relation = -1;

#endif