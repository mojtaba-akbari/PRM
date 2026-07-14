/* PROG Module: TEMPLATE
 * Hook: <HOOK_TYPE>  (e.g., FILE_OPEN, SOCKET_CONNECT, BPRM_SECURITY, etc.)
 * Slot: <N>          (assign in conf/PRMProg.h)
 *
 * Description: <what this module does>
 *
 * ─── HOW TO CREATE A NEW MODULE ───────────────────────────────────────────
 *
 * 1. Copy this file to: progs/modules/prog_yourName.c
 * 2. Implement your _prog function (enforcement logic)
 * 3. Implement your _fingerprint function (parameter extraction for cache)
 * 4. Register with __PROG_REGISTER__
 * 5. Add #include in progs/PRMProgEntry.c
 * 6. Assign slot in conf/PRMProg.h:  #define PROG_N yourName
 * 7. Add RETURN rule in conf/PRM.h pointing to your slot
 * 8. Rebuild: make ebpf
 *
 * ─── RULES ────────────────────────────────────────────────────────────────
 *
 * - _prog returns:
 *     RET_ACCEPT          → allow, cache with fingerprint
 *     RET_REJECT          → deny, add to blacklist
 *     RET_ACCEPT_FORCEFULLY → allow, skip caching entirely
 *
 * - _fingerprint must:
 *     Extract the SAME parameters as _prog
 *     Call FLAG_FOR_HASH with the same values
 *     Return RET_ACCEPT
 *
 * - FLAG_FOR_HASH(hook_ctx, val1, val2, val3):
 *     Computes Jenkins hash of (val1, val2, val3) and stores in cache slot.
 *     Call it on the ACCEPT path in _prog.
 *     Call it unconditionally in _fingerprint.
 *     If parameters change between calls → cache miss → full re-evaluation.
 *
 * - Available helpers:
 *     checkValidElemConfigSTR(buf, ConfigName, on_match_action)
 *     checkValidElemConfigNUMBER(val, ConfigName, on_match_action)
 *     checkValidElemConfigForceSTRLen(buf, ConfigName, on_match_action)
 *     lineageUIDAnalizer(task, ukey) → severity score
 *     is_containerized_root(task) → bool
 *     ip_in_subnet(ip, port, rule_string) → bool
 *     char_memory_allocate(key, NULL) → buffer
 *     char_memory_delete(key)
 *     str_to_u32(buf) → first 4 bytes as __u32
 *     generate_tmp_ukey(pid, tpid) → unique key for temp allocations
 *
 * ─── MOCK MODE ────────────────────────────────────────────────────────────
 *
 * To test without enforcing, wrap your reject in:
 *   #ifdef PRM_MOCK_MODE
 *     bpf_printk("MOCK: would reject ...");
 *     RET_ACCEPT
 *   #else
 *     RET_REJECT
 *   #endif
 */

/*
static __u32 yourName_prog(struct hooks_context_t *hook_ctx){
    // Extract parameters from hook_ctx->args.<hook_type>.*
    // Validate / check against config
    // On reject: RET_REJECT
    // On accept:
    FLAG_FOR_HASH(hook_ctx, param1, param2, param3)
    RET_ACCEPT
}

static __u32 yourName_fingerprint(struct hooks_context_t *hook_ctx){
    // Extract the SAME parameters (no enforcement logic)
    FLAG_FOR_HASH(hook_ctx, param1, param2, param3)
    RET_ACCEPT
}

__PROG_REGISTER__(yourName, HOOK_TYPE, yourName_prog, yourName_fingerprint)
*/
