/* PROG Module: test
 * Hook: NONE (placeholder, always accepts)
 * Slot: 0
 *
 * Template for new PROG modules. Copy this file and modify.
 */

static __u32 test_prog(struct hooks_context_t *hook_ctx){
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA),bpf_printk("___PROG___TEST__BRANCH___\n"));
    RET_ACCEPT
}

static __u32 test_fingerprint(struct hooks_context_t *hook_ctx){
    RET_ACCEPT
}

__PROG_REGISTER__(test, NONE_CELL, test_prog, test_fingerprint)
