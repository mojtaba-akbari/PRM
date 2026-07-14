/* PROG Module: denyLoadModule
 * Hook: KERNEL_MODULE_REQUEST
 * Slot: 8
 *
 * Blocks loading of kernel modules matching ModuleDeny config prefixes.
 */

static __u32 denyLoadModule_prog(struct hooks_context_t *hook_ctx){
    char *kmod_name = hook_ctx->args.kernel_module_request.kmod_name;
    if(!kmod_name) RET_ACCEPT

    __u64 module_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 600;
    struct empty_buffer *module_name_buf = char_memory_allocate(&module_key, NULL);
    if (!module_name_buf) {
        char_memory_delete(&module_key);
        RET_ACCEPT
    }

    bpf_core_read_str(module_name_buf->_buff_, MAX_STR, kmod_name);
    
    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: Kernel module load requested: %s", module_name_buf->_buff_));

    checkValidElemConfigForceSTRLen(module_name_buf->_buff_, ModuleDeny, RET_REJECT)
    
    char_memory_delete(&module_key);

    FLAG_FOR_HASH(hook_ctx, str_to_u32(module_name_buf->_buff_), 0, 0)
    RET_ACCEPT
}

static __u32 denyLoadModule_fingerprint(struct hooks_context_t *hook_ctx){
    char *kmod_name = hook_ctx->args.kernel_module_request.kmod_name;
    if(!kmod_name) RET_ACCEPT

    __u64 module_key = generate_tmp_ukey(hook_ctx->key.pid, hook_ctx->key.tpid) + 601;
    struct empty_buffer *module_name_buf = char_memory_allocate(&module_key, NULL);
    if (!module_name_buf) {
        char_memory_delete(&module_key);
        RET_ACCEPT
    }

    bpf_core_read_str(module_name_buf->_buff_, MAX_STR, kmod_name);
    
    FLAG_FOR_HASH(hook_ctx, str_to_u32(module_name_buf->_buff_), 0, 0)
    char_memory_delete(&module_key);
    RET_ACCEPT
}

__PROG_REGISTER__(denyLoadModule, KERNEL_MODULE_REQUEST, denyLoadModule_prog, denyLoadModule_fingerprint)
