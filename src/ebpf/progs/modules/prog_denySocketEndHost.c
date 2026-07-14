/* PROG Module: denyMakeSocketToEndHost
 * Hook: SOCKET_CONNECT
 * Slot: 3
 *
 * Blocks outbound connections matching IPDestRules config.
 * Also rejects invalid socket families from SocketProtocolInvalid.
 * AF_UNSPEC (family 0) is accepted early (harmless disconnect).
 */

static __u32 denyMakeSocketToEndHost_prog(struct hooks_context_t *hook_ctx){
    struct sockaddr *address = hook_ctx->args.socket_connect.address;
    if(!address) RET_ACCEPT

    __u32 dest_ip = 0;
    __u16 dest_port = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(address, sa_family);

    if (family == 0) RET_ACCEPT

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: Outbound Family connection to %d", family));
    checkValidElemConfigNUMBER(family, SocketProtocolInvalid, RET_REJECT)

    if (family == AF_INET) {
        dest_ip = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);
        dest_port = BPF_CORE_READ((struct sockaddr_in *)address, sin_port);
        dest_port = (dest_port >> 8) | (dest_port << 8);

        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: Outbound connection to %pI4 port %d", &dest_ip, dest_port));

        int len = sizeof(IPDestRules._holder_) / sizeof(IPDestRules._holder_[0]);
        for(int i = 0; i < len; i++) {
            if (ip_in_subnet(dest_ip, dest_port, IPDestRules._holder_[i])) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Outbound connection denied to port %d", dest_port));
                RET_REJECT
            }
        }
    }

    FLAG_FOR_HASH(hook_ctx, dest_ip, dest_port, family)
    RET_ACCEPT
}

static __u32 denyMakeSocketToEndHost_fingerprint(struct hooks_context_t *hook_ctx){
    struct sockaddr *address = hook_ctx->args.socket_connect.address;
    if(!address) RET_ACCEPT

    __u32 dest_ip = 0;
    __u16 dest_port = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(address, sa_family);

    if (family == AF_INET) {
        dest_ip = BPF_CORE_READ((struct sockaddr_in *)address, sin_addr.s_addr);
        dest_port = BPF_CORE_READ((struct sockaddr_in *)address, sin_port);
        dest_port = (dest_port >> 8) | (dest_port<<8);
    }
    
    FLAG_FOR_HASH(hook_ctx, dest_ip, dest_port, family)
    RET_ACCEPT
}

__PROG_REGISTER__(denyMakeSocketToEndHost, SOCKET_CONNECT, denyMakeSocketToEndHost_prog, denyMakeSocketToEndHost_fingerprint)
