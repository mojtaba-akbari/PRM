/* PROG Module: denyIncomeSocket
 * Hook: SOCKET_ACCEPT
 * Slot: 6
 *
 * Filters incoming connections by source IP against IPSrcRules config.
 */

static __u32 denyIncomeSocket_prog(struct hooks_context_t *hook_ctx){
    struct socket *sock = hook_ctx->args.socket_accept.sock;
    if(!sock) RET_ACCEPT

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if(!sk) RET_ACCEPT

    __u32 src_ip = 0;
    __u16 dst_port = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);

    checkValidElemConfigNUMBER(family, SocketProtocolInvalid, RET_REJECT)

    if (family == AF_INET) {
        src_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        dst_port = BPF_CORE_READ(sk, __sk_common.skc_num);
        
        FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL),bpf_printk("INSPECT: Incoming connection from %pI4 to port %d", &src_ip, dst_port));

        int len = sizeof(IPSrcRules._holder_) / sizeof(IPSrcRules._holder_[0]);
        for(int i = 0; i < len; i++) {
            if (ip_in_subnet(src_ip, dst_port, IPSrcRules._holder_[i])) {
                FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("BLOCKED: Incoming connection denied for port %d (not in allowed range)", dst_port));
                RET_REJECT
            }   
        }
    }

    FLAG_FOR_HASH(hook_ctx, src_ip, dst_port, family)
    RET_ACCEPT
}

static __u32 denyIncomeSocket_fingerprint(struct hooks_context_t *hook_ctx){
    struct socket *sock = hook_ctx->args.socket_accept.sock;
    if(!sock) RET_ACCEPT

    struct sock *sk = BPF_CORE_READ(sock, sk);
    if(!sk) RET_ACCEPT

    __u32 src_ip = 0;
    __u16 dst_port = 0;
    __u16 family = 0;

    family = BPF_CORE_READ(sk, __sk_common.skc_family);

    if (family == AF_INET) {
        src_ip = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        dst_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    }
    
    FLAG_FOR_HASH(hook_ctx, src_ip, dst_port, family)
    RET_ACCEPT
}

__PROG_REGISTER__(denyIncomeSocket, SOCKET_ACCEPT, denyIncomeSocket_prog, denyIncomeSocket_fingerprint)
