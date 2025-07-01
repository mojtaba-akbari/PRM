#include "../../include/baseheaders.h"
#include "../../include/BTFFunctions.h"
#include "../include/PRMProgStructs.h"

// UID Section // Mojtaba Change Anything here will cause huge Chaose , do not change anything
static bool is_containerized_root(struct task_struct *task) {
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    if (!parent)
        return false;

    struct nsproxy *ns = BPF_CORE_READ(task, nsproxy);
    struct nsproxy *parent_ns = BPF_CORE_READ(parent, nsproxy);

    if (!ns || !parent_ns)
        return false;

    struct mnt_namespace *mnt_ns = BPF_CORE_READ(ns, mnt_ns);
    struct mnt_namespace *parent_mnt_ns = BPF_CORE_READ(parent_ns, mnt_ns);

    if (!mnt_ns || !parent_mnt_ns)
        return false;

    __u64 cur_ns_inum = BPF_CORE_READ(mnt_ns, ns.inum);
    __u64 parent_ns_inum = BPF_CORE_READ(parent_mnt_ns, ns.inum);

    return cur_ns_inum != parent_ns_inum;
}

static int symbolicUIDFindClosestPattern(struct UIDVectorAncestors *lineage) {
    __u16 worstPattern=0;
    struct UIDVector *pattern;
    if(!lineage) return worstPattern;

    __u32 _safeCounter_=0;
    __u32 _index_=0;
    
    for (__u32 i = 0; i < MAX_VECTORS; i++) {
        _safeCounter_ = i;
        pattern = bpf_map_lookup_elem(&uid_base_map, &_safeCounter_);
        if (!pattern)
            continue;

        for (__u32 j = 0; j <= MAX_ANCESTORS-MAX_VECTOR_CELL; j++) {
            if(lineage->val[j] == UIDEMPTYCELL) break;
            if (lineage->val[j] != pattern->val[0]) continue;

            if (lineage->val[j+1] != pattern->val[1]) continue;

            if (lineage->val[j+2] != pattern->val[2]) continue;

            if (lineage->val[j+3] != pattern->val[3]) continue;
            

            if(worstPattern < pattern->severity) {
                worstPattern = pattern->severity;
                _index_ = i;
            }
        }
    }

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("UID ancestors has been checked out and worstPattern %d , index %d\n", worstPattern, _index_));

    return worstPattern;
}


static int lineageUIDAnalizer(struct task_struct * task, struct UniqueKey * ukey){

    kuid_t real_uid = BPF_CORE_READ(task, real_cred, uid);
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    struct task_struct *parent_prv = parent;
    
    __u32 lineage_key = generate_tmp_ukey(ukey->pid, ukey->tpid) + 300;
    struct UIDVectorAncestors *lineage = lineage_memory_allocate(&lineage_key, NULL);
    if (!lineage) {
        lineage_memory_delete(&lineage_key);
        return BASE;
    }
    
    kuid_t parent_uid ;

    int uidHolder= real_uid.val> 0? real_uid.val: -1;
    
    __u8 tmpValue;
    
    tmpValue= real_uid.val >0 ? UIDWILDCARD : UIDROOT;
    if (0 < MAX_ANCESTORS) lineage->val[0] = tmpValue;

    #pragma clang loop unroll(disable)
    for (int i = 1; i < MAX_ANCESTORS && i < 32; i++) {
        // Early termination - preserve logic
        if(!parent){
            tmpValue = UIDEMPTYCELL;
            lineage->val[i] = tmpValue;
            continue;
        }

        // Read parent UID with safety
        struct cred *parent_cred = BPF_CORE_READ(parent, real_cred);
        if (!parent_cred) {
            tmpValue = UIDEMPTYCELL;
            lineage->val[i] = tmpValue;
            continue;
        }
        
        kuid_t parent_uid = BPF_CORE_READ(parent_cred, uid);

        // Preserve original logic
        if(uidHolder == -1){
            if(parent_uid.val > 0){
                tmpValue = UIDWILDCARD;
                uidHolder = parent_uid.val;
            }
            else {
                tmpValue = UIDROOT;
            }
        }
        else{
            if(parent_uid.val > 0 && uidHolder != parent_uid.val){
                tmpValue = UIDMISMATCH;
                uidHolder = parent_uid.val;
            }
            else if(parent_uid.val > 0 && uidHolder == parent_uid.val){
                tmpValue = UIDWILDCARD;
            }
            else {
                tmpValue = UIDROOT;
            }
        }

        lineage->val[i] = tmpValue;

        parent_prv=parent;
        
        // Safe parent traversal with termination check
        parent = BPF_CORE_READ(parent, real_parent);
    }

    int result = symbolicUIDFindClosestPattern(lineage);
    lineage_memory_delete(&lineage_key);
    
    return result;
}

// Network Sections // Mojtaba Try not to change anything because network pattern & flags
static __u32 to_network_order(__u32 hostlong) {
    return ((hostlong & 0xFF000000) >> 24) |
           ((hostlong & 0x00FF0000) >> 8)  |
           ((hostlong & 0x0000FF00) << 8)  |
           ((hostlong & 0x000000FF) << 24);
}

static int parse_ipv4_cidr(const char *input, __u32 *ip, __u32 *mask,  __u16 *port_start, __u16 *port_end) {
    int i = 0, octet = 0, cidr = 0;
    __u32 tmp_ip = 0;

    for (int part = 0; part < 4; part++) {
        octet = 0;
        for (; input[i] >= '0' && input[i] <= '9'; i++) {
            octet = octet * 10 + (input[i] - '0');
        }
        if (octet > 255) return -1; 
        tmp_ip = (tmp_ip << 8) | (__u8)octet;
        if (input[i] == '.') i++;
    }

    if (input[i++] != '/') return -1;

    for (; input[i] >= '0' && input[i] <= '9'; i++) {
        cidr = cidr * 10 + (input[i] - '0');
    }

    if (cidr > 32) return -1;

    *ip = to_network_order(tmp_ip);
    *mask = cidr ? to_network_order(0xFFFFFFFF << (32 - cidr)) : 0;

    if (input[i++] != ':') return -1;

    int port1 = 0, port2 = 0;
    for (; input[i] >= '0' && input[i] <= '9'; i++) {
        port1 = port1 * 10 + (input[i] - '0');
    }

    if (input[i] == '-') {
        i++;
        for (; input[i] >= '0' && input[i] <= '9'; i++) {
            port2 = port2 * 10 + (input[i] - '0');
        }
    } else {
        port2 = port1;
    }

    if (port1 < 0 || port2 < 0 || port1 > 65535 || port2 > 65535 || port1 > port2) return -1;

    *port_start = (__u16)port1;
    *port_end = (__u16)port2;

    return 0;
}

static int ip_in_subnet(__u32 target_ip, __u16 dst_port, const char *rule) {
    __u32 subnet_ip = 0, mask = 0;
    __u16 port_start = 0, port_end = 0;

    if (parse_ipv4_cidr(rule, &subnet_ip, &mask, &port_start, &port_end) != 0)
        return 0;

    ;

    FULLY_DEBUG(__DEBUG__,(VERBOSE | HIGH | EXTERA | NORMAL | LOWER),bpf_printk("SUBNET: %x, MASK: %x, TARGET: %x , PORT: %d %d", subnet_ip, mask, target_ip, port_start , port_end));

    return ((target_ip & mask) == (subnet_ip & mask)) &&
           (dst_port >= port_start && dst_port <= port_end);
}
