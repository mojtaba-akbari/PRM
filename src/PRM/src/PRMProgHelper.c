#include "../../include/baseheaders.h"
#include "../../include/BTFFunctions.h"
#include "../include/PRMProgStructs.h"

// UID Section // Mojjjak: Change Anything here will cause huge Chaose
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

    struct pid_namespace *pid_ns = BPF_CORE_READ(ns, pid_ns_for_children);
    struct pid_namespace *parent_pid_ns = BPF_CORE_READ(parent_ns, pid_ns_for_children);
    if (!pid_ns || !parent_pid_ns)
        return false;

    struct uts_namespace *uts_ns = BPF_CORE_READ(ns, uts_ns);
    struct uts_namespace *parent_uts_ns = BPF_CORE_READ(parent_ns, uts_ns);
    if (!uts_ns || !parent_uts_ns)
        return false;

    __u64 cur_mnt_inum = BPF_CORE_READ(mnt_ns, ns.inum);
    __u64 parent_mnt_inum = BPF_CORE_READ(parent_mnt_ns, ns.inum);

    __u64 cur_pid_inum = BPF_CORE_READ(pid_ns, ns.inum);
    __u64 parent_pid_inum = BPF_CORE_READ(parent_pid_ns, ns.inum);

    __u64 cur_uts_inum = BPF_CORE_READ(uts_ns, ns.inum);
    __u64 parent_uts_inum = BPF_CORE_READ(parent_uts_ns, ns.inum);

    // Only mark as container if ALL these differ
    return (cur_mnt_inum != parent_mnt_inum) &&
           (cur_pid_inum != parent_pid_inum) &&
           (cur_uts_inum != parent_uts_inum);
}

static int symbolicUIDFindClosestPattern(__u32 lineage_key) {
    __u16 worstPattern=0;
    if(!lineage_key) return worstPattern;

    struct UIDVector *pattern;
    struct UIDVectorAncestors *lineage = lineage_memory_read(&lineage_key);
    if(!lineage) return worstPattern;

    __u32 _safeCounter_=0;
    __u32 _index_=0;
    
    for (__u32 i = 0; i < 16; i++) {
        _safeCounter_ = i;
        pattern = bpf_map_lookup_elem(&uid_base_map, &_safeCounter_);
        if (!pattern) break;

        // Check 4-element chunks: [0-3], [4-7], [8-11], [12-15]
        if ((lineage->val[0] == pattern->val[0] && lineage->val[1] == pattern->val[1] && lineage->val[2] == pattern->val[2] && lineage->val[3] == pattern->val[3])) {
            if(worstPattern < pattern->severity) {
                worstPattern = pattern->severity;
                _index_ = i;
            }
        }
        else if ((lineage->val[4] == pattern->val[0] && lineage->val[5] == pattern->val[1] && lineage->val[6] == pattern->val[2] && lineage->val[7] == pattern->val[3])) {
            if(worstPattern < pattern->severity) {
                worstPattern = pattern->severity;
                _index_ = i;
            }
        }
        else if ((lineage->val[8] == pattern->val[0] && lineage->val[9] == pattern->val[1] && lineage->val[10] == pattern->val[2] && lineage->val[11] == pattern->val[3])) {
            if(worstPattern < pattern->severity) {
                worstPattern = pattern->severity;
                _index_ = i;
            }
        }
        else if ((lineage->val[12] == pattern->val[0] && lineage->val[13] == pattern->val[1] && lineage->val[14] == pattern->val[2] && lineage->val[15] == pattern->val[3])) {
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
    if(!task || !ukey) return BASE;

    kuid_t real_uid = BPF_CORE_READ(task, real_cred, uid);
    if(real_uid.val < 0) return BASE;
    
    __u32 lineage_key = generate_tmp_ukey(ukey->pid, ukey->tpid) + 300;
    struct UIDVectorAncestors *lineage = lineage_memory_allocate(&lineage_key, NULL);
    if (!lineage) {
        lineage_memory_delete(&lineage_key);
        return BASE;
    }

    int uidHolder= real_uid.val> 0? real_uid.val: -1;
    
    __u8 tmpValue;
    
    tmpValue= real_uid.val >0 ? UIDWILDCARD : UIDROOT;
    if (0 < MAX_ANCESTORS) lineage->val[0] = tmpValue;

    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    struct task_struct *parent_prv = parent;

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

    for (int i = 0; i < MAX_ANCESTORS; i += 4) {
        bpf_printk("Lineage[%d-%d]: %d %d %d %d", i, i+3, 
                   lineage->val[i], lineage->val[i+1], lineage->val[i+2], lineage->val[i+3]);
    }

    int result = symbolicUIDFindClosestPattern(lineage_key);
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

// Filesystem Superblock Detection
static bool get_filesystem_info(struct file *file, char *sb_name, bool *is_kernel_fs, char *fs_type) {
    if (!file || !sb_name || !is_kernel_fs || !fs_type) return false;
    
    struct dentry *de = BPF_CORE_READ(file, f_path.dentry);
    if (!de) return false;
    
    struct super_block *sb = BPF_CORE_READ(de, d_sb);
    if (!sb) return false;
    
    struct file_system_type *fs = BPF_CORE_READ(sb, s_type);
    if (!fs) return false;
    
    const char *fs_name = BPF_CORE_READ(fs, name);
    if (!fs_name) return false;
    
    // Read filesystem type name to fs_type buffer
    bpf_probe_read_str(fs_type, MAX_STR, fs_name);
    
    // Detect kernel filesystems and set sb_name
    *is_kernel_fs = false;
    if (fs_type[0] == 'p' && fs_type[1] == 'r' && fs_type[2] == 'o' && fs_type[3] == 'c') {
        *is_kernel_fs = true;
        sb_name[0] = 'p'; sb_name[1] = 'r'; sb_name[2] = 'o'; sb_name[3] = 'c'; sb_name[4] = '\0';
    } else if (fs_type[0] == 's' && fs_type[1] == 'y' && fs_type[2] == 's') {
        *is_kernel_fs = true;
        sb_name[0] = 's'; sb_name[1] = 'y'; sb_name[2] = 's'; sb_name[3] = '\0';
    } else if (fs_type[0] == 'd' && fs_type[1] == 'e' && fs_type[2] == 'v') {
        *is_kernel_fs = true;
        sb_name[0] = 'd'; sb_name[1] = 'e'; sb_name[2] = 'v'; sb_name[3] = '\0';
    } else if (fs_type[0] == 't' && fs_type[1] == 'm' && fs_type[2] == 'p' && fs_type[3] == 'f' && fs_type[4] == 's') {
        *is_kernel_fs = true;
        sb_name[0] = 't'; sb_name[1] = 'm'; sb_name[2] = 'p'; sb_name[3] = '\0';
    }
    
    return true;
}