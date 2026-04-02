#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_CONFIG
#define FILTERING_SYSCALL_FRAMEWORK_PRM_CONFIG
#include "../PRMConfigGenerator.h"

// SCONFIG -> 16bit Chars
// LCONFIG -> 32bit Chars
// HCONFIG -> 64bit Chars
// N32CONFIG -> 32bit Numbers

// Define your config here //

// Allow root and normal users for SSH/sudo to work
__N32CONFIG__(1, SafeUID, 1,
            65534,      // nogroup
)

__N32CONFIG__(1, UnSafeGID, 2,
            1000,
            65534   // nogroup
)

// ONLY /home/ is valid - attackers trapped here
__SCONFIG__(14, BinaryHomeDirectory, 11,
            ENTRY(sbin),
            ENTRY(bin),
            ENTRY(usr),
            ENTRY(lib),
            ENTRY(lib64),
            ENTRY(etc),
            ENTRY(proc),
            ENTRY(sys),
            ENTRY(dev),
            ENTRY(run),
            ENTRY(boot)
)

// Validate directory entries
__SCONFIG__(4, ValidateDirectory, 13,
            ENTRY(home),
            ENTRY(console),
            ENTRY(stdin),
            ENTRY(stdout),
            ENTRY(stderr),
            ENTRY(null),
            ENTRY(urandom),
            ENTRY(random),
            ENTRY(tmp),
            ENTRY(dev),
            ENTRY(shm),
            ENTRY(nvidia),
            ENTRY(tty),
)

// Block sensitive paths but allow system operation
__LCONFIG__(12, BlockedPaths, 4,
            ENTRY(proc/1/fd/mem),              // Block memory access
            ENTRY(proc/1/fd/kmem),             // Block kernel memory
            ENTRY(proc/kcore),                 // Block kernel core
            ENTRY(proc/1/mem)                  // Block direct memory
)

// Block ALL socket protocols except TCP/UDP
__N32CONFIG__(27, SocketProtocolInvalid, 20,
            0,   // AF_UNSPEC
            3,   // AF_AX25
            4,   // AF_IPX
            5,   // AF_APPLETALK
            6,   // AF_NETROM
            9,   // AF_X25
            11,  // AF_ROSE
            12,  // AF_DECnet
            13,  // AF_NETBEUI
            15,  // AF_SECURITY
            17,  // AF_PACKET - Block raw packets
            18,  // AF_ASH
            19,  // AF_ECONET
            22,  // AF_SNA
            23,  // AF_IRDA
            24,  // AF_PPPOX
            27,  // AF_IB - InfiniBand
            29,  // AF_CAN
            31,  // AF_ISDN
            38   // AF_ALG
)

// Block ALL IPs except localhost + 3 private networks
__LCONFIG__(1, IPDestRules, 1,
            ENTRY(0.0.0.0/0:0-65535)           // Block everything by default
)

// Allow: 127.0.0.0/8 (localhost), 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16

// Block ALL incoming traffic - allow SSHD for honeypot *** Check your SSH port , by default it is 22 , but in my configuration it was 2222
__LCONFIG__(1, IPSrcRules, 2,
            ENTRY(0.0.0.0/0:0-8079),
            ENTRY(0.0.0.0/0:8081-65535)
)

// Block execv from dangerous paths only
__SCONFIG__(12, BPRMDestination, 9,
            ENTRY(/proc/self/fd/),
            ENTRY(/dev/shm/),
            ENTRY(/tmp/.),                     // Hidden files only
            ENTRY(/var/tmp/),
            ENTRY(/run/user/),
            ENTRY(/sys/fs/cgroup/),
            ENTRY(/media/),
            ENTRY(/var/run/),
            ENTRY(/tmp/)
)

// Block interpreters from dangerous paths only
__SCONFIG__(12, BPRMInValidInterpreterDirectory, 8,
            ENTRY(/tmp),
            ENTRY(/var/tmp),
            ENTRY(/dev/shm),
            ENTRY(/proc),
            ENTRY(/sys),
            ENTRY(/run),
            ENTRY(/boot),
            ENTRY(/home),
)


// Memory-mapped file restrictions for containers
__SCONFIG__(12, MMAPFileAttached, 5,
            ENTRY(tmp),
            ENTRY(dev),
            ENTRY(proc),
            ENTRY(sys),
            ENTRY(run)
)

// Block dangerous tools but allow sudo
__LCONFIG__(12, BPRMInterpreter, 4,
            ENTRY(/usr/bin/perl),              // Block perl
            ENTRY(/usr/bin/singularity),       // Block singularity
            ENTRY(/usr/bin/apptainer),         // Block apptainer
            ENTRY(/usr/sbin/reboot)
)

// Block Opening
__SCONFIG__(6, OpenFileDeny, 39,
            ENTRY(ib_uverbs.ko),
            ENTRY(ib_core.ko),
            ENTRY(rdma_cm.ko),
            ENTRY(mlx4_core.ko),
            ENTRY(mlx5_core.ko),
            ENTRY(nvidia.ko),
            ENTRY(kvm.ko),
            ENTRY(vhost.ko),
            ENTRY(tun.ko),
            ENTRY(bridge.ko),
            ENTRY(netfilter.ko),
            ENTRY(xt_socket.ko),
            ENTRY(nf_nat.ko),
            ENTRY(ip_tables.ko),
            ENTRY(overlay.ko),
            ENTRY(aufs.ko),
            ENTRY(fuse.ko),
            ENTRY(cifs.ko),
            ENTRY(nfs.ko),
            ENTRY(bluetooth.ko),
            ENTRY(yum.conf),                   
            ENTRY(dnf.conf),                   
            ENTRY(apt.conf),                   
            ENTRY(pacman.conf),
            ENTRY(shadow),
            ENTRY(gshadow),
            ENTRY(passwd),
            ENTRY(group),
            ENTRY(sudoers),
            ENTRY(grub.cfg),
            ENTRY(sshd_config),
            ENTRY(authorized_keys),
            ENTRY(hosts),
            ENTRY(fstab),
            ENTRY(resolv.conf),
            ENTRY(crontab),
            ENTRY(environment),
            ENTRY(profile),
            ENTRY(ld.so.conf),
)

// Block Opening Aggressivly for any users , any situation , Any miss-configuration with this part goes through not loading services
// So hit this one just when you trace all the outputs of your system
__SCONFIG__(6, OpenFileDenyAggressivly, 22,
            ENTRY(yum.conf),                   
            ENTRY(dnf.conf),                   
            ENTRY(apt.conf),                   
            ENTRY(pacman.conf),
            ENTRY(shadow),
            ENTRY(gshadow),
            ENTRY(passwd),
            ENTRY(group),
            ENTRY(sudoers),
            ENTRY(grub.cfg),
            ENTRY(sshd_config),
            ENTRY(authorized_keys),
            ENTRY(hosts),
            ENTRY(fstab),
            ENTRY(resolv.conf),
            ENTRY(crontab),
            ENTRY(environment),
            ENTRY(profile),
            ENTRY(ld.so.conf),
            ENTRY(prm),
            ENTRY(trace_pipe),
            ENTRY(kvm)
)

// Block module loading from dangerous paths
__SCONFIG__(12, OpenFileDirectoryDeny, 6,
            ENTRY(tmp),
            ENTRY(home),
            ENTRY(/var/tmp),
            ENTRY(/dev/shm),
            ENTRY(run),
            ENTRY(proc)
)

// Block ALL module prefixes
__SCONFIG__(6, ModuleDeny, 15,
            ENTRY(ib_),
            ENTRY(rdma_),
            ENTRY(mlx),
            ENTRY(nvidia),
            ENTRY(kvm),
            ENTRY(vhost),
            ENTRY(tun),
            ENTRY(bridge),
            ENTRY(netfilter),
            ENTRY(overlay),
            ENTRY(fuse),
            ENTRY(bluetooth),
            ENTRY(bpf),                        // Block BPF modules
            ENTRY(xdp),                        // Block XDP
            ENTRY(tc)                          // Block TC
)

// Allow BackBone Service binaries
__SCONFIG__(6, HookValidList, 3,
            ENTRY(runc),                       // Docker/nginx container
            ENTRY(containerd),                 // Containerd for docker
            ENTRY(systemd)                     // Systemd for SSH
)


#endif