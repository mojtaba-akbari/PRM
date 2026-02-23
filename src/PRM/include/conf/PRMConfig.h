#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_CONFIG
#define FILTERING_SYSCALL_FRAMEWORK_PRM_CONFIG
#include "../PRMConfigGenerator.h"

// SCONFIG -> 16bit Chars
// LCONFIG -> 32bit Chars
// HCONFIG -> 64bit Chars
// N32CONFIG -> 32bit Numbers

// Define your config here //

__N32CONFIG__(1, SafeUID, 5,
            0,      // root (system operations)
            1000,   // slurm user
            1001,   // hpc-admin
            2000,   // compute users start
            65534   // nobody (container isolation)
)

__N32CONFIG__(1, UnSafeGID, 4,
            0,      // root group
            1000,   // slurm group  
            2000,   // hpc-users group
            65534   // nogroup
)

// HPC-Safe directories for job execution and data // ****Keep this config low as much as you can ! it is gonna get checked frequently
__SCONFIG__(14, BinaryHomeDirectory, 3,
            ENTRY(sbin),
            ENTRY(bin),
            ENTRY(usr),
)

// HPC-Safe directories for job execution and data
__SCONFIG__(4, ValidateDirectory, 8,
            ENTRY(home),
            ENTRY(scratch),
            ENTRY(work),
            //ENTRY(tmp),
            ENTRY(opt),
            ENTRY(apps),
            ENTRY(shared),
            ENTRY(lustre),
            ENTRY(console), // /dev/console , mostly for all kind of contribution with tty and terminal , the real file is /console or /dev/console
)

// Block specific dangerous paths - full path matching
__LCONFIG__(12, BlockedPaths, 4,
            ENTRY(proc/1/fd/mem),              // Block memory access via /proc/1/fd/mem
            ENTRY(proc/1/fd/kmem),             // Block kernel memory
            ENTRY(proc/kcore),                 // Block kernel core dump
            ENTRY(proc/1/mem)                  // Block direct memory access
)

// Dangerous socket protocols - InfiniBand, legacy protocols, and attack vectors
__N32CONFIG__(27, SocketProtocolInvalid, 15,
            3,   // AF_AX25 - Amateur radio
            4,   // AF_IPX - Legacy Novell
            5,   // AF_APPLETALK - AppleTalk
            6,   // AF_NETROM - Amateur Radio NET/ROM
            9,   // AF_X25 - Legacy X.25
            11,  // AF_ROSE - Amateur Radio X.25 PLP
            12,  // AF_DECnet - DECnet
            13,  // AF_NETBEUI - NetBEUI
            17,  // AF_PACKET - Raw packet access
            19,  // AF_ECONET - Legacy Acorn
            22,  // AF_SNA - IBM SNA
            23,  // AF_IRDA - Infrared
            24,  // AF_PPPOX - PPPoX vulnerabilities
            27,  // AF_IB - InfiniBand RDMA bypass
            38   // AF_ALG - Crypto API exploits
)

// Block dangerous network destinations
__LCONFIG__(1, IPDestRules, 9,
            ENTRY(192.168.1.1/32:80-1000),     // Original rule
            ENTRY(10.10.0.0/16:20000-25500),   // Original rule
            ENTRY(192.168.1.250/27:0-65535),   // Original rule
            ENTRY(169.254.0.0/16:0-65535),     // Link-local metadata attacks
            ENTRY(127.0.0.0/8:22-22),          // Localhost SSH
            ENTRY(10.0.0.1/32:80-443),         // Management interface
            ENTRY(192.168.1.0/24:23-23),       // Telnet
            ENTRY(0.0.0.0/0:135-139),          // Windows NetBIOS
            ENTRY(0.0.0.0/0:445-445)           // SMB
)

// Allow incoming connections
__LCONFIG__(1, IPSrcRules, 6,
            ENTRY(0.0.0.0/0:1000-65534),       // Original rule
            ENTRY(192.168.1.0/24:0-65534),     // Original rule
            ENTRY(10.0.0.0/8:1024-65535),      // Internal HPC network
            ENTRY(172.16.0.0/12:1024-65535),   // Private network
            ENTRY(192.168.0.0/16:1024-65535),  // Local network
            ENTRY(127.0.0.1/32:0-65535)        // Localhost MPI
)

// Dangerous execution paths in HPC , Any Fork or Exec or memfd from this location will be baned
__SCONFIG__(12, BPRMDestination, 6,
            ENTRY(/proc/self/fd/),             // File descriptor tricks
            ENTRY(/dev/shm/),                  // Shared memory exploits
            ENTRY(/tmp/.),                     // Hidden temp files
            ENTRY(/var/tmp/),                  // Persistent temp
            ENTRY(/run/user/),                 // User runtime
            ENTRY(/sys/fs/cgroup/)             // Container escape
)

// Restrict interpreter execution outside safe paths
__SCONFIG__(12, BPRMInValidInterpreterDirectory, 7,
            ENTRY(/tmp),
            ENTRY(/var/tmp),
            ENTRY(/dev/shm),
            ENTRY(/proc),
            ENTRY(/sys),
            ENTRY(/run),
            ENTRY(/boot)
)


// Memory-mapped file restrictions for containers
__SCONFIG__(12, MMAPFileAttached, 5,
            ENTRY(tmp),
            ENTRY(dev),
            ENTRY(proc),
            ENTRY(sys),
            ENTRY(run)
)

// Critical HPC interpreters are rejected ! , modify list , Any kind of exec, fork , ...
__LCONFIG__(12, BPRMInterpreter, 4,
            //ENTRY(/usr/bin/python),            // Python jobs --- Sample Interpreter which you need to limit
            //ENTRY(/usr/bin/python3),           // Python3 jobs  
            //ENTRY(/bin/bash),                  // Shell scripts --- two bash inside , like docker entrypoints , so restricted
            //ENTRY(/bin/sh),                    // POSIX shell --- So restricted 
            ENTRY(/usr/bin/perl),              // Perl scripts --- Sample real interpreter
            ENTRY(/usr/bin/R),                 // R statistical computing -- *
            ENTRY(/usr/bin/singularity),       // Container runtime -- *
            ENTRY(/usr/bin/sudo),            // sudo -- *
            //ENTRY(/docker-entrypoint.sh),       // default of entrypoint for docker -- If you need to allow people call different type of entrypoint , add your entrypoint here
            //ENTRY(/usr/bin/apptainer)          // Container runtime - Remove this one if you need to run apptainer , Apptainer with this chain use fork, apptainer -> apptainer -> sudo
            //ENTRY(/usr/bin/sudo),               // sudo
)

// Block dangerous kernel modules in HPC
__SCONFIG__(6, OpenFileDeny, 20,
            ENTRY(ib_uverbs.ko),               // InfiniBand userspace
            ENTRY(ib_core.ko),                 // InfiniBand core
            ENTRY(rdma_cm.ko),                 // RDMA connection manager
            ENTRY(mlx4_core.ko),               // Mellanox driver
            ENTRY(mlx5_core.ko),               // Mellanox driver
            ENTRY(nvidia.ko),                  // GPU driver (if restricted)
            ENTRY(kvm.ko),                     // Virtualization
            ENTRY(vhost.ko),                   // Virtual host
            ENTRY(tun.ko),                     // TUN/TAP
            ENTRY(bridge.ko),                  // Network bridge
            ENTRY(netfilter.ko),               // Firewall bypass
            ENTRY(xt_socket.ko),               // Socket matching
            ENTRY(nf_nat.ko),                  // NAT module
            ENTRY(ip_tables.ko),               // iptables
            ENTRY(overlay.ko),                 // Container overlay
            ENTRY(aufs.ko),                    // Union filesystem
            ENTRY(fuse.ko),                    // FUSE filesystem
            ENTRY(cifs.ko),                    // SMB/CIFS
            ENTRY(nfs.ko),                     // NFS (if restricted)
            ENTRY(bluetooth.ko)                // Bluetooth
)

// Restrict module loading from dangerous paths
__SCONFIG__(12, OpenFileDirectoryDeny, 6,
            ENTRY(tmp),
            ENTRY(home),
            ENTRY(/var/tmp),
            ENTRY(/dev/shm),
            ENTRY(run),
            ENTRY(proc)
)

// Block dangerous module prefixes
__SCONFIG__(6, ModuleDeny, 12,
            ENTRY(ib_),                        // InfiniBand modules
            ENTRY(rdma_),                      // RDMA modules  
            ENTRY(mlx),                        // Mellanox drivers
            ENTRY(nvidia),                     // GPU drivers (if restricted)
            ENTRY(kvm),                        // Virtualization
            ENTRY(vhost),                      // Virtual hosting
            ENTRY(tun),                        // Tunneling
            ENTRY(bridge),                     // Bridging
            ENTRY(netfilter),                  // Firewall
            ENTRY(overlay),                    // Container overlay
            ENTRY(fuse),                       // FUSE
            ENTRY(bluetooth)                   // Bluetooth
)

// BPF hook injector list
__SCONFIG__(6, HookValidList, 3,
            ENTRY(runc),                        // RUNC - docker and k8s BPF hook list
            ENTRY(systemd),                     // Systemd - systemd BPF hook list (SystemCallFilter=~@mount @reboot ...)
            ENTRY(containerd)                   // Containerd - containerd BPF hook list
)


#endif