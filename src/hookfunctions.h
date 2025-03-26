#ifndef FILTERING_SYSCALL_FRAMEWORK_HELPERS_H
#define FILTERING_SYSCALL_FRAMEWORK_HELPERS_H
// Mojtaba, Deny Any Write OutSide of Home Directory //
// Check the Mask , Current Directory , And rewrite this part of memory then Let them to Open and Write file
static int denyWritingDestinationFile(struct file *file, int mask){
    struct dentry *dentry = file->f_path.dentry; // Get Destination
    const char *filenameDirectoryAdd = (const char *)dentry->d_name.name; // Get file Directory 

    // Check if operation is not a write return 0 to keep going
    if (!(mask & MAY_WRITE)) return 0;

    uid_t uid = (uid_t)bpf_get_current_uid_gid(); // Mojtaba , Get the user-id specificly with inline function , because of Memory exceed error //
    const char *username= (uid == 0) ? "root" : "username";

    // Default Directory Path for All Users 
    // Change it if you change in your Linux to /srv or /opt // Mojtaba :) Some Admins Change the user-home directory
    char userHome[DIR_SIZE];
    bpf_probe_read_str(userHome, sizeof(userHome), HOME_DIR);
    bpf_probe_read_kernel_str(userHome + 6, sizeof(userHome) - 6, username);
    bpf_printk("User Directory is : %s File Destination is : %s", userHome, filenameDirectoryAdd);

    // If file is outside $HOME, redirect it
    if (__builtin_memcmp(filenameDirectoryAdd, userHome, __builtin_strlen(userHome)) != 0) {

        bpf_printk("Deny writing from %s , User Home is %s\n", filenameDirectoryAdd, userHome);

        return -EPERM;
    }

    return 0;
}

// Mojtaba, Retreive ENV From Current Process //
// Do not use it , till you need it emergency //
// Please Do not change this algorithm because of more complixity //
static void retreiveENVfromTask(struct task_struct * task, char * env, int env_len){
    // unsigned long env_start;
    // struct mm_struct *mm;
    // char env_buf[ENV_MAX_SIZE] = {}; // Mojtaba, The Maximum Char of a Simple ENV i assume it 64 KEY=VALUE

    // // Get memory mapping (mm_struct) from task
    // mm = task->mm;
    // if (!mm) {
    //     return 0;
    // }

    // // Read the environment start address
    // bpf_probe_read(&env_start, sizeof(env_start), &mm->env_start);

    // // Mojtaba, Scan environment variables for "SLURM_JOB_USER=" 
    // // Mojtaba , Put MAX_ITR because of long runing loop ofcurse this variable is part of first MAX_ITR //
    // // I assume MAX_ITR for the highest numbers of ENV , But Take Care it is pointer to address not CHAR //
    // for (int i = 0; i < MAX_ITR; i += sizeof(env_buf)) {

    //     if (bpf_probe_read_str(env_buf, sizeof(env_buf), (void *)(env_start + i)) < 0) {
    //         break; // take care close the loop if env address goes no where
    //     }
        
    //     bpf_printk("ENV  %s\n", env_buf);

    //     if (memcmp(env_buf, env, env_len) == 0) {
    //         char *username = env_buf + 15; // Mojtaba , do not need to use memcp just point to the first char to \0
    //         bpf_probe_read_kernel_str(user_home + 6, sizeof(user_home) - 6, username);
    //         break;
    //     }
    // }
}

// Redirect Any Write in open Files To User Home Directory //
// Open File Structure //
// This function seize more space than usuall so please avoid of any any other space //
static int redirectWritingDestinationFileToTMP(struct path *dir, struct dentry *dentry, int flags, umode_t mode){
    struct task_struct *task;
    struct fs_struct *fs;
    struct path cwd_path;
    struct mm_struct *mm;

    unsigned long env_start;
    char user_home[USR_HOME_DIR_SIZE] = HOME_DIR;
    char filename[MAX_DST_ADDRS];
    char new_filename[USR_HOME_DIR_SIZE];

    // Get current task
    task = (struct task_struct *) bpf_get_current_task_btf();
    if (!task) {
        return 0;
    }

    fs = task->fs;
    if (!fs) {
        return 0; // If fs struct is unavailable, just return
    }

    // Get the current working directory (cwd)
    cwd_path = fs->pwd;
    char cwd_buf[USR_HOME_DIR_SIZE]; // Store the working directory path

    // Read the path of the current working directory into the buffer
    bpf_probe_read_str(cwd_buf, sizeof(cwd_buf), cwd_path.dentry->d_name.name);

    // Print the current working directory for debugging
    bpf_printk("Current working directory: %s\n", cwd_buf);


    bpf_probe_read_str(user_home + HOME_DIR_LEN ,__builtin_strlen(cwd_buf), cwd_buf);

    
    // Read the original filename
    if (bpf_probe_read_str(filename, sizeof(filename), dentry->d_name.name) < 0) {
        return 0;
    }

    bpf_printk("Open write from %s it must be written %s\n", filename, user_home);

    // Because of multiple time uses , define some TEMP holders
    size_t new_filename_s = sizeof(new_filename);
    size_t user_home_s = __builtin_strlen(user_home);
    size_t constant_part_s = sizeof(REDIRECTED_DIR)-1;

    __builtin_memset(new_filename, 0, new_filename_s);

    bpf_probe_read_str(new_filename, new_filename_s, user_home);

    if (user_home_s >= new_filename_s) {
        bpf_printk("Invalid Memory Offset : %s, %s", user_home, new_filename);
        return 0; // Prevent invalid memory access
    }

    bpf_probe_read_str(new_filename + user_home_s,
                        new_filename_s - user_home_s,
                        REDIRECTED_DIR);

    // Mojtaba , Do not forget to check the positive value of offset because compiler verifier does not allow you to put it freely here :) //
    size_t user_home_constant = user_home_s + constant_part_s;

    if (user_home_constant >= new_filename_s) {
        bpf_printk("Invalid Memory Offset : %s, %s", filename, new_filename);
        return 0; // Prevent invalid memory access
    }

    bpf_probe_read_str(new_filename + user_home_constant,
                        (new_filename_s - user_home_constant),
                        filename);


    // If the file is outside the home directory, redirect it
    if (__builtin_memcmp(filename, user_home, user_home_s) != 0) {
        // Log redirection
        bpf_printk("Redirecting write from %s to %s\n", filename, new_filename);

        // Redirect file path
        bpf_probe_write_user((void *)dentry->d_name.name, new_filename, sizeof(new_filename));

        bpf_printk("New path for writing %s \n", dentry->d_name.name);

        return 0; // Allow file open with new filename
    }

    return 0; // Allow normal writes
}

// Mojtaba, Find the ancester parent for the syscalls //
// Where Syscalls come from //
static int getAncestorParent(){
    struct task_struct *task = (struct task_struct *) bpf_get_current_task_btf();
    struct task_struct *parent;
    struct task_struct *grandparent;
    char comm[TASK_COMM_LEN], p_comm[TASK_COMM_LEN], grand_p_comm[TASK_COMM_LEN];

    if (!task) return 0;

    bpf_get_current_comm(comm, sizeof(comm));

    
    parent = task->real_parent;
    if (parent) {
        bpf_probe_read_kernel_str(p_comm, sizeof(p_comm), parent->comm);
    } else {
        return 0;
    }

    grandparent = parent->real_parent;
    // Some times we do not have grand
    if (!grandparent) {
        bpf_probe_read_kernel_str(grand_p_comm, sizeof(""), "");
    }

    bpf_probe_read_kernel_str(grand_p_comm, sizeof(grand_p_comm), grandparent->comm);



    // Mojtaba, Get into roles and find pattern :) ;) I know I know i am best , i am joking with you just smile man i wanted to make nice smile for you who is reading this code , be kind ;)
    // I customized the if clouse to be readable so put your roles there
    struct process_relation *prm;
    bool condition=false;
    #pragma unroll
    for (int i = 0; i < MAX_RELATION; i++) {

        prm = bpf_map_lookup_elem(&relation_map, &i); // Retreive from user-space memory which was allocated in the libpbf load time , Mojtaba , 2 Hits to user-space memory
        if(prm){
            int test=strcmp_safe(comm, prm->process);
            condition = ((prm->process == NULL) ? true : (strcmp_safe(comm, prm->process) ==0? true : false))
                &&
                ((prm->parent == NULL) ? true : (strcmp_safe(p_comm, prm->parent) ==0? true : false)) 
                &&
                ((prm->grandparent == NULL) ? true : (strcmp_safe(grand_p_comm, prm->grandparent) ==0? true : false));

            if(condition) 
            {
                bpf_printk("Indirect process detected: %s -> %s -> %s due to role : {%s,%s,%s}\n", comm, p_comm, grand_p_comm , (prm->process == NULL) ? "" : prm->process , (prm->parent == NULL) ? "" : prm->parent, (prm->grandparent == NULL) ? "" : prm->grandparent);
                return 1;  // Process is part of a known hierarchy
            }
        }
    }
    



    return 0;
}

// Mojtaba, Return cgroup of task 
// Sometimes i am going to use this cgroup because understanding patterin is difficult
static char * getTypeOfProcess(struct task_struct *task) {
    // Find the cgroup of SLURM JOB that is the best idea , otherwise you need check ENV variables which could be more than 10 //
    // Then Per Syscall Call All We Have Too Traverse Between Big Array // Mojtaba :)

    struct css_set *cgroups = BPF_CORE_READ(task, cgroups);
    struct cgroup_subsys_state *css;
    char buffer[128];
    int ret;

    if (!cgroups)
        return false;

    for (int i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
        bpf_probe_read_kernel(&css, sizeof(css), &cgroups->subsys[i]);

        if (!css)
            continue;

        struct cgroup *cgrp = BPF_CORE_READ(css, cgroup);
        const char *cgroup_name = BPF_CORE_READ(cgrp, kn, name);

        ret = bpf_probe_read_kernel_str(buffer, sizeof(buffer), cgroup_name);

        if (ret > 0) {
            return buffer;
        }
    }

    return false;
}

static __always_inline bool detectHarmfulSyscall() {
    // Load Process Relation Table Roles //
    struct process_relation *relation_list;
    __u32 key = 0; // Static relation list location by key
    relation_list = bpf_map_lookup_elem(&relation_map, &key);

    if (!relation_list) {
        defineProcessRelation();
        relation_list = bpf_map_lookup_elem(&relation_map, &key);
        if(!relation_list){
            bpf_printk("Was not able to load PRM");
            return false;
        }
    }

    // Get the current task (process)
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    // Slurm Check Should come from Config file //
    // Probably in next iterations it will be retrieved from configuration files //
    if(getAncestorParent()){
        // Check if the process name is "python"
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(&comm, sizeof(comm));

        // Check if the process name contains "python"
        // NOTICE : Do not use Loop even 5*5 because it is too much   :) Mojtaba
        // Do not use external function , put your function exactlly inline here
        //return checkPrefix(comm)? true: false;
        return true;
    }

    return false;
}

#endif // FILTERING_SYSCALL_FRAMEWORK_HELPERS_H