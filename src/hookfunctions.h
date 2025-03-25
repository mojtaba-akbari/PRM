#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

static const char PYTHON_PREFIX[] = "python";
static const int PYTHON_PREFIX_LEN = 6;

static const char BASH_PREFIX[] = "bash";
static const int BASH_PREFIX_LEN = 4;

static const int PREFIX_NUMBERS=2;

// Mojtaba , instead of using builtin function use this function for comparing anything //
static int memcmp(const void *s1, const void *s2, __u32 n) {
    __u8 c1, c2;

    for (__u32 i = 0; i < n; i++) {
        // Read 1 byte safely from each pointer // Mojtaba , Never compiler verifier does not allow you to use simple //
        // s1[i] != s2[i] because of unbound memory offset
        if (bpf_probe_read(&c1, sizeof(c1), (const __u8 *)s1 + i) < 0) return 1;
        if (bpf_probe_read(&c2, sizeof(c2), (const __u8 *)s2 + i) < 0) return 1;

        if (c1 != c2) return 1;
    }

    return 0;
}

// Mojtaba, Use Function to Return the size of char array //
// Take care of Stack Memory // Mojtaba
static int strlen(const char *str) {
    int len = 0;

    #pragma unroll // To avoid More Iteration
    for (int i = 0; i < MAX_LEN; i++) { // Max Len to avoid longer Len
        char c;
        if (bpf_probe_read_kernel(&c, sizeof(c), &str[i]) < 0) break;
        if (c == '\0') break;
        len++;
    }

    return len;
}

// Mojtaba, Try To use __builtin_strcmp function for fix len //
// If you wanted to find Substr in String use this algorithm // Mojtaba
static bool strstr(char *str, char *substr){
    int i,j=0;
    int str_len= strlen(str);
    int substr_len= strlen(substr);

    bool innerBreak=true;

    for(;i<=str_len -1; i++){
        
        if(str_len - i < substr_len) return false;

        for(j=0; j<=substr_len-1;j++){
            if(str[i+j] != substr[j]) {
                innerBreak=false;
                break;
            }
        }

        if(innerBreak) return innerBreak;
        else innerBreak=true;
    }

    return false;

}

// Mojtaba, Deny Any Write OutSide of Home Directory //
// Check the Mask , Current Directory , And rewrite this part of memory then Let them to Open and Write file // Mojtaba
static int denyWritingDestinationFile(struct file *file, int mask){
    struct dentry *dentry = file->f_path.dentry; // Get Destination
    const char *filenameDirectoryAdd = (const char *)dentry->d_name.name; // Get file Directory 

    // Check if operation is not a write return 0 to keep going
    if (!(mask & MAY_WRITE)) return 0;

    uid_t uid = (uid_t)bpf_get_current_uid_gid(); // Mojtaba , Get the user-id specificly with inline function , because of Memory exceed error //
    const char *username= (uid == 0) ? "root" : "username";

    // Default Directory Path for All Users 
    // Change it if you change in your Linux to /srv or /opt // Mojtaba :) Some Admins Change the user-home directory
    char userHome[64] = HOME_DIR;
    bpf_probe_read_kernel_str(userHome + 6, sizeof(userHome) - 6, username);
    bpf_printk("User Directory is : %s File Destination is : %s", userHome, filenameDirectoryAdd);

    // If file is outside $HOME, redirect it
    if (__builtin_memcmp(filenameDirectoryAdd, userHome, strlen(userHome)) != 0) {

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
    if (memcmp(filename, user_home, user_home_s) != 0) {
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
    char comm[TASK_COMM_LEN], p_comm[TASK_COMM_LEN];

    if (!task) return 0;

    bpf_get_current_comm(comm, sizeof(comm));

    
    parent = task->real_parent;
    if (parent) {
        bpf_probe_read_kernel_str(p_comm, sizeof(p_comm), parent->comm);
    } else {
        return 0;
    }

    // Mojtaba,  If parent is a shell or SSH process → USER PROCESS
    // Every syscalls with shell parent , comes from user otherwise come from daemon 
    // It covers even admins and root :)
    if (memcmp(p_comm, PREFIX_BASH, PREFIX_BASH_LEN) == 0 || memcmp(p_comm, PREFIX_ZSH, PREFIX_ZSH_LEN) == 0 || 
        memcmp(p_comm, PREFIX_SSH, PREFIX_SSH_LEN) == 0 || memcmp(p_comm, PREFIX_FISH, PREFIX_FISH_LEN) == 0) {
        bpf_printk("User Process Detected: %s (Parent: %s)\n", comm, p_comm);
        return 1;
    }
    else {
        bpf_printk("Internal Service Detected: %s (Parent: %s)\n", comm, p_comm);
    }

    return 0;
}

// I checked out everything and found out we can do it with slurmstepd.scope which is responsible to execute jobs //
// Slurm jobs come from srun , sbatch which are executed by slurmstepd.scope //
static int getTypeOfProcess(struct task_struct *task) {
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
            // Use the custom string comparison function
            if (__builtin_strcmp(buffer,"slurmstepd.scope") == 0) {

                bpf_printk("Process is part of a SLURM job: %s", buffer);

                return true;
            }
        }
    }

    return false;
}

static bool checkPrefix(const char *str) {
    // look it up for all Prefix , if in Any prefix it get matched then it is part of our Table //
    int stageChecker=PREFIX_NUMBERS;

    bpf_printk("Checking Prefix ... :)  %s", str);

    // Phase 1 Checking Prefix , Mojtaba :| Check Prefix to make sure about the process which is running  //
    // Do not forget checking the String end \0 
    for (int i = 0; (i < PYTHON_PREFIX_LEN - 1) && (str[i] != '\0'); i++) {
        if (str[i] != PYTHON_PREFIX[i]) {
            stageChecker--;
            break;
        }
    }

    // Remove Bash For Now //
    for (int i = 0; (i < BASH_PREFIX_LEN - 1); i++) {
        if (str[i] != BASH_PREFIX[i]) {
            stageChecker--;
            break;
        }
    } 

    return stageChecker==0? false:true; //False means it is not part of our patterns
}

static __always_inline bool detectHarmfulSyscall() {
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

#endif // BPF_HELPERS_H