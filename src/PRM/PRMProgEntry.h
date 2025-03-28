#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_ENTRY
#define FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_ENTRY
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
    if (__builtin_memcmp(filenameDirectoryAdd, userHome, strlen(userHome,DIR_SIZE)) != 0) {

        bpf_printk("Deny writing from %s , User Home is %s\n", filenameDirectoryAdd, userHome);

        return -EPERM;
    }

    return 0;
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


    bpf_probe_read_str(user_home + HOME_DIR_LEN ,strlen(cwd_buf,USR_HOME_DIR_SIZE), cwd_buf);

    
    // Read the original filename
    if (bpf_probe_read_str(filename, sizeof(filename), dentry->d_name.name) < 0) {
        return 0;
    }

    bpf_printk("Open write from %s it must be written %s\n", filename, user_home);

    // Because of multiple time uses , define some TEMP holders
    size_t new_filename_s = sizeof(new_filename);
    size_t user_home_s = strlen(user_home,DIR_SIZE);
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

static int testProg(){
    bpf_printk("___PROG___TEST__BRANCH___\n");
    return 0;
}
#endif