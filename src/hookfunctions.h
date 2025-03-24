#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

static const char PYTHON_PREFIX[] = "python";
static const int PYTHON_PREFIX_LEN = 6;

static const char BASH_PREFIX[] = "bash";
static const int BASH_PREFIX_LEN = 4;

static const int PREFIX_NUMBERS=1;

static int strlen(const char *str) {
    int len = 0;

    #define MAX_LEN 128  // To avoid verifier issues

    #pragma unroll // To avoid More Iteration
    for (int i = 0; i < MAX_LEN; i++) {
        char c;
        if (bpf_probe_read_kernel(&c, sizeof(c), &str[i]) < 0) break;
        if (c == '\0') break;
        len++;
    }

    return len;
}

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

        if(innerBreak) return true;
        else innerBreak=true;
    }

    return false;

}

static bool is_slurmJob(struct task_struct *task) {
    // Find the cgroup of SLURM JOB that is the best idea , otherwise you need check ENV variables which could be more than 10 //
    // Then Per Syscall Call All We Have Too Traverse Between Big Array // Mojtaba :)

    struct css_set *cgroups = BPF_CORE_READ(task, cgroups);
    struct cgroup_subsys_state *css;
    char buffer[128];
    int ret;

    if (!cgroups)
        return false;

    bpf_printk("I took the cgroup of task: %d",CGROUP_SUBSYS_COUNT);

    for (int i = 0; i < CGROUP_SUBSYS_COUNT; i++) {
        bpf_probe_read_kernel(&css, sizeof(css), &cgroups->subsys[i]);

        if (!css)
            continue;

        struct cgroup *cgrp = BPF_CORE_READ(css, cgroup);
        const char *cgroup_name = BPF_CORE_READ(cgrp, kn, name);

        ret = bpf_probe_read_kernel_str(buffer, sizeof(buffer), cgroup_name);

        bpf_printk("cgroup name : %s",buffer);

        if (ret > 0) {
            // Use the custom string comparison function
            if (strstr(buffer, "slurm") || strstr(buffer, "job_")) {

                bpf_printk("Process is part of a SLURM job: %s", buffer);

                return true;
            }
        }
    }

    return false;
}

static bool bpf_checkPrefix(const char *str) {
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
/*     for (int i = 0; (i < BASH_PREFIX_LEN - 1); i++) {
        if (str[i] != BASH_PREFIX[i]) {
            stageChecker--;
            break;
        }
    } */

    bpf_printk("For Prefix %s , Have been found  %d", str, stageChecker);

    return stageChecker==0? false:true; //False means it is not part of our patterns
}

static __always_inline bool bpf_detectHarmfulSyscall() {
    // Get the current task (process)
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    if(is_slurmJob(task) && SLURM_CHECK){
        // Check if the process name is "python"
        char comm[TASK_COMM_LEN];
        bpf_get_current_comm(&comm, sizeof(comm));

        // Check if the process name contains "python"
        // NOTICE : Do not use Loop even 5*5 because it is too much   :) Mojtaba
        // Do not use external function , put your function exactlly inline here
        return bpf_checkPrefix(comm);
    }

    return false;
}

#endif // BPF_HELPERS_H