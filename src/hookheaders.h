// Mojtaba //
// If you want to define your constant here take care of other elements //
// Try to define constant then you do not need to get any headers from linux kernel //
// it helps you to compile it by ecc directly :) do not ask me why //
#ifndef MAY_WRITE
    #define MAY_WRITE 0x2
#endif

#ifndef TASK_COMM_LEN
    #define TASK_COMM_LEN 16
#endif

#ifndef EPERM
    #define EPERM 1
#endif


#ifndef ENOENT
    #define ENOENT 2
#endif


#ifndef EACCES
    #define EACCES 13
#endif


#ifndef EEXIST
    #define EEXIST 17
#endif

#ifndef EINVAL
    #define EINVAL 22
#endif

#ifndef MAX_LEN
    #define MAX_LEN 128
#endif

#ifndef MAX_ITR
    #define MAX_ITR 256
#endif

#ifndef MAX_DST_ADDRS
    #define MAX_DST_ADDRS 64
#endif

#ifndef ENV_MAX_SIZE
    #define ENV_MAX_SIZE 32
#endif

#ifndef USR_HOME_DIR_SIZE
    #define USR_HOME_DIR_SIZE 64
#endif

#ifndef SLURM_CHECK
    #define SLURM_CHECK true
#endif

#ifndef HOME_DIR
    #define HOME_DIR "/home/"
#endif

#ifndef REDIRECTED_DIR
    #define REDIRECTED_DIR "redirectedFiles/"
#endif

#ifndef SLURM_JOB_USER
    #define SLURM_JOB_USER "SLURM_JOB_USER="
#endif

#ifndef SLURM_JOB_USER_LEN
    #define SLURM_JOB_USER_LEN 15
#endif