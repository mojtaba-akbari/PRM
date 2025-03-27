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

#ifndef PRM_STATE
    #define PRM_STATE 1
#endif

#ifndef MAX_LEN
    #define MAX_LEN 128
#endif

#ifndef EMPTY
    #define EMPTY 0
#endif

#ifndef MAX_RELATION_PROCESSNAME 
    #define MAX_RELATION_PROCESSNAME 16
#endif

#ifndef MAX_ITR
    #define MAX_ITR 256
#endif

#ifndef MIN_ITR
    #define MIN_ITR 64
#endif

#ifndef MAX_DST_ADDRS
    #define MAX_DST_ADDRS 64
#endif

#ifndef ENV_MAX_SIZE
    #define ENV_MAX_SIZE 64
#endif

#ifndef USR_HOME_DIR_SIZE
    #define USR_HOME_DIR_SIZE 64
#endif

#ifndef DIR_SIZE
    #define DIR_SIZE 64
#endif

#ifndef HOME_DIR
    #define HOME_DIR "/home/"
#endif

#ifndef HOME_DIR_LEN
    #define HOME_DIR_LEN 6
#endif

#ifndef TMP_DIR
    #define TMP_DIR "/tmp/"
#endif

#ifndef TMP_DIR_LEN
    #define TMP_DIR_LEN 5
#endif

#ifndef REDIRECTED_DIR
    #define REDIRECTED_DIR "/"
#endif

#ifndef SLURM_JOB_USER
    #define SLURM_JOB_USER "SLURM_JOB_USER="
#endif

#ifndef SLURM_JOB_USER_LEN
    #define SLURM_JOB_USER_LEN 15
#endif


#ifndef SLURM_PROCESS
    #define SLURM_PROCESS 1
#endif
#ifndef SLURM_CHECK
    #define SLURM_CHECK true
#endif

#ifndef DOCKER_PROCESS
    #define DOCKER_PROCESS 2
#endif

#ifndef PREFIX_PYTHON
    #define PREFIX_PYTHON "python"
#endif
#ifndef PREFIX_PYTHON_LEN
    #define PREFIX_PYTHON_LEN 6
#endif

#ifndef PREFIX_BASH
    #define PREFIX_BASH "bash"
#endif
#ifndef PREFIX_BASH_LEN
    #define PREFIX_BASH_LEN 4
#endif

#ifndef PREFIX_ZSH
    #define PREFIX_ZSH "zsh"
#endif
#ifndef PREFIX_ZSH_LEN
    #define PREFIX_ZSH_LEN 3
#endif

#ifndef PREFIX_SSH
    #define PREFIX_SSH "ssh"
#endif
#ifndef PREFIX_SSH_LEN
    #define PREFIX_SSH_LEN 3
#endif

#ifndef PREFIX_FISH
    #define PREFIX_FISH "fish"
#endif
#ifndef PREFIX_FISH_LEN
    #define PREFIX_FISH_LEN 4
#endif

#ifndef PREFIX_SH
    #define PREFIX_SH "sh"
#endif
#ifndef PREFIX_SH_LEN
    #define PREFIX_SH_LEN 2
#endif

#ifndef PREFIX_NOCARE
    #define PREFIX_NOCARE "*"
#endif
#ifndef PREFIX_NOCARE_LEN
    #define PREFIX_NOCARE_LEN 1
#endif


// MACRO PREPROCESSOR //
#define IS_NUMERIC(x) (0 * x + 0)