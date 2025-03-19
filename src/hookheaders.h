// Try to define constant then you do not need to get any headers from linux kernel //
// it helps you to compile it by ecc directly :) do not ask me why //
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