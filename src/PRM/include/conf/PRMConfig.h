#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_CONFIG
#define FILTERING_SYSCALL_FRAMEWORK_PRM_CONFIG
#include "../PRMConfigGenerator.h"

// STRUCTURE
// __CONFIG__(idx, key, number-of-elements, elements) ***struct(int , prefix, int, struct ENTRY)***
// Access in code: key[i] , for size ---> sizeof(key._holder_) / sizeof(key._holder_[0]);
// Notice : save a magic data into idx , it is good oppurtinity to save something in this holder for fast access , ex: maximum char for ValidateDirectory is 4 , or start point of ValidateUID is 1000 or etc....
//          That s a free space to save something there , do it and improves your Progs algorithm :)
// SCONFIG -> 16
// LCONFIG -> 32
// HCONFIG -> 64

// Define your config here //


// Writing outside of these folders is invalid
__SCONFIG__(12, ValidateDirectory, 3,
            ENTRY(home),
            ENTRY(tmp),
            ENTRY(mnt)
)

// Valid user who is doing something
__N32CONFIG__(1, SafeUID, 1,
            1001
)

// Connection to any of these ip/mask/port would be invalid
__LCONFIG__(1, IPDestRules, 3,
            ENTRY(192.168.1.1/32:80-1000),
            ENTRY(10.10.0.0/16:20000-25500),
            ENTRY(192.168.1.250/27:0-65535)
)


// Execute any code from these destination pointer would be invalid
__SCONFIG__(12, BPRMDestination, 3,
            ENTRY(/proc/self/fd/),
            ENTRY(/tmp/),
            ENTRY(/dev/shm/)
)

// Execute any code from these destination pointer would be invalid
__SCONFIG__(12, MMAPFileAttached, 2,
            ENTRY(tmp),
            ENTRY(dev),
            ENTRY(proc) 
)


// Call any interpreter outside of these folders would be invalid
__SCONFIG__(12, BPRMValidInterpreter, 2,
            ENTRY(/lib),
            ENTRY(/usr),
)

#endif