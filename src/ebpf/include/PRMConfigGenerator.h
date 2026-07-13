#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_CONFIG_GENERATOR
#define FILTERING_SYSCALL_FRAMEWORK_PRM_CONFIG_GENERATOR

#include "baseheaders.h"

#define ENTRY(elem) #elem


#define __SCONFIG__(idx, keyArg, len, ...) \
    struct keyArg##_container{ \
        int _magic_;    \
        char _holder_[len][MAX_STR];   \
    };  \
    const struct keyArg##_container keyArg SEC(".rodata") = {   \
        ._holder_= { __VA_ARGS__ },   \
        ._magic_=idx \
    };

#define __USCONFIG__(idx, keyArg, len, ...) \
    struct keyArg##_container{ \
        int _magic_;    \
        unsigned char _holder_[len][MAX_STR];   \
    };  \
    const struct keyArg##_container keyArg SEC(".rodata") = {   \
        ._holder_= { __VA_ARGS__ },   \
        ._magic_=idx \
    };

#define __LCONFIG__(idx, keyArg, len, ...) \
    struct keyArg##_container{ \
        int _magic_;    \
        char _holder_[len][LARGE_STR];   \
    };  \
    const struct keyArg##_container keyArg SEC(".rodata") = {   \
        ._holder_= { __VA_ARGS__ },   \
        ._magic_=idx \
    };

#define __XLCONFIG__(idx, keyArg, len, ...) \
    struct keyArg##_container{ \
        int _magic_;    \
        char _holder_[len][HUGE_STR];   \
    };  \
    const struct keyArg##_container keyArg SEC(".rodata") = {   \
        ._holder_= { __VA_ARGS__ },   \
        ._magic_=idx \
    };

#define __N32CONFIG__(idx, keyArg, len, ...) \
    struct keyArg##_container{ \
        int _magic_;    \
        __u32 _holder_[len];   \
    };  \
    const struct keyArg##_container keyArg SEC(".rodata") = {   \
        ._holder_= { __VA_ARGS__ },   \
        ._magic_=idx \
    };

#define __N32N32CONFIG__(idx, keyArg, len1,len2 ...) \
    struct keyArg##_container{ \
        int _magic_;    \
        __u32 _holder_[len1][len2];   \
    };  \
    const struct keyArg##_container keyArg SEC(".rodata") = {   \
        ._holder_= { __VA_ARGS__ },   \
        ._magic_=idx \
    };




// Checkers //
// -> Mojtaba Implement me more
#define checkValidElemConfigNUMBER(elem, struct, behave) \
                                    do{\
                                        int len=sizeof(struct._holder_) / sizeof(struct._holder_[0]);     \
                                        for(int i=0;i<len;i++){     \
                                            if (elem == struct._holder_[i]){    \
                                                behave   \
                                                break; \
                                            } \
                                        } \
                                    } \
                                    while(0);

#define checkValidElemConfigSTR(elem, struct, behave) \
                                    do{\
                                        int len=sizeof(struct._holder_) / sizeof(struct._holder_[0]);     \
                                        for(int i=0;i<len;i++){     \
                                            if (strcmp_nolen(elem, struct._holder_[i]) == 0) {   \
                                                behave   \
                                                break; \
                                            } \
                                        } \
                                    }\
                                    while(0);

#define checkValidElemConfigForceSTRLen(elem, struct, behave) \
                                    do{\
                                        int len=sizeof(struct._holder_) / sizeof(struct._holder_[0]);     \
                                        for(int i=0;i<len;i++){     \
                                            if (strcmp_forceS1(struct._holder_[i], elem) == 0) {   \
                                                behave \
                                                break; \
                                            }  \
                                        }   \
                                    }   \
                                    while(0);

#define checkValidElemConfigForceSTRLenFocusOnElem(elem, struct, behave) \
                                    do{\
                                        int len=sizeof(struct._holder_) / sizeof(struct._holder_[0]);     \
                                        for(int i=0;i<len;i++){     \
                                            if (strcmp_forceS1(elem, struct._holder_[i]) == 0) {   \
                                                behave \
                                                break; \
                                            }  \
                                        }   \
                                    }   \
                                    while(0);
#endif