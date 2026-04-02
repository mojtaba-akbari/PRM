#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_Filters_H
#define FILTERING_SYSCALL_FRAMEWORK_PRM_Filters_H
// Mojtaba, 
// If you want to hook any filters before Verifier, implement here
// Input -> Filter 1 -> Filter 2 -> ..... Filter 10 -> output // *** Output = 0 return Accept to core , Output = 1 redirect it to Verifier
// __RET__ 1 ---> Return output to hook entry before Verifier //
// 
#define MAX_FILTERS 10



#define Filter_1 1
static __u32 filter1(struct hooks_context_t * hook, __u32 input);

#define Filter_2 0
static __u32 filter2(struct hooks_context_t * hook, __u32 input);

#define Filter_3 0
static __u32 filter3(struct hooks_context_t * hook, __u32 input);

#define Filter_4 0
static __u32 filter4(struct hooks_context_t * hook, __u32 input);

#define Filter_5 0
static __u32 filter5(struct hooks_context_t * hook, __u32 input);

#define Filter_6 0
static __u32 filter6(struct hooks_context_t * hook, __u32 input);

#define Filter_7 0
static __u32 filter7(struct hooks_context_t * hook, __u32 input);

#define Filter_8 0
static __u32 filter8(struct hooks_context_t * hook, __u32 input);

#define Filter_9 0
static __u32 filter9(struct hooks_context_t * hook, __u32 input);

#define Filter_10 0
static __u32 filter10(struct hooks_context_t * hook, __u32 input);




#define __RET__ 1

#define CONCAT(a, b) a##b
#define FILTER_EXISTS(n) CONCAT(Filter_, n)
#define __RETURN__(x,output) if(x) return output;

#define CALL_FILTERS(hook, u32_input,func_number,u32_output) \
    do { \
        if(FILTER_EXISTS(func_number)) \
            u32_output=filter##func_number(hook, u32_input); \
            if(u32_output == 1) __RETURN__(__RET__, u32_output) \
    } while (0);


#define __INJECT_FILTERS__(hook, u32_input,u32_output) \
                             CALL_FILTERS(hook,u32_input,1, u32_output) \
                             CALL_FILTERS(hook,u32_output,2, u32_output) \
                             CALL_FILTERS(hook,u32_output,3, u32_output) \
                             CALL_FILTERS(hook,u32_output,4, u32_output) \
                             CALL_FILTERS(hook,u32_output,5, u32_output) \
                             CALL_FILTERS(hook,u32_output,6, u32_output) \
                             CALL_FILTERS(hook,u32_output,7, u32_output) \
                             CALL_FILTERS(hook,u32_output,8, u32_output) \
                             CALL_FILTERS(hook,u32_output,9, u32_output) \
                             CALL_FILTERS(hook,u32_output,10, u32_output) \
                             __RETURN__(__RET__,u32_output)
#endif