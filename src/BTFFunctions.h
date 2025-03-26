#ifndef FILTERING_SYSCALL_FRAMEWORK_BTF_HELPERS_H
#define FILTERING_SYSCALL_FRAMEWORK_BTF_HELPERS_H
/*  Mojtaba , Notice , Never change anything here,
    These functions working with Memory and Complexity
    Never Use High Performance Algorithm Here , Use simplest one ,
    Highest Memory Pointer here just points out to 128 Char.
    Or Will be bound to the Max and Min Direct Access.
    Take care of any infinit loop.
*/
// Mojtaba , Inline min function
// Inline
static inline int min(int a, int b) {
    return a < b ? a : b;
}
// Mojtaba , Inline min function
// Inline
static inline int max(int a, int b) {
    return a > b ? a : b;
}
// Mojtaba , memcmp //
// Take care of read carefully , read dirty
static int memcmp(const void *s1, const void *s2, __u32 n) {
    __u8 c1, c2; // Mojtaba Define as unsinged 8 byte

    for (__u32 i = 0; i < n; i++) {
        // Read 1 byte safely from each pointer // Mojtaba , Never compiler verifier does not allow you to use simple //
        // s1[i] != s2[i] because of unbound memory offset
        if (bpf_probe_read(&c1, sizeof(c1), (const __u8 *)s1 + i) < 0) return 1;
        if (bpf_probe_read(&c2, sizeof(c2), (const __u8 *)s2 + i) < 0) return 1;

        if (c1 != c2) return 1;
    }

    return 0;
}
// Mojtaba , strcmp
// Notice , define MAX_ITR->MIN_ITR so short because of long loop
static int strcmp(const char *s1, const char *s2) {
    if (!s1 || !s2) return 1;

    char buf1[MAX_LEN] = {0};
    char buf2[MAX_LEN] = {0};

    if (bpf_probe_read_kernel_str(buf1, sizeof(buf1), s1) < 0) return 1;
    if (bpf_probe_read_kernel_str(buf2, sizeof(buf2), s2) < 0) return 1;

    #pragma unroll
    for (int i = 0; i < MAX_LEN; i++) {
        if (buf1[i] != buf2[i]) return 1;
        if (buf1[i] == '\0') return 0;
    }

    return 1;
}
// Mojtaba , Safe strcmp :) # Both function are safe the only things is a dirty game which compiler verifier started
// Because of BTF for strcmp , so i change the name to srtcmp_safe
// Notice , define MAX_ITR->MIN_ITR so short because of long loop
static int strcmp_safe(const char *s1, const char *s2) {
    if (!s1 || !s2) return 1;

    char buf1[MAX_LEN] = {0};
    char buf2[MAX_LEN] = {0};

    if (bpf_probe_read_kernel_str(buf1, sizeof(buf1), s1) < 0) return 1;
    if (bpf_probe_read_kernel_str(buf2, sizeof(buf2), s2) < 0) return 1;

    #pragma unroll
    for (int i = 0; i < MAX_LEN; i++) {
        if (buf1[i] != buf2[i]) return 1;
        if (buf1[i] == '\0') return 0;
    }

    return 1;
}
// Mojtaba, Strlen //
// Take care of Stack Memory
static __u32 strlen(const char *str) {
    __u32 len = 0;
    char c;
    while (len < MAX_LEN) { 
        bpf_probe_read_kernel(&c, sizeof(c), str + len);
        if (c == '\0') break;
        len++;
    }

    return len;
}
// Mojtaba, Strstr , contains //
// Take care of out of bound memory
static bool strstr(char *str, char *substr){
    int i,j=0;
    int str_len= __builtin_strlen(str);
    int substr_len= __builtin_strlen(substr);

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
#endif