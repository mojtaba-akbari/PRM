#ifndef FILTERING_SYSCALL_FRAMEWORK_BTF_HELPERS_H
#define FILTERING_SYSCALL_FRAMEWORK_BTF_HELPERS_H
/*  Mojtaba , Notice , Never change anything here,
    These functions working with Memory and Complexity
    Never Use High Performance Algorithm Here , Use simplest one ,
    Highest Memory Pointer here just points out to 128 Char.
    Or Will be bound to the Max and Min Direct Access.
    Take care of any infinit loop.
    Take care of changing any signed variable to -1
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
// Mojtaba , memset //
void * memset(void *ptr, int value, size_t num) {
    unsigned char *p = ptr;
    while (num--) {
        *p++ = (unsigned char)value;
    }
    return ptr;
}
// Mojtaba , memcmp //
// Take care of read carefully , read dirty
static int memcmp(const void *s1, const void *s2, const __u32 n) {
    __u8 c1, c2; // Mojtaba Defined as unsinged 2 byte

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
// Define Len to just make it safer than simple \0 way
static int strcmp(const char *s1, const char *s2, const __u32 len) {
    char c1, c2;
    __u32 _safeCounter_=0;
    for (__u32 i = 0; i < len; i++) {
        _safeCounter_ = i;
        if (bpf_probe_read_kernel(&c1, sizeof(c1), s1 + _safeCounter_) < 0) return 1;
        if (bpf_probe_read_kernel(&c2, sizeof(c2), s2 + _safeCounter_) < 0) return 1;

        if (c1 != c2) return 1;
        if (c1 == '\0' && c2 == '\0') return 0;
    }
    return 0;
}
// Mojtaba, Strlen //
// Take care of Stack Memory
static __u32 strlen(const char *str, const __u32 len) {
    __u32 lenCounter = 0;
    char c;
    while (lenCounter < len) { 
        bpf_probe_read_kernel(&c, sizeof(c), str + lenCounter);
        if (c == '\0') break;
        lenCounter++;
    }

    return lenCounter;
}
// Mojtaba, Strstr , contains //
// Take care of out of bound memory
static bool strstr(const char *str, const char *substr, const __u32 len){
    int i,j=0;
    int str_len= strlen(str,len);
    int substr_len= strlen(substr,len);

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