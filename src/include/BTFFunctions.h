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
static __u32 memcmp(const void *s1, const void *s2, const __u32 n) {
    const __u8 *p1 = s1, *p2 = s2;

    for (__u32 i = 0; i < n; i++) {
        if (p1[i] != p2[i]) return 1;
    }
    
    return 0;
}
// Mojtaba , strcmp
// Notice , define MAX_ITR->MIN_ITR so short because of long loop
// Define Len to just make it safer than simple \0 way
// No need to use bpf helper , it causes extra heavy jumps
static __u32 strcmp_regx(const char *s1, const char *s2, const __u32 len) {
    if(s1[0] == '\0' && s2[0] == '\0') return 0;
    if(s1[0] == '\0' || s2[0] == '\0') return 1;
    if(len == 0) return 1;
    if(len == 1) return (s1[0] == s2[0]) ? 0 : 1;

    const char *p1 = s1, *p2 = s2;
    for (__u32 i = 0; i < len && i < MAX_STR; i++, p1++, p2++) {
        char c1 = *p1, c2 = *p2;
        
        if (c1 == '\0' || c2 == '\0') return (c1 == c2) ? 0 : 1;
        if (c1 != c2) return 1;
    }
    return 0;
}
// Mojtaba , strcmp - optimized for eBPF verifier with bounded arrays
static __u32 strcmp_bounded(const char s1[MAX_RELATION_PROCESSNAME], const char s2[MAX_RELATION_PROCESSNAME]) {
    if(s1[0] == '\0' || s2[0] == '\0') return 1;
    
    #pragma unroll
    for (__u32 i = 0; i < MAX_RELATION_PROCESSNAME && i < 16; i++) {
        if (s1[i] != s2[i]) return 1;
        if (s1[i] == '\0' && s2[i] == '\0') return 0;
    }
    return 0;
}

// Keep old strcmp for compatibility
static __u32 strcmp(const char *s1, const char *s2, const __u32 len) {
    if(s1[0] == '\0' || s2[0] == '\0') return 1;
    
    for (__u32 i = 0; i < len && i < 16; i++) {
        if (s1[i] != s2[i]) return 1;
        if (s1[i] == '\0' && s2[i] == '\0') return 0;
    }
    return 0;
}
// Mojtaba , strcmp_nolen
// Notice , define MAX_ITR->MIN_ITR so short because of long loop
// Define Len to just make it safer than simple \0 way
// No need to use bpf helper , it causes extra heavy jumps
static __u32 strcmp_nolen(const char *s1, const char *s2) {
    for (__u32 i = 0; i < MAX_STR; i++) {
        if (s1[i] != s2[i]) return 1;  // Mismatch found
        if (s1[i] == '\0' && s2[i] == '\0') return 0;  // Both reached end
    }
    return 0;
}
// Mojtaba , strcmp_forceS1
// Notice , define MAX_ITR->MIN_ITR so short because of long loop, However we focuse on the first string len - when s1len < s2len
// Define Len to just make it safer than simple \0 way
// No need to use bpf helper , it causes extra heavy jumps
static __u32 strcmp_forceS1(const char *s1, const char *s2) {
    if(s1[0] == '\0' || s2[0] == '\0') return 1;

    for (__u32 i = 0; i < MAX_STR; i++) {
        if (s1[i] == '\0') return 0;  // s1 reached end with match
        if (s1[i] != s2[i]) return 1;  // Mismatch found
        //if (s2[i] == '\0') return 0;  // s2 reached end
    }
    return 0;
}
// Mojtaba , strcmp_forceS1_len
// Notice , define MAX_ITR->MIN_ITR so short because of long loop, However we focuse on the first string len - when s1len < s2len
// Define Len to just make it safer than simple \0 way
// No need to use bpf helper , it causes extra heavy jumps
static __u32 strcmp_forceS1_len(const char *s1, const char *s2, const __u32 len) {
    for (__u32 i = 0; i < len; i++) {
        if (s1[i] == '\0') return 0;  // s1 reached end with match
        if (s1[i] != s2[i]) return 1;  // Mismatch found
        if (s2[i] == '\0') return 0;  // s2 reached end
    }
    return 0;
}
// Mojtaba, Strlen //
// Take care of Stack Memory
static __u32 strlen(const char *str, const __u32 len) { // Stack memory
    __u32 lenCounter = 0;

    while (lenCounter < len && str[lenCounter] != '\0') { 
        lenCounter++;
    }

    return lenCounter;
}
static __u32 safe_strlen(const char *str, const __u32 len) { // Kernel memory
        __u32 i;

    for (i = 0; i < 32; i++) {
        if (i >= len)
            break;
        char c = 0;
        if (bpf_probe_read_kernel(&c, 1, &str[i]) < 0)
            break;
        if (c == '\0')
            return i;
    }
    return len;
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
// It must just copy at maximum 64 char ! , so take care !, Kernel adapted
static int cp_buff2buff_byoffsets(char *dst,int dst_offset, const char *src, int src_offset, int len, bool copy_terminate) {
    int copied = 0;
    char c;
    int lenCom = min(len, HUGE_STR);
    for (int i = 0; i < lenCom; i++) { // MAX 64 Byte // ***
        bpf_probe_read_kernel(&c, sizeof(c), &src[src_offset+i]);

        if (copy_terminate && c == '\0'){
            dst[dst_offset + i] = c;
            copied++;
            break;
        }
        else if (c == '\0'){
            break;
        }

        dst[dst_offset + i] = c;
        copied++;
    }

    return copied;
}
// Shift Array to left from index k to zero
static void shift_array_to_left(char *a, __u32 k, __u32 max_len) {
    if (k == 0 || !a) return;

    __u32 i = 0;
    char tmp;
    for (; k + i < max_len && a[k + i]; i++) {
        tmp = a[i];
        a[i] = a[k + i];
        a[k+i] = tmp;
    }

    //memset(a + i, 0, max_len - i); // fix me , put me up instead of swap , Verifier will find any memset 0 , Mojjjak
}
static void itos(__u32 num, char *str, int max_len) {
    int i = max_len - 2;
    str[max_len - 1] = '\0';

    if (num == 0) {
        str[i--] = '0';
    } else {
        for (; num > 0 && i >= 0; num /= 10, i--) {
            str[i] = '0' + (num % 10);
        }
    }

    int j = 0;
    i++;
    while (i < max_len - 1) {
        str[j++] = str[i++];
    }
    str[j] = '\0';
}
// Mojtaba , String to u32 - DJB2//
static __u32 str_to_u32(char *s) {
    if (!s) return SEED;
    __u32 hash = SEED;  // seed
    char c;
    for (int i = 0; i < MAX_STR && (c = s[i]) != '\0'; i++) {
        hash = ((hash << 5) + hash) + (__u8)c;  // hash * 33 + c
    }
    return hash;
}
// Mojtaba , Make tmp unique key //
static __u32 generate_tmp_ukey(__u32 pid, __u32 tid){
    __u64 time_ns = bpf_ktime_get_ns();
    return pid ^ tid ^ (__u32)time_ns;
}
#endif