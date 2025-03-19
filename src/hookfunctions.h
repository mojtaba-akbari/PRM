#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

// Check if the string contains specific another string or not //
static __always_inline bool bpf_strcontains(const char *str, const char *substr) {
    int i, j;
    int str_len = 0;
    int substr_len = 0;

    // Calculate the length of the substring
    for (substr_len = 0; substr[substr_len] != '\0'; substr_len++);

    // it is just O(n*n) and n=16 so do not worried :) Mojtaba
    for (i = 0; str[i] != '\0'; i++) {
        
        for (j = 0; j < substr_len; j++) {
            if (str[i + j] != substr[j]) {
                break; 
            }
        }

        if (j == substr_len) {
            return true;
        }
    }

    // No match found
    return false;
}


#endif // BPF_HELPERS_H