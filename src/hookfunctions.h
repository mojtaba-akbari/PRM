#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

static const char PYTHON_PREFIX[] = "python";
static const int PYTHON_PREFIX_LEN = 6;

static __always_inline bool bpf_checkPrefix(const char *str) {
    bool stageChecker=true;

    for (int i = 0; i < PYTHON_PREFIX_LEN - 1; i++) {
        if (str[i] != PYTHON_PREFIX[i]) {
            stageChecker=false;
        }
    }

    return stageChecker;
}
#endif // BPF_HELPERS_H