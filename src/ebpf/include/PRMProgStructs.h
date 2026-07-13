#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_STRUCT
#define FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_STRUCT

#include "../conf/PRMProg.h"
#include "PRMStructs.h"



// Prog Structs //
#define EMPTY_PROG test // test prog

struct prog_struct {
    char * name;
    enum PRM_HOOK_ENUM hookForce;
    __u32 (*prog)(struct hooks_context_t *);
    __u32 (*fingerprint)(struct hooks_context_t *);
};

#define __PROG_REGISTER__(name, hook_force ,prog_address, fingerprint_address) const struct prog_struct name SEC(".rodata") = {#name, hook_force, prog_address, fingerprint_address};

struct prog_struct_tb_holder {
    struct prog_struct * prog_struct_tb[PROG_Numbers];
};

// Prog Storage //
#define __INSTALL_PROGS__ const struct prog_struct_tb_holder prog_struct_tb_h SEC(".rodata") = {{{&PROG_0},  \
    {&PROG_1},  \
    {&PROG_2},  \
    {&PROG_3},  \
    {&PROG_4},  \
    {&PROG_5},  \
    {&PROG_6},  \
    {&PROG_7},  \
    {&PROG_8},  \
    {&PROG_9},  \
    {&PROG_10}, \
    {&PROG_11}, \
    {&PROG_12}, \
    {&PROG_13}, \
    {&PROG_14}, \
    {&PROG_15}, \
    {&PROG_16}, \
    {&PROG_17}, \
    {&PROG_18}, \
    {&PROG_19}, \
    {&PROG_20}, \
    {&PROG_21}, \
    {&PROG_22}, \
    {&PROG_23}, \
    {&PROG_24}, \
    {&PROG_25}, \
    {&PROG_26}, \
    {&PROG_27}, \
    {&PROG_28}, \
    {&PROG_29}, \
    {&PROG_30}, \
    {&PROG_31}}};


#endif