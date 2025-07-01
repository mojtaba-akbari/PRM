#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_ENTRY
#define FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_ENTRY

#include "../include/PRMProgStructs.h"
#include "../include/PRMProgHelper.h"

static __u32 test_prog(struct hooks_context_t *hook_ctx);
static __u32 test_fingerprint(struct hooks_context_t *hook_ctx);

static __u32 signalKillTracer_prog(struct hooks_context_t *hook_ctx);
static __u32 signalKillTracer_fingerprint(struct hooks_context_t *hook_ctx);

static __u32 bprmSecurityCheck_prog(struct hooks_context_t *hook_ctx);
static __u32 bprmSecurityCheck_fingerprint(struct hooks_context_t *hook_ctx);

static __u32 memoryProtectCheck_prog(struct hooks_context_t *hook_ctx);
static __u32 memoryProtectCheck_fingerprint(struct hooks_context_t *hook_ctx);

static __u32 denyWriteOutSideOfValidDirectories_prog(struct hooks_context_t *hook_ctx);
static __u32 denyWriteOutSideOfValidDirectories_fingerprint(struct hooks_context_t *hook_ctx);

static __u32 denyMakeSocketToEndHost_prog(struct hooks_context_t *hook_ctx);
static __u32 denyMakeSocketToEndHost_fingerprint(struct hooks_context_t *hook_ctx);

#endif