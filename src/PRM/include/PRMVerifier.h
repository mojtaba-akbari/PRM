#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_Verifier_H
#define FILTERING_SYSCALL_FRAMEWORK_PRM_Verifier_H

#include "../include/conf/PRM.h"
#include "../include/conf/PRMConfig.h"
#include "../include/PRMProgDispatcher.h"
#include "../include/PRMFilters.h"

static int PRMVerifier(struct hooks_context_t *hook_ctx);

static int detectSyscallRelations(struct hooks_context_t *hook_ctx);

static int entryStartPoint(struct hooks_context_t *hook_ctx);

static int saveSelfPID(struct hooks_context_t *hook_ctx);


#endif // FILTERING_SYSCALL_FRAMEWORK_HELPERS_H