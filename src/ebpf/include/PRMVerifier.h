#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_Verifier_H
#define FILTERING_SYSCALL_FRAMEWORK_PRM_Verifier_H

#include "../conf/PRM.h"
#include "../conf/PRMConfig.h"  
#include "PRMProgDispatcher.h"
#include "PRMFilters.h"

// Macro to detect and skip kernel threads for performance optimization
#define PF_KTHREAD 0x00200000

static int compare_path(const char *flat, struct execPath *path);

static int kernelThreadCheck(struct hooks_context_t *hook_ctx);

static struct taskUKey *  createTaskUKey(struct task_struct *etask, struct taskUKey * taskUKeyk);

static  struct execPath * getExecPath(struct task_struct * task, struct taskUKey * taskUKey);

static int PRMVerifier(struct hooks_context_t *hook_ctx);

static int detectSyscallRelations(struct hooks_context_t *hook_ctx);

static int entryStartPoint(struct hooks_context_t *hook_ctx);

static int saveSelfPID(struct hooks_context_t *hook_ctx);


#endif // FILTERING_SYSCALL_FRAMEWORK_HELPERS_H