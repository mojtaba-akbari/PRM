#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_Verifier_H
#define FILTERING_SYSCALL_FRAMEWORK_PRM_Verifier_H

static char * getCgroup(struct task_struct *task);

static void retreiveENVfromTask(struct task_struct * task, char * env, int env_len);

static void addLRUCache(__u32 * processID, struct process_relation * prmRelation);

static struct process_relation * getLRUCache(__u32 * processID,enum PRM_HOOK_ENUM hook);

static int PRMVerifier(enum PRM_HOOK_ENUM hook, __u32 * pid);

static int detectSyscallRelations(enum PRM_HOOK_ENUM hook, __u32 * pid);

static int entryStartPoint(enum PRM_HOOK_ENUM hook);

static int saveSelfPID();


#endif // FILTERING_SYSCALL_FRAMEWORK_HELPERS_H