#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_HELPER
#define FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_HELPER

static bool is_containerized_root(struct task_struct *task);
static int symbolicUIDFindClosestPattern(__u32 lineage_key);
static int lineageUIDAnalizer(struct task_struct * task, struct UniqueKey * ukey);

#endif