#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_HELPER
#define FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_HELPER

static bool is_containerized_root(struct task_struct *task);
static int symbolicUIDFindClosestPattern(__u32 lineage_key);
static int lineageUIDAnalizer(struct task_struct * task, struct UniqueKey * ukey);
static bool get_filesystem_info(struct file *file, char *sb_name, bool *is_kernel_fs, char *fs_type);

#endif