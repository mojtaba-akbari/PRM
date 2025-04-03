#ifndef FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_ENTRY
#define FILTERING_SYSCALL_FRAMEWORK_PRM_PROG_ENTRY

static int testProg();

static int denyWritingDestinationFile(struct file *file, int mask);

static int redirectWritingDestinationFileToTMP(struct path *dir, struct dentry *dentry, int flags, umode_t mode);

#endif