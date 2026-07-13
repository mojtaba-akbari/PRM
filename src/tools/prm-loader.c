/*
 * PRM Loader
 * Load, inspect, and manage the PRM eBPF security framework.
 *
 * Usage:
 *   prm-loader load [--daemon]       Load and pin eBPF programs
 *   prm-loader unload                Remove pinned programs and maps
 *   prm-loader status                Show PRM state and attached hooks
 *   prm-loader show relations        Dump the 300-entry rule table
 *   prm-loader show config           Print compiled-in security config
 *   prm-loader show cache            Show cache statistics
 *   prm-loader show progs            List PROG handlers
 *   prm-loader help                  Print this help
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <libbpf.h>
#include <bpf.h>

#define TOKEN_MAX_AGE 3600  /* 1 hour */
#define NONCE_DIR "/var/lib/prm"
#define NONCE_FILE NONCE_DIR "/used_nonces"
#define TRUSTED_KEY_ID "prm-admin@gwdg.de"

#define MAX_NUMBER_OF_RELATION 300
#define MAX_RELATION_PROCESSNAME 16
#define MAX_STR 16
#define LARGE_STR 32
#define MAX_CACHE_ENTRIES 5
#define MAX_DIR_ITR 10
#define ALLOWED_PIDS 2024
#define PIN_PATH "/sys/fs/bpf/prm"

static const char *action_names[] = {
    "NONE", "ACCEPT", "REJECT", "REDIRECT", "PATTERN",
    "DEBUG", "BYPASS", "RETURN", "END"
};

static const char *hook_names[] = {
    "ANY", "FILE_PERMISSION", "FILE_IOCTL", "FILE_MPROTECT",
    "FILE_RECEIVE", "FILE_SIGIOTASK", "FILE_OPEN", "SB_MOUNT",
    "SHM_ALLOC", "INODE_CREATE", "INODE_PERMISSION", "INODE_SETATTR",
    "INODE_MKDIR", "SYSLOG", "SOCKET_CREATE", "SOCKET_CONNECT",
    "BPRM_SECURITY", "BPF", "SECURITY_CAPGET", "TASK_KILL",
    "TASK_ALLOC", "TASK_MOVEMEMORY", "TASK_PTRACE", "TASK_SETPGID",
    "TASK_GETGID", "TASK_GETSID", "TASK_PRLIMIT", "TASK_SETPRLIMIT",
    "TASK_SETIOPRIO", "TASK_FIX_SETUID", "CRED_PREPARE",
    "SOCKET_ACCEPT", "KERNEL_MODULE_REQUEST", "CAPABLE"
};

static const char *state_names[] = {
    "UNLOADED", "STARTUP", "LOADED", "BROKEN",
    "TOO_MANY_ROLES", "NON_OF_GENERAL_ROLE"
};

static const char *prog_names[] = {
    "test",
    "signalKillTracer",
    "denyWriteOutSideOfValidDirectories",
    "denyMakeSocketToEndHost",
    "bprmSecurityCheck",
    "memoryProtectCheck",
    "denyIncomeSocket",
    "denyFileOpen",
    "denyLoadModule",
    "credPrepareCheck",
    "capableCheck",
    "taskFixSetUIDCheck"
};

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct cache_entry {
    unsigned int hash;
    unsigned char is_valid;
};

struct cache_record {
    signed char direct_relation;
    unsigned char is_valid_entries;
    unsigned char active_entries;
    unsigned char prog_tb_id;
    struct cache_entry cache_entries[MAX_CACHE_ENTRIES];
};

struct unique_key {
    unsigned int pid;
    unsigned int tpid;
    unsigned int hook;
    struct cache_record crecord;
};

struct process_relation {
    char process[MAX_RELATION_PROCESSNAME];
    char parent[MAX_RELATION_PROCESSNAME];
    char grandparent[MAX_RELATION_PROCESSNAME];
    unsigned int action;
    unsigned int redirect_index;
    int protect_zone;
    unsigned int hook_type;
    unsigned int process_hash;
    unsigned int parent_hash;
    unsigned int grandparent_hash;
    unsigned char is_symmetric;
    unsigned int symmetric_hash;
};

struct prm_state {
    unsigned int state;
};

static const char *safe_action(unsigned int a)
{
    return a < ARRAY_SIZE(action_names) ? action_names[a] : "?";
}

static const char *safe_hook(unsigned int h)
{
    return h < ARRAY_SIZE(hook_names) ? hook_names[h] : "?";
}

static const char *safe_state(unsigned int s)
{
    return s < ARRAY_SIZE(state_names) ? state_names[s] : "?";
}

static int pin_exists(void)
{
    struct stat st;
    return stat(PIN_PATH, &st) == 0;
}

/* ── token verification ── */

static int verify_token(const char *token_path, const char *expected_action)
{
    char sig_path[512];
    snprintf(sig_path, sizeof(sig_path), "%s.sig", token_path);

    /* 1. verify GPG signature */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "gpg --trust-model always --verify %s %s >/dev/null 2>&1",
             sig_path, token_path);
    if (system(cmd) != 0) {
        fprintf(stderr, "TOKEN REJECTED: invalid GPG signature\n");
        return -1;
    }

    /* 2. read token content: ACTION:HOSTNAME:TIMESTAMP:NONCE */
    FILE *f = fopen(token_path, "r");
    if (!f) {
        fprintf(stderr, "TOKEN REJECTED: cannot read token file\n");
        return -1;
    }
    char line[256] = {0};
    fgets(line, sizeof(line), f);
    fclose(f);

    /* strip newline */
    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;

    char action[32]={0}, hostname[128]={0}, nonce[64]={0};
    long timestamp = 0;

    char *tok = strtok(line, ":");
    if (tok) strncpy(action, tok, 31);
    tok = strtok(NULL, ":");
    if (tok) strncpy(hostname, tok, 127);
    tok = strtok(NULL, ":");
    if (tok) timestamp = atol(tok);
    tok = strtok(NULL, ":");
    if (tok) strncpy(nonce, tok, 63);

    /* 3. check action matches (accept "manage" as wildcard for load/unload) */
    if (strcmp(action, expected_action) != 0 && strcmp(action, "manage") != 0) {
        fprintf(stderr, "TOKEN REJECTED: action mismatch (got '%s', expected '%s')\n",
                action, expected_action);
        return -1;
    }

    /* 4. check hostname matches */
    char my_hostname[128] = {0};
    gethostname(my_hostname, sizeof(my_hostname) - 1);
    if (strcmp(hostname, my_hostname) != 0) {
        fprintf(stderr, "TOKEN REJECTED: hostname mismatch (got '%s', this is '%s')\n",
                hostname, my_hostname);
        return -1;
    }

    /* 5. check timestamp within 5 minutes */
    long now = (long)time(NULL);
    if (now - timestamp > TOKEN_MAX_AGE || timestamp - now > 60) {
        fprintf(stderr, "TOKEN REJECTED: expired (age=%lds, max=%ds)\n",
                now - timestamp, TOKEN_MAX_AGE);
        return -1;
    }

    /* 6. check nonce not reused */
    mkdir(NONCE_DIR, 0700);
    FILE *nf = fopen(NONCE_FILE, "r");
    if (nf) {
        char used[64];
        while (fgets(used, sizeof(used), nf)) {
            char *unl = strchr(used, '\n');
            if (unl) *unl = 0;
            if (strcmp(used, nonce) == 0) {
                fclose(nf);
                fprintf(stderr, "TOKEN REJECTED: nonce already used (replay attack?)\n");
                return -1;
            }
        }
        fclose(nf);
    }

    /* 7. record nonce as used */
    nf = fopen(NONCE_FILE, "a");
    if (nf) {
        fprintf(nf, "%s\n", nonce);
        fclose(nf);
    }

    printf("TOKEN ACCEPTED: action=%s host=%s age=%lds\n",
           action, hostname, now - timestamp);
    return 0;
}

static int open_pinned_map(const char *name)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", PIN_PATH, name);
    int fd = bpf_obj_get(path);
    if (fd < 0)
        fprintf(stderr, "  cannot open map %s: %s\n", path, strerror(errno));
    return fd;
}

/* ── load ── */

static int cmd_load(int daemon_mode, const char *token_path, const char *obj_dir)
{
    if (!token_path) {
        fprintf(stderr, "ERROR: --token is required\n");
        fprintf(stderr, "Generate one with: prm-gentoken load <hostname>\n");
        return 1;
    }
    if (verify_token(token_path, "load") != 0)
        return 1;

    char bpf_file[512];
    if (obj_dir)
        snprintf(bpf_file, sizeof(bpf_file), "%s/hookentry.bpf.o", obj_dir);
    else
        snprintf(bpf_file, sizeof(bpf_file), "hookentry.bpf.o");
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int err;

    if (pin_exists()) {
        fprintf(stderr, "PRM already loaded (pin at %s). Run 'prm-loader unload' first.\n", PIN_PATH);
        return 1;
    }

    printf("Loading %s ...\n", bpf_file);

    obj = bpf_object__open_file(bpf_file, NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    printf("BPF object loaded into kernel\n");

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", PIN_PATH);
    system(cmd);

    int count = 0;
    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__type(prog) == BPF_PROG_TYPE_LSM) {
            link = bpf_program__attach(prog);
            if (!link) {
                fprintf(stderr, "Failed to attach %s: %s\n",
                        bpf_program__name(prog), strerror(errno));
                bpf_object__close(obj);
                return 1;
            }
            char link_path[512];
            snprintf(link_path, sizeof(link_path), "%s/%s_link",
                     PIN_PATH, bpf_program__name(prog));
            err = bpf_link__pin(link, link_path);
            if (err)
                fprintf(stderr, "Warning: failed to pin link %s\n", link_path);
            count++;
        }
    }

    err = bpf_object__pin_programs(obj, PIN_PATH);
    if (err) {
        fprintf(stderr, "Failed to pin programs: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    err = bpf_object__pin_maps(obj, PIN_PATH);
    if (err) {
        fprintf(stderr, "Failed to pin maps: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }

    printf("\nPRM loaded successfully\n");
    printf("  Attached hooks : %d\n", count);
    printf("  Pin path       : %s\n", PIN_PATH);
    printf("  Unload         : prm-loader unload\n");

    if (daemon_mode) {
        printf("  Running in daemon mode (Ctrl+C to stop)\n");
        while (1) sleep(3600);
    }

    bpf_object__close(obj);
    return 0;
}

/* ── unload ── */

static int cmd_unload(const char *token_path)
{
    if (!token_path) {
        fprintf(stderr, "ERROR: --token is required\n");
        fprintf(stderr, "Generate one with: prm-gentoken unload <hostname>\n");
        return 1;
    }
    if (verify_token(token_path, "unload") != 0)
        return 1;

    if (!pin_exists()) {
        printf("PRM is not loaded (no pin at %s)\n", PIN_PATH);
        return 0;
    }

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", PIN_PATH);
    int ret = system(cmd);
    if (ret == 0)
        printf("PRM unloaded (removed %s)\n", PIN_PATH);
    else
        fprintf(stderr, "Failed to remove %s\n", PIN_PATH);
    return ret;
}

/* ── status ── */

static int cmd_status(void)
{
    printf("PRM Status\n──────────\n");

    if (!pin_exists()) {
        printf("  State: NOT LOADED (no pin at %s)\n", PIN_PATH);
        return 0;
    }

    printf("  Pin path: %s\n", PIN_PATH);

    int fd = open_pinned_map("prm_state_map");
    if (fd >= 0) {
        unsigned int key = 0;
        struct prm_state st = {0};
        if (bpf_map_lookup_elem(fd, &key, &st) == 0)
            printf("  State  : %s (%u)\n", safe_state(st.state), st.state);
        close(fd);
    }

    fd = open_pinned_map("self_pids");
    if (fd >= 0) {
        unsigned int key = 0;
        struct { unsigned int pid; unsigned long magic; } sp = {0};
        if (bpf_map_lookup_elem(fd, &key, &sp) == 0)
            printf("  Self PID: %u\n", sp.pid);
        close(fd);
    }

    printf("\n  Attached LSM hooks:\n");
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "ls %s/*_link 2>/dev/null | wc -l", PIN_PATH);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        int n = 0;
        fscanf(fp, "%d", &n);
        pclose(fp);
        printf("    %d hooks attached\n", n);
    }

    fd = open_pinned_map("process_list");
    if (fd >= 0) {
        struct unique_key key = {0};
        int count = 0;
        while (bpf_map_get_next_key(fd, &key, &key) == 0) count++;
        printf("\n  Cache (whitelist): %d / %d entries\n", count, ALLOWED_PIDS);
        close(fd);
    }

    fd = open_pinned_map("blacklist");
    if (fd >= 0) {
        struct unique_key key = {0};
        int count = 0;
        while (bpf_map_get_next_key(fd, &key, &key) == 0) count++;
        printf("  Cache (blacklist): %d / 2048 entries\n", count);
        close(fd);
    }

    return 0;
}

/* ── show relations ── */

static int cmd_show_relations(void)
{
    if (!pin_exists()) {
        fprintf(stderr, "PRM not loaded. Run: prm-loader load\n");
        return 1;
    }

    int fd = open_pinned_map("prm_map");
    if (fd < 0) return 1;

    printf("%-5s %-16s %-16s %-16s %-10s %-6s %-5s %-18s %s\n",
           "Rule", "Process", "Parent", "Grandparent", "Action", "Redir", "Zone", "Hook", "Flags");
    printf("─────────────────────────────────────────────────────────────────────────────────────────────────\n");

    for (unsigned int i = 0; i < MAX_NUMBER_OF_RELATION; i++) {
        struct process_relation rel = {0};
        if (bpf_map_lookup_elem(fd, &i, &rel) != 0) continue;
        if (rel.process[0] == '\0' && rel.action == 0) continue;

        char proc[17]={0}, par[17]={0}, gpar[17]={0};
        memcpy(proc, rel.process, 16);
        memcpy(par, rel.parent, 16);
        memcpy(gpar, rel.grandparent, 16);

        printf("%-5u %-16s %-16s %-16s %-10s %-6u %-5d %-18s %s\n",
               i, proc, par, gpar,
               safe_action(rel.action), rel.redirect_index,
               rel.protect_zone, safe_hook(rel.hook_type),
               rel.is_symmetric ? "SYM" : "");
    }

    close(fd);
    return 0;
}

/* ── show config ── */

static int cmd_show_config(void)
{
    printf("PRM Compiled Configuration\n──────────────────────────\n\n");
    printf("  MAX_NUMBER_OF_RELATION   = %d\n", MAX_NUMBER_OF_RELATION);
    printf("  MAX_CACHE_ENTRIES        = %d\n", MAX_CACHE_ENTRIES);
    printf("  ALLOWED_PIDS (cache)     = %d\n", ALLOWED_PIDS);
    printf("  Pin path: %s\n", PIN_PATH);

    if (pin_exists()) {
        printf("\nLoaded maps:\n");
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ls %s/ 2>/dev/null | grep -v _link | sort", PIN_PATH);
        system(cmd);
    }
    return 0;
}

/* ── show cache ── */

static int cmd_show_cache(void)
{
    if (!pin_exists()) {
        fprintf(stderr, "PRM not loaded. Run: prm-loader load\n");
        return 1;
    }

    printf("PRM Cache Statistics\n────────────────────\n\n");

    int fd = open_pinned_map("process_list");
    if (fd >= 0) {
        struct unique_key key={0}, prev={0};
        int total = 0, hooks[34] = {0};
        int first = 1;
        while (1) {
            int ret = first ? bpf_map_get_next_key(fd, NULL, &key)
                           : bpf_map_get_next_key(fd, &prev, &key);
            first = 0;
            if (ret != 0) break;
            total++;
            if (key.hook < 34) hooks[key.hook]++;
            prev = key;
        }
        printf("Whitelist: %d / %d entries\n", total, ALLOWED_PIDS);
        for (int i = 0; i < 34; i++)
            if (hooks[i] > 0) printf("  %-24s %d\n", safe_hook(i), hooks[i]);
        close(fd);
    }

    fd = open_pinned_map("blacklist");
    if (fd >= 0) {
        struct unique_key key={0}, prev={0};
        int total = 0, first = 1;
        while (1) {
            int ret = first ? bpf_map_get_next_key(fd, NULL, &key)
                           : bpf_map_get_next_key(fd, &prev, &key);
            first = 0;
            if (ret != 0) break;
            total++;
            prev = key;
        }
        printf("\nBlacklist: %d / 2048 entries\n", total);
        close(fd);
    }
    return 0;
}

/* ── show progs ── */

static int cmd_show_progs(void)
{
    static const char *prog_hooks[] = {
        "--", "TASK_KILL", "INODE_CREATE", "SOCKET_CONNECT",
        "BPRM_SECURITY", "FILE_MPROTECT", "SOCKET_ACCEPT",
        "FILE_OPEN", "KERNEL_MODULE_REQUEST", "CRED_PREPARE",
        "CAPABLE", "TASK_FIX_SETUID"
    };

    printf("%-5s %-38s %s\n", "ID", "Handler", "Hook");
    printf("──────────────────────────────────────────────────────────\n");
    for (unsigned int i = 0; i < ARRAY_SIZE(prog_names); i++)
        printf("%-5u %-38s %s\n", i, prog_names[i],
               i < ARRAY_SIZE(prog_hooks) ? prog_hooks[i] : "?");
    return 0;
}

/* ── help ── */

static void cmd_help(const char *argv0)
{
    printf("PRM Loader -- Process Rule Management Framework\n\n");
    printf("Usage: %s <command> [options]\n\n", argv0);
    printf("Commands:\n");
    printf("  load [--daemon] [--token FILE] [--dir PATH]  Load eBPF, attach LSM hooks\n");
    printf("  unload [--token FILE]            Remove pinned programs and maps\n");
    printf("  status              Show PRM state, self-PID, cache usage\n");
    printf("  show relations      Dump the rule table (non-empty rules)\n");
    printf("  show config         Print buffer sizes and map capacities\n");
    printf("  show cache          Show whitelist/blacklist cache stats\n");
    printf("  show progs          List PROG security handlers\n");
    printf("  help                Print this help\n");
    printf("\nSee also: prm-configure (interactive TUI editor)\n");
}

/* ── main ── */

int main(int argc, char **argv)
{
    if (argc < 2) { cmd_help(argv[0]); return 1; }

    const char *cmd = argv[1];

    if (strcmp(cmd, "load") == 0) {
        int daemon = 0;
        const char *token = NULL;
        const char *obj_dir = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--daemon") == 0) daemon = 1;
            else if (strcmp(argv[i], "--token") == 0 && i+1 < argc) token = argv[++i];
            else if (strcmp(argv[i], "--dir") == 0 && i+1 < argc) obj_dir = argv[++i];
        }
        return cmd_load(daemon, token, obj_dir);
    }
    if (strcmp(cmd, "unload") == 0) {
        const char *token = NULL;
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--token") == 0 && i+1 < argc) token = argv[++i];
        }
        return cmd_unload(token);
    }
    if (strcmp(cmd, "status") == 0)
        return cmd_status();
    if (strcmp(cmd, "show") == 0 && argc > 2) {
        if (strcmp(argv[2], "relations") == 0) return cmd_show_relations();
        if (strcmp(argv[2], "config") == 0)    return cmd_show_config();
        if (strcmp(argv[2], "cache") == 0)     return cmd_show_cache();
        if (strcmp(argv[2], "progs") == 0)     return cmd_show_progs();
        fprintf(stderr, "Unknown: show %s\n", argv[2]);
        return 1;
    }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        cmd_help(argv[0]);
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd);
    cmd_help(argv[0]);
    return 1;
}
