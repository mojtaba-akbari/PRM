/*
 * PRM Configure - Interactive TUI editor for rules and config
 * Usage: prm-configure
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ncurses.h>

#define TUI_MAX_RULES 300
#define TUI_MAX_FIELD 16
#define TUI_MAX_CONFIGS 20
#define TUI_MAX_ENTRIES 40
#define TUI_MAX_ENTRY_LEN 32


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

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

struct tui_rule {
    char process[TUI_MAX_FIELD];
    char parent[TUI_MAX_FIELD];
    char grandparent[TUI_MAX_FIELD];
    char action[12];
    int redirect;
    int zone;
    int hook;
    int empty;
};

struct tui_config {
    char name[32];
    char desc[64];
    char entries[TUI_MAX_ENTRIES][TUI_MAX_ENTRY_LEN];
    int count;
};


static const char *tui_hook_desc(int h)
{
    if (h < (int)ARRAY_SIZE(hook_names))
        return hook_names[h];
    return "Unknown";
}

static void tui_read_field(WINDOW *win, int y, int x, char *buf, int maxlen)
{
    curs_set(1);
    wmove(win, y, x);
    wclrtoeol(win);
    box(win, 0, 0);
    wmove(win, y, x);
    wrefresh(win);
    memset(buf, 0, maxlen);
    noecho();
    int ch = wgetch(win);
    if (ch == 27) {
        buf[0] = 0;
        curs_set(0);
        return;
    }
    buf[0] = (char)ch;
    mvwaddch(win, y, x, ch);
    echo();
    wmove(win, y, x + 1);
    wrefresh(win);
    if (maxlen > 2) {
        char rest[64] = {0};
        wgetnstr(win, rest, maxlen - 2);
        strcat(buf, rest);
    }
    noecho();
    curs_set(0);
}


static int tui_parse_rules(const char *path, struct tui_rule *rules)
{
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        int idx;
        if (sscanf(line, "#define RELATION_%d", &idx) != 1) continue;
        if (idx < 0 || idx >= TUI_MAX_RULES) continue;

        char *val = strchr(line, ' ');
        if (!val) continue;
        val = strchr(val + 1, ' ');
        if (!val) continue;
        val++;
        char *nl = strchr(val, '\n');
        if (nl) *nl = 0;
        char *cmt = strstr(val, "//");
        if (cmt) *cmt = 0;
        int len = strlen(val);
        while (len > 0 && val[len-1] == ' ') val[--len] = 0;

        if (strcmp(val, "EMPTY") == 0) {
            rules[idx].empty = 1;
            continue;
        }
        rules[idx].empty = 0;
        char p1[TUI_MAX_FIELD]="*", p2[TUI_MAX_FIELD]="*", p3[TUI_MAX_FIELD]="*";
        char act[12] = "BYPASS";
        int redir=0, zone=0, hook=0;

        char *tokens[7] = {0};
        int tc = 0;
        char *tok = val;
        for (int i = 0; i < 7 && tok && *tok; i++) {
            while (*tok == ' ' || *tok == ',') tok++;
            if (*tok == '"') {
                tok++;
                tokens[tc] = tok;
                char *end = strchr(tok, '"');
                if (end) { *end = 0; tok = end + 1; }
            } else {
                tokens[tc] = tok;
                char *end = tok;
                while (*end && *end != ',' && *end != ' ') end++;
                if (*end) { *end = 0; tok = end + 1; } else tok = end;
            }
            tc++;
        }

        if (tc >= 1) {
            if (strcmp(tokens[0], "PREFIX_NOCARE") == 0) strcpy(p1, "*");
            else if (strcmp(tokens[0], "PREFIX_INVALID_BINARY") == 0) strcpy(p1, "!INVALID");
            else strncpy(p1, tokens[0], TUI_MAX_FIELD-1);
        }
        if (tc >= 2) {
            if (strcmp(tokens[1], "PREFIX_NOCARE") == 0) strcpy(p2, "*");
            else if (strcmp(tokens[1], "PREFIX_INVALID_BINARY") == 0) strcpy(p2, "!INVALID");
            else strncpy(p2, tokens[1], TUI_MAX_FIELD-1);
        }
        if (tc >= 3) {
            if (strcmp(tokens[2], "PREFIX_NOCARE") == 0) strcpy(p3, "*");
            else if (strcmp(tokens[2], "PREFIX_INVALID_BINARY") == 0) strcpy(p3, "!INVALID");
            else strncpy(p3, tokens[2], TUI_MAX_FIELD-1);
        }
        if (tc >= 4) strncpy(act, tokens[3], 11);
        if (tc >= 5) redir = atoi(tokens[4]);
        if (tc >= 6) zone = atoi(tokens[5]);
        if (tc >= 7) hook = atoi(tokens[6]);

        strncpy(rules[idx].process, p1, TUI_MAX_FIELD-1);
        strncpy(rules[idx].parent, p2, TUI_MAX_FIELD-1);
        strncpy(rules[idx].grandparent, p3, TUI_MAX_FIELD-1);
        strncpy(rules[idx].action, act, 11);
        rules[idx].redirect = redir;
        rules[idx].zone = zone;
        rules[idx].hook = hook;
    }
    fclose(f);
    return 0;
}


static void tui_draw_rules(WINDOW *win, struct tui_rule *rules, int scroll, int selected)
{
    int h, w;
    getmaxyx(win, h, w);
    werase(win);
    box(win, 0, 0);

    wattron(win, A_BOLD | COLOR_PAIR(1));
    mvwprintw(win, 0, 2, " PRM Rule Table (H=Help  Tab=Next  Q=Quit) ");
    wattroff(win, A_BOLD | COLOR_PAIR(1));

    wattron(win, A_BOLD);
    mvwprintw(win, 1, 1, "%-4s %-16s %-16s %-16s %-9s %-5s %-4s %-16s",
              "#", "Process", "Parent", "Grandparent", "Action", "Redir", "Zone", "Syscall");
    wattroff(win, A_BOLD);
    mvwhline(win, 2, 1, ACS_HLINE, w - 2);

    int row = 3;
    int count = 0;
    for (int i = 0; i < TUI_MAX_RULES && row < h - 3; i++) {
        if (rules[i].empty) continue;
        if (count < scroll) { count++; continue; }

        int is_sel = (i == selected);
        if (is_sel) wattron(win, A_REVERSE);

        int cp = 0;
        if (strcmp(rules[i].action, "ACCEPT") == 0) cp = 3;
        else if (strcmp(rules[i].action, "REJECT") == 0) cp = 2;
        else if (strcmp(rules[i].action, "REDIRECT") == 0) cp = 4;
        else if (strcmp(rules[i].action, "RETURN") == 0) cp = 6;
        else if (strcmp(rules[i].action, "BYPASS") == 0) cp = 5;
        else if (strcmp(rules[i].action, "DEBUG") == 0) cp = 5;
        else if (strcmp(rules[i].action, "END") == 0) cp = 2;

        if (cp && !is_sel) wattron(win, COLOR_PAIR(cp));

        mvwprintw(win, row, 1, "%-4d %-16s %-16s %-16s %-9s %-5d %-4d %-16s",
                  i, rules[i].process, rules[i].parent, rules[i].grandparent,
                  rules[i].action, rules[i].redirect, rules[i].zone,
                  tui_hook_desc(rules[i].hook));

        if (cp && !is_sel) wattroff(win, COLOR_PAIR(cp));
        if (is_sel) wattroff(win, A_REVERSE);
        row++;
        count++;
    }

    mvwhline(win, h - 2, 1, ACS_HLINE, w - 2);
    wattron(win, COLOR_PAIR(5));
    mvwprintw(win, h - 1, 1, " [H] Help  [A] Add  [E] Edit  [D] Delete  [S] Save  [PgDn/PgUp] Scroll  [Tab] Next  [Q] Quit");
    wattroff(win, COLOR_PAIR(5));
}


static void tui_draw_config(WINDOW *win, struct tui_config *cfgs, int ncfg, int scroll, int selected)
{
    int h, w;
    getmaxyx(win, h, w);
    werase(win);
    box(win, 0, 0);

    wattron(win, A_BOLD | COLOR_PAIR(1));
    mvwprintw(win, 0, 2, " PRM Security Config (Tab=Next  Q=Quit  E=Edit  S=Save) ");
    wattroff(win, A_BOLD | COLOR_PAIR(1));

    int row = 2;
    for (int i = scroll; i < ncfg && row < h - 2; i++) {
        int is_sel = (i == selected);

        if (is_sel) wattron(win, A_REVERSE | A_BOLD);
        else wattron(win, A_BOLD | COLOR_PAIR(3));
        mvwprintw(win, row, 2, "%s", cfgs[i].desc);
        if (is_sel) wattroff(win, A_REVERSE | A_BOLD);
        else wattroff(win, A_BOLD | COLOR_PAIR(3));
        row++;

        wattron(win, COLOR_PAIR(5));
        char buf[256] = "  ";
        for (int j = 0; j < cfgs[i].count && strlen(buf) < 200; j++) {
            if (j > 0) strcat(buf, ", ");
            strcat(buf, cfgs[i].entries[j]);
        }
        if ((int)strlen(buf) > w - 4) buf[w-4] = 0;
        mvwprintw(win, row, 2, "%s", buf);
        wattroff(win, COLOR_PAIR(5));
        row += 2;
    }
}


static void tui_edit_rule(WINDOW *win, struct tui_rule *r)
{
    int h, w;
    getmaxyx(stdscr, h, w);
    int dh = 18, dw = 65;
    int dy = (h - dh) / 2, dx = (w - dw) / 2;
    WINDOW *dlg = newwin(dh, dw, dy, dx);
    box(dlg, 0, 0);
    wattron(dlg, A_BOLD | COLOR_PAIR(1));
    mvwprintw(dlg, 0, 2, " Edit Rule (ESC to cancel) ");
    wattroff(dlg, A_BOLD | COLOR_PAIR(1));

    struct tui_rule copy = *r;
    char tmp[TUI_MAX_FIELD];

    mvwprintw(dlg, 2, 2, "Process name (who is making the call)");
    mvwprintw(dlg, 3, 2, "  [%s]: ", copy.process);
    tui_read_field(dlg, 3, 20, tmp, TUI_MAX_FIELD);
    if (tmp[0] == 0 && wgetch(dlg) == ERR) goto cancel;
    if (tmp[0]) strncpy(copy.process, tmp, TUI_MAX_FIELD-1);

    mvwprintw(dlg, 5, 2, "Parent (who launched the process)");
    mvwprintw(dlg, 6, 2, "  [%s]: ", copy.parent);
    tui_read_field(dlg, 6, 20, tmp, TUI_MAX_FIELD);
    if (tmp[0]) strncpy(copy.parent, tmp, TUI_MAX_FIELD-1);

    mvwprintw(dlg, 8, 2, "Grandparent (who launched the parent)");
    mvwprintw(dlg, 9, 2, "  [%s]: ", copy.grandparent);
    tui_read_field(dlg, 9, 20, tmp, TUI_MAX_FIELD);
    if (tmp[0]) strncpy(copy.grandparent, tmp, TUI_MAX_FIELD-1);

    mvwprintw(dlg, 11, 2, "Action: ACCEPT REJECT REDIRECT RETURN BYPASS DEBUG END");
    mvwprintw(dlg, 12, 2, "  [%s]: ", copy.action);
    tui_read_field(dlg, 12, 20, tmp, 12);
    if (tmp[0]) strncpy(copy.action, tmp, 11);

    mvwprintw(dlg, 13, 2, "Redirect index (jump to rule #, 0-299)");
    mvwprintw(dlg, 14, 2, "  [%d]: ", copy.redirect);
    tui_read_field(dlg, 14, 20, tmp, 6);
    if (tmp[0]) copy.redirect = atoi(tmp);

    mvwprintw(dlg, 15, 2, "Zone (0=normal, 1=protected, 2+=prog#)");
    mvwprintw(dlg, 15, 42, "  [%d]: ", copy.zone);
    tui_read_field(dlg, 15, 52, tmp, 4);
    if (tmp[0]) copy.zone = atoi(tmp);

    mvwprintw(dlg, 16, 2, "Syscall (0=All, 6=FileOpen, 16=Exec...)");
    mvwprintw(dlg, 16, 42, "  [%d]: ", copy.hook);
    tui_read_field(dlg, 16, 52, tmp, 4);
    if (tmp[0]) copy.hook = atoi(tmp);

    copy.empty = 0;
    *r = copy;
    delwin(dlg);
    return;

cancel:
    delwin(dlg);
}


static void tui_edit_config(struct tui_config *c)
{
    int h, w;
    getmaxyx(stdscr, h, w);
    int dh = c->count + 6;
    if (dh > h - 4) dh = h - 4;
    int dw = 60;
    int dy = (h - dh) / 2, dx = (w - dw) / 2;
    WINDOW *dlg = newwin(dh, dw, dy, dx);
    box(dlg, 0, 0);
    wattron(dlg, A_BOLD | COLOR_PAIR(1));
    mvwprintw(dlg, 0, 2, " Edit: %s ", c->desc);
    wattroff(dlg, A_BOLD | COLOR_PAIR(1));
    mvwprintw(dlg, 1, 2, "Edit entries (leave blank to keep, 'x' to delete):");

    char tmp[TUI_MAX_ENTRY_LEN];
    int new_count = 0;
    char new_entries[TUI_MAX_ENTRIES][TUI_MAX_ENTRY_LEN];

    for (int i = 0; i < c->count && i + 3 < dh - 1; i++) {
        mvwprintw(dlg, i + 3, 2, "%2d. [%s]: ", i+1, c->entries[i]);
        tui_read_field(dlg, i + 3, 20, tmp, TUI_MAX_ENTRY_LEN);
        if (tmp[0] == 'x' || tmp[0] == 'X') continue;
        if (tmp[0]) strncpy(new_entries[new_count], tmp, TUI_MAX_ENTRY_LEN-1);
        else strncpy(new_entries[new_count], c->entries[i], TUI_MAX_ENTRY_LEN-1);
        new_count++;
    }

    if (new_count < TUI_MAX_ENTRIES && 3 + c->count < dh - 1) {
        mvwprintw(dlg, 3 + c->count, 2, "New: ");
        tui_read_field(dlg, 3 + c->count, 7, tmp, TUI_MAX_ENTRY_LEN);
        if (tmp[0]) {
            strncpy(new_entries[new_count], tmp, TUI_MAX_ENTRY_LEN-1);
            new_count++;
        }
    }

    c->count = new_count;
    for (int i = 0; i < new_count; i++)
        strncpy(c->entries[i], new_entries[i], TUI_MAX_ENTRY_LEN-1);

    delwin(dlg);
}


static int tui_parse_config(const char *path, struct tui_config *cfgs)
{
    static const char *descs[] = {
        "SafeUID", "Trusted User IDs",
        "UnSafeGID", "Restricted Group IDs",
        "BinaryHomeDirectory", "Trusted system directories",
        "ValidateDirectory", "User-allowed directories",
        "BlockedPaths", "Always-blocked paths",
        "SocketProtocolInvalid", "Blocked network protocols",
        "IPDestRules", "Blocked outbound IPs",
        "IPSrcRules", "Blocked inbound IPs",
        "BPRMDestination", "Blocked execution paths",
        "BPRMInValidInterpreterDirectory", "Blocked interpreter dirs",
        "MMAPFileAttached", "Blocked executable memory dirs",
        "BPRMInterpreter", "Blocked interpreter binaries",
        "OpenFileDeny", "Blocked file names",
        "OpenFileDenyAggressivly", "Strictly blocked files",
        "OpenFileDirectoryDeny", "Blocked file directories",
        "ModuleDeny", "Blocked kernel modules",
        "HookValidList", "Trusted system services",
        NULL, NULL
    };

    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char content[16384];
    int clen = fread(content, 1, sizeof(content)-1, f);
    content[clen] = 0;
    fclose(f);

    int ncfg = 0;
    for (int d = 0; descs[d] != NULL; d += 2) {
        const char *name = descs[d];
        const char *desc = descs[d+1];

        char search[64];
        snprintf(search, sizeof(search), ", %s,", name);
        char *pos = strstr(content, search);
        if (!pos) continue;

        strncpy(cfgs[ncfg].name, name, 31);
        strncpy(cfgs[ncfg].desc, desc, 63);
        cfgs[ncfg].count = 0;

        char *block_start = pos;
        char *block_end = NULL;
        char *p = block_start;
        int paren = 0;
        while (*p) {
            if (*p == '(') paren++;
            if (*p == ')') { paren--; if (paren <= 0) { block_end = p; break; } }
            p++;
        }

        if (block_end) {
            char *scan = block_start;
            while (scan < block_end && cfgs[ncfg].count < TUI_MAX_ENTRIES) {
                char *ent = strstr(scan, "ENTRY(");
                if (ent && ent < block_end) {
                    ent += 6;
                    char *end = strchr(ent, ')');
                    if (end && end < block_end) {
                        int elen = end - ent;
                        if (elen > 0 && elen < TUI_MAX_ENTRY_LEN) {
                            strncpy(cfgs[ncfg].entries[cfgs[ncfg].count], ent, elen);
                            cfgs[ncfg].entries[cfgs[ncfg].count][elen] = 0;
                            cfgs[ncfg].count++;
                        }
                        scan = end + 1;
                    } else break;
                } else {
                    char *num = scan;
                    while (num < block_end) {
                        while (num < block_end && !(*num >= '0' && *num <= '9') && *num != '-') num++;
                        if (num >= block_end) break;
                        char *nend = num;
                        while (nend < block_end && ((*nend >= '0' && *nend <= '9') || *nend == '.' || *nend == '/' || *nend == ':' || *nend == '-')) nend++;
                        int nlen = nend - num;
                        if (nlen > 0 && nlen < TUI_MAX_ENTRY_LEN && cfgs[ncfg].count < TUI_MAX_ENTRIES) {
                            strncpy(cfgs[ncfg].entries[cfgs[ncfg].count], num, nlen);
                            cfgs[ncfg].entries[cfgs[ncfg].count][nlen] = 0;
                            cfgs[ncfg].count++;
                        }
                        num = nend;
                    }
                    break;
                }
            }
        }
        ncfg++;
    }
    return ncfg;
}


int main(int argc, char **argv)
{
    char prm_h[512], config_h[512];
    const char *conf_dir = getenv("PRM_CONF_DIR");
    if (!conf_dir) conf_dir = "../src/PRM/include/conf";
    snprintf(prm_h, sizeof(prm_h), "%s/PRM.h", conf_dir);
    snprintf(config_h, sizeof(config_h), "%s/PRMConfig.h", conf_dir);

    if (access(prm_h, R_OK) != 0) {
        fprintf(stderr, "Cannot find %s\nSet PRM_CONF_DIR or run from deployment/\n", prm_h);
        return 1;
    }

    struct tui_rule rules[TUI_MAX_RULES];
    memset(rules, 0, sizeof(rules));
    for (int i = 0; i < TUI_MAX_RULES; i++) rules[i].empty = 1;
    tui_parse_rules(prm_h, rules);

    struct tui_config cfgs[TUI_MAX_CONFIGS];
    memset(cfgs, 0, sizeof(cfgs));
    int ncfg = tui_parse_config(config_h, cfgs);

    initscr();
    start_color();
    use_default_colors();
    init_pair(1, COLOR_WHITE, COLOR_BLUE);
    init_pair(2, COLOR_RED, -1);
    init_pair(3, COLOR_GREEN, -1);
    init_pair(4, COLOR_YELLOW, -1);
    init_pair(5, COLOR_CYAN, -1);
    init_pair(6, COLOR_MAGENTA, -1);
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);

    int tab = 0;
    int r_scroll = 0, r_sel = 0;
    int c_scroll = 0, c_sel = 0;
    int dirty = 0;

    for (int i = 0; i < TUI_MAX_RULES; i++) {
        if (!rules[i].empty) { r_sel = i; break; }
    }

    clear();
    refresh();

    while (1) {
        int h, w;
        getmaxyx(stdscr, h, w);
        WINDOW *win = newwin(h, w, 0, 0);
        keypad(win, TRUE);

        if (tab == 0)
            tui_draw_rules(win, rules, r_scroll, r_sel);
        else if (tab == 1)
            tui_draw_config(win, cfgs, ncfg, c_scroll, c_sel);
        else {
            werase(win);
            box(win, 0, 0);
            wattron(win, A_BOLD | COLOR_PAIR(1));
            mvwprintw(win, 0, 2, " PRM Help (Tab=Next  Q=Quit) ");
            wattroff(win, A_BOLD | COLOR_PAIR(1));
            int y = 2;
            mvwprintw(win, y++, 2, "Rules: Process/Parent/Grandparent matching, first match wins");
            mvwprintw(win, y++, 2, "Actions: ACCEPT, REJECT, REDIRECT, RETURN, BYPASS, DEBUG, END");
            mvwprintw(win, y++, 2, "Use * for wildcard. Max 15 chars per name.");
            y++;
            mvwprintw(win, y++, 2, "Table layout:");
            mvwprintw(win, y++, 2, "  1-16: System ACCEPT   17-56: Free ACCEPT slots");
            mvwprintw(win, y++, 2, "  57-74: REJECT rules   75-108: Free REJECT slots");
            mvwprintw(win, y++, 2, "  109-119: REDIRECTs    120: END");
            mvwprintw(win, y++, 2, "  121-156: Protected zone (RETURN/PROGs)");
            y++;
            mvwprintw(win, y++, 2, "After saving, run 'make' in deployment/ to rebuild.");
        }

        if (dirty) {
            wattron(win, A_BOLD | COLOR_PAIR(2));
            mvwprintw(win, 0, w - 12, " MODIFIED ");
            wattroff(win, A_BOLD | COLOR_PAIR(2));
        }

        wrefresh(win);
        int ch = wgetch(win);
        delwin(win);

        if (ch == 'q' || ch == 'Q') {
            if (dirty) {
                mvprintw(h-1, 1, "Unsaved! Press 'y' to quit: ");
                refresh();
                if (getch() != 'y') continue;
            }
            break;
        }

        if (ch == '\t') {
            tab = (tab + 1) % 3;
        } else if (ch == KEY_DOWN) {
            if (tab == 0) {
                for (int i = r_sel + 1; i < TUI_MAX_RULES; i++) {
                    if (!rules[i].empty) { r_sel = i; break; }
                }
                int visible = h - 7;
                int pos = 0;
                for (int i = 0; i < r_sel; i++) if (!rules[i].empty) pos++;
                if (pos >= r_scroll + visible) r_scroll = pos - visible + 1;
            } else {
                if (c_sel < ncfg - 1) c_sel++;
                int visible = (h - 4) / 3;
                if (c_sel >= c_scroll + visible) c_scroll = c_sel - visible + 1;
            }
        } else if (ch == KEY_UP) {
            if (tab == 0) {
                for (int i = r_sel - 1; i >= 0; i--) {
                    if (!rules[i].empty) { r_sel = i; break; }
                }
                int pos = 0;
                for (int i = 0; i < r_sel; i++) if (!rules[i].empty) pos++;
                if (pos < r_scroll) r_scroll = pos;
            } else {
                if (c_sel > 0) c_sel--;
                if (c_sel < c_scroll) c_scroll = c_sel;
            }
        } else if (ch == KEY_NPAGE) {
            if (tab == 0) {
                int jumps = 20;
                while (jumps-- > 0) {
                    int found = 0;
                    for (int i = r_sel + 1; i < TUI_MAX_RULES; i++) {
                        if (!rules[i].empty) { r_sel = i; found = 1; break; }
                    }
                    if (!found) break;
                }
                int visible = h - 7;
                int pos = 0;
                for (int i = 0; i < r_sel; i++) if (!rules[i].empty) pos++;
                if (pos >= r_scroll + visible) r_scroll = pos - visible + 1;
            } else {
                c_sel += 5;
                if (c_sel >= ncfg) c_sel = ncfg - 1;
                int visible = (h - 4) / 3;
                if (c_sel >= c_scroll + visible) c_scroll = c_sel - visible + 1;
            }
        } else if (ch == KEY_PPAGE) {
            if (tab == 0) {
                int jumps = 20;
                while (jumps-- > 0) {
                    int found = 0;
                    for (int i = r_sel - 1; i >= 0; i--) {
                        if (!rules[i].empty) { r_sel = i; found = 1; break; }
                    }
                    if (!found) break;
                }
                int pos = 0;
                for (int i = 0; i < r_sel; i++) if (!rules[i].empty) pos++;
                if (pos < r_scroll) r_scroll = pos;
            } else {
                c_sel -= 5;
                if (c_sel < 0) c_sel = 0;
                if (c_sel < c_scroll) c_scroll = c_sel;
            }
        } else if (ch == 'e' || ch == 'E') {
            if (tab == 0) {
                tui_edit_rule(stdscr, &rules[r_sel]);
                dirty = 1;
            } else if (tab == 1) {
                tui_edit_config(&cfgs[c_sel]);
                dirty = 1;
            }
        } else if (ch == 'a' || ch == 'A') {
            if (tab == 0) {
                int found = 0;
                for (int i = r_sel + 1; i < TUI_MAX_RULES; i++) {
                    if (rules[i].empty) {
                        strcpy(rules[i].process, "*");
                        strcpy(rules[i].parent, "*");
                        strcpy(rules[i].grandparent, "*");
                        strcpy(rules[i].action, "ACCEPT");
                        rules[i].empty = 0;
                        r_sel = i;
                        tui_edit_rule(stdscr, &rules[i]);
                        dirty = 1;
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    mvprintw(h-1, 1, " No empty slot after rule %d! ", r_sel);
                    refresh();
                    napms(1500);
                }
            }
        } else if (ch == 'd' || ch == 'D') {
            if (tab == 0) {
                rules[r_sel].empty = 1;
                dirty = 1;
            }
        } else if (ch == 's' || ch == 'S') {
            /* backup */
            char bak[520];
            snprintf(bak, sizeof(bak), "%s.bak", prm_h);
            FILE *src = fopen(prm_h, "r");
            FILE *dst = fopen(bak, "w");
            if (src && dst) {
                char buf[1024];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
                    fwrite(buf, 1, n, dst);
            }
            if (src) fclose(src);
            if (dst) fclose(dst);

            /* write rules */
            src = fopen(prm_h, "r");
            if (src) {
                char *content = malloc(65536);
                int clen = fread(content, 1, 65535, src);
                content[clen] = 0;
                fclose(src);

                for (int i = 0; i < TUI_MAX_RULES; i++) {
                    char pattern[64];
                    snprintf(pattern, sizeof(pattern), "#define RELATION_%d ", i);
                    char *pos = strstr(content, pattern);
                    if (!pos) continue;

                    char *eol = strchr(pos, '\n');
                    if (!eol) eol = content + clen;

                    char newline[256];
                    if (rules[i].empty) {
                        snprintf(newline, sizeof(newline), "#define RELATION_%d EMPTY", i);
                    } else {
                        char p1[32], p2[32], p3[32];
                        if (strcmp(rules[i].process, "*") == 0) strcpy(p1, "PREFIX_NOCARE");
                        else if (strcmp(rules[i].process, "!INVALID") == 0) strcpy(p1, "PREFIX_INVALID_BINARY");
                        else snprintf(p1, sizeof(p1), "\"%s\"", rules[i].process);

                        if (strcmp(rules[i].parent, "*") == 0) strcpy(p2, "PREFIX_NOCARE");
                        else if (strcmp(rules[i].parent, "!INVALID") == 0) strcpy(p2, "PREFIX_INVALID_BINARY");
                        else snprintf(p2, sizeof(p2), "\"%s\"", rules[i].parent);

                        if (strcmp(rules[i].grandparent, "*") == 0) strcpy(p3, "PREFIX_NOCARE");
                        else if (strcmp(rules[i].grandparent, "!INVALID") == 0) strcpy(p3, "PREFIX_INVALID_BINARY");
                        else snprintf(p3, sizeof(p3), "\"%s\"", rules[i].grandparent);

                        snprintf(newline, sizeof(newline),
                                 "#define RELATION_%d %s, %s, %s, %s, %d,%d,%d",
                                 i, p1, p2, p3, rules[i].action,
                                 rules[i].redirect, rules[i].zone, rules[i].hook);
                    }

                    int old_len = eol - pos;
                    int new_len = strlen(newline);
                    if (new_len != old_len) {
                        memmove(pos + new_len, pos + old_len, clen - (pos - content) - old_len + 1);
                        clen += (new_len - old_len);
                    }
                    memcpy(pos, newline, new_len);
                }

                dst = fopen(prm_h, "w");
                if (dst) {
                    fwrite(content, 1, clen, dst);
                    fclose(dst);
                }
                free(content);
            }

            dirty = 0;
            mvprintw(h-1, 1, " Saved (backup: PRM.h.bak). Run 'make' to rebuild. ");
            refresh();
            napms(2000);
        }
    }

    endwin();
    return 0;
}
