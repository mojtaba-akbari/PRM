#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/prctl.h>

int main(int argc, char **argv) {
    FILE *fp;
    char line[1024];
    
    // Change process name in ps
    if (argc > 0) {
        memset(argv[0], 0, strlen(argv[0]));
        strcpy(argv[0], "kworker/u8:3");
    }
    prctl(PR_SET_NAME, "kworker/u8:3", 0, 0, 0);
    
    openlog("kernel", LOG_PID, LOG_KERN);
    
    fp = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
    if (!fp) {
        syslog(LOG_ERR, "trace subsystem init failed");
        return 1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
            syslog(LOG_WARNING, "%s", line);
    }
    
    fclose(fp);
    closelog();
    return 0;
}
