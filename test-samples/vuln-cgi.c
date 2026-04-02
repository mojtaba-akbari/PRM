#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

void redirect() {
    static char msg1[] = "Content-Type: text/plain\r\n\r\n";
    static char msg2[] = "redirected\n";
    static char path[] = "/var/www/class";
    static char data[] = "user|pg|1\n";
    
    write(1, msg1, sizeof(msg1)-1);
    write(1, msg2, sizeof(msg2)-1);
    
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        write(fd, data, sizeof(data)-1);
        close(fd);
    }
    
    _exit(0);
}

void userBuff(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Content-Type: text/plain\r\n\r\n");
    printf(buffer);
}

int main() {
    char *query = getenv("QUERY_STRING");
    
    printf("Content-Type: text/plain\r\n\r\n");
    
    if (query && strstr(query, "_redirect_")) {
        printf("redirecting..\n");
        redirect();
    }
    
    if (query) {
        userBuff(query);
    } else {
        printf("No input provided\n");
    }
    
    return 0;
}
