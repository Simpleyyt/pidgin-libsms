#include <stdio.h>
#include <string.h>
#include "tcp.h"

int main() {
    int fd = tcp_init(8888);
    char *ip_address = "127.0.0.1";
    char *sendtext = "TCP Test\n";
    printf("Connect to %s...\n", ip_address);
    if (tcp_connect(fd, ip_address) == -1)
        return -1;
    printf("Sending text:\n%s\n", sendtext);
    tcp_send(fd, sendtext, strlen(sendtext));
    tcp_close(fd);
    return 0;
}
