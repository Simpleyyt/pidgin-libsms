#include <stdio.h>
#include <string.h>
#include "udp.h"

int main() {
    int fd = udp_init(8887);
    char *sendtext = "UDP Test\n";
    printf("Sending text:\n%s\n", sendtext);
    udp_send(fd, sendtext, strlen(sendtext));
    udp_close(fd);
    return 0;
}
