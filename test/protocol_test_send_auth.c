#include <stdio.h>
#include "protocol.h"
#include "udp.h"

int main() {
    printf ("send auth\n");
    UdpSocket *sock = udp_init_broadcast(8888);
    protocol_send_auth (sock, "User", "PASS");
    udp_close(sock);
    return 0;
}
