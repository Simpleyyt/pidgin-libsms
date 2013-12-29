#include <stdio.h>
#include "protocol.h"

int main()
{
    UdpSocket *sock = udp_init_broadcast(8889);
    PtlHeader header;
    protocol_init(&header);
    header.from = "1";
    header.to = "2";
    protocol_set_key(&header, "user", "pwd");
    protocol_send_auth(sock, &header, "user", "pwd");
    udp_close(sock);
    return 0;
}
