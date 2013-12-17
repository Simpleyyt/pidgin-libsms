#include "udp.h" 


UdpSocket *udp_init(const char *ip, int port) 
{
    int sockfd;
    struct sockaddr_in *servaddr = malloc(sizeof(struct sockaddr_in));
    UdpSocket *udp_sock = malloc(sizeof(UdpSocket));

    //Create ip address
    memset(servaddr, 0, sizeof(*servaddr));
    servaddr->sin_family = AF_INET;
    servaddr->sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &servaddr->sin_addr) <= 0) {
        udp_debug_error("Convert character to ip address error"); 
        return NULL;
    }
    udp_sock->servaddr = servaddr;    

    //Create socket
    udp_debug_info("Creating udp socket. Port:%d ...", port);
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        udp_debug_error("Create udp socket error");
        return NULL;
    }

    udp_debug_info("Initialized socket");
    udp_sock->sockfd = sockfd;
    return udp_sock;
}

UdpSocket *udp_init_broadcast(int port) {
    return udp_init("0.0.0.0", port);
}

int udp_send(UdpSocket *sock, const void *buf, uint32_t length) 
{
    if (sendto(sock->sockfd, buf, length, 0, (struct sockaddr*)(sock->servaddr), sizeof(*sock->servaddr)) < 0) {
        udp_debug_error("Send data error");
        return -1;
    }
    return 0;
}

int udp_close(UdpSocket *socket) 
{
    udp_debug_info("Closing udp broadcast...");

    if (close(socket->sockfd)) {
        udp_debug_error("Close socket error");
        return -1;
    }

    free(socket->servaddr);
    free(socket);
    udp_debug_info("Closed socket");
    return 0;
}
