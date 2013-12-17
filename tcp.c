#include "tcp.h" 

static int tcp_port;

int tcp_init(int port) 
{
    int sockfd;

    tcp_port = port;

    //Create socket
    tcp_debug_info("Creating tcp socket, listen port:%d", port);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        tcp_debug_error("Create tcp socket error");
        return -1;
    }

    tcp_debug_info("Initialized tcp socket");
    return sockfd;
}

int tcp_connect(int sockfd, char *ip_address) 
{
    struct sockaddr_in servaddr;

    tcp_debug_info("Connect to ip address: %s", ip_address);

    //Convert character to ip address
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(tcp_port);
    if (inet_pton(AF_INET, ip_address, &servaddr.sin_addr) <= 0) {
        tcp_debug_error("Convert character to ip address error"); 
        return -1;
    }

    //Connect to ip address
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        tcp_debug_error("Connect to ip address error");
        return -1;
    }

    tcp_debug_info("Connected to ip address");
    return 0;
}

int tcp_send(int sockfd, const void *buf, int32_t length) 
{
    //Send data to server
    tcp_debug_info("Send data to server\nSending data:\n%s\nSending data length:%d", (const char*)buf, length);
    if (send(sockfd, buf, length, 0) < 0) {
        tcp_debug_error("Send data error");
        return -1;
    }

    tcp_debug_info("Sended data");
    return 0;
}

int tcp_close(int sockfd) 
{
    tcp_debug_info("Closing tcp socket");
    if (close(sockfd)) {
        tcp_debug_error("Close tcp socket error");
        return -1;
    }

    tcp_debug_info("Closed tcp socket");
    return 0;
}
