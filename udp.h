#ifndef UDP_H
#define UDP_H

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>

#define udp_tag "udp"

#define udp_debug_info(format, ...) fprintf(stdout, "%s:", udp_tag);\
                                    fprintf(stdout, format,## __VA_ARGS__);\
                                    fprintf(stdout, "\n")

#define udp_debug_error(format, ...) fprintf(stderr, "%s:", udp_tag);\
                                     fprintf(stderr, "%s: %s(errno: %d)\n", format, strerror(errno), errno, ## __VA_ARGS__)

#ifdef  DEBUG
#define udp_debug_trace(format, ...)  fprintf(stdout, "%s:", udp_tag);\
                                      fprintf(stdout, format,## __VA_ARGS__);\
                                      fprintf(stdout, "\n")
#else
#define udp_debug_trace(format, ...)  NULL
#endif


struct _UdpSocket {
    int sockfd;
    struct sockaddr_in *servaddr;
};
typedef struct _UdpSocket UdpSocket;

UdpSocket *udp_init(const char *ip, int port);
UdpSocket *udp_init_broadcast(int port);
int udp_send(UdpSocket *sock, const void *buf, uint32_t length);
int udp_close(UdpSocket *sock);

#endif
