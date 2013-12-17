#ifndef _TCP_
#define _TCP_

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<unistd.h>

#define TCP_TAG "tcp"

#define tcp_debug_info(format, ...) fprintf(stdout, "%s:", TCP_TAG);\
                                     fprintf(stdout, format,## __VA_ARGS__);\
                                     fprintf(stdout, "\n")

#define tcp_debug_error(format, ...) fprintf(stderr, "%s:", TCP_TAG);\
                                     fprintf(stderr, "%s: %s(errno: %d)\n", format, strerror(errno), errno, ## __VA_ARGS__)

#ifdef  DEBUG
#define tcp_debug_trace(format, ...)  fprintf(stdout, "%s:", TCP_TAG);\
                                      fprintf(stdout, format,## __VA_ARGS__);\
                                      fprintf(stdout, "\n")
#else
#define tcp_debug_trace(format, ...)  NULL
#endif

int tcp_init(int port);

int tcp_connect(int sockfd, char *ip_address); 

int tcp_send(int sockfd, const void *buf, int32_t length);

int tcp_close(int sockfd);

#endif
