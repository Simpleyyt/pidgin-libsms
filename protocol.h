#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include <stdio.h>
#include "udp.h"
#include "json.h"

#define PROTOCOL_TAG "protocol"

#define VAL_EX(V, N)        JSON_KEY, #V, N
#define VAL(V)              VAL_EX(V, strlen(#V)) 
#define KEY_EX(K, N)        JSON_STRING, #K, N
#define KEY(K)              KEY_EX(K,strlen(#K)
#define VAL_KEY(V, K)       VAL(V), KEY(K)

#define protocol_debug_info(format, ...) fprintf(stdout, "%s:", PROTOCOL_TAG);\
                                         fprintf(stdout, format,## __VA_ARGS__);\
                                         fprintf(stdout, "\n")

#define protocol_debug_error(format, ...) fprintf(stderr, "%s:", PROTOCOL_TAG);\
                                          fprintf(stderr, format,## __VA_ARGS__);\
                                          fprintf(stderr, "\n")

#define protocol_debug_trace(format, ...) fprintf(stdout, "%s:", PROTOCOL_TAG);\
                                          fprintf(stdout, format,## __VA_ARGS__);\
                                          fprintf(stdout, "\n")


struct json_val_elem {
    char *key;
    uint32_t key_length;
    struct json_val *val;
};

typedef struct _PrplHeader {
    char *from;
    char *to;
    char *ver;
    char *key;
} PrplHeader;

typedef struct json_val {
    int type;
    int length;
    union {
        char *data;
        struct json_val **array;
        struct json_val_elem **object;
    } u;
} json_val_t;

typedef struct protocol_parser {
    json_parser *parser;
    json_parser_dom *parser_dom;
} protocol_parser_t;


json_printer *protocol_get_print(UdpSocket *sock);

int protocol_send_contact_req(UdpSocket *sock);

int protocol_send_auth(UdpSocket *sock, const char *usr, const char *pwd);

int protocol_send_msg(UdpSocket *sock, const char *to, const char *msg);

int protocol_parser_init(protocol_parser_t *parser);


int protocol_parser_string(protocol_parser_t *parser, const char *string, uint32_t length);

void protocol_parser_free (protocol_parser_t *parser);

int protocol_parser_is_done (protocol_parser_t *parser);

char *protocol_get_string_val (json_val_t *val, ...);

json_val_t **protocol_get_array_val (json_val_t *val, ...);

json_val_t *protocol_get_val (json_val_t *val, ...);

#endif
