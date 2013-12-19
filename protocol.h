#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdio.h>
#include "udp.h"
#include "json.h"
#include "context.h"
#include "crypt/aes.h"
#include "crypt/sha1.h"

#define PROTOCOL_TAG "protocol"

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

typedef struct _PtlHeader {
    char *from;
    char *to;
    char *ver;
    char *key;
    char *dist;
} PtlHeader;

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

//Json value helper
json_val_t *json_val_create(int is_object);
int json_val_append_string(json_val_t *val_t, char *key, const char *val);
int json_val_append_val(json_val_t *val_t, char *key, json_val_t *elem_val);
int json_val_pretty(json_printer *printer, json_val_t *val);
int json_val_free(json_val_t *val);

//Protocol pretty helper
int protocol_init(PtlHeader *header);
int protocol_set_key(PtlHeader *header, char *user, char *pwd);
int protocol_pretty_val(Context *ctx, json_val_t *val);
int protocol_encrypt_val(Context *ctx, PtlHeader *header, json_val_t *val);
int protocol_send_val(UdpSocket *sock, PtlHeader *header, json_val_t *val);
int protocol_send_auth(UdpSocket *sock, PtlHeader *header, const char *user, const char *pwd);

//Protocol parser
int protocol_parser_init(protocol_parser_t *parser);
int protocol_parser_string(protocol_parser_t *parser, const char *string, uint32_t length);
int protocol_decrypt_string(Context *ctx, PtlHeader *header);
int protocol_parser_is_done (protocol_parser_t *parser);
char *protocol_get_string(json_val_t *val, const char* key);
json_val_t *protocol_get_val(json_val_t *val, const char* key);
void protocol_parser_free (protocol_parser_t *parser);

//Json function callback
static void *tree_create_structure(int nesting, int is_object);
static char *memalloc_copy_length(const char *src, uint32_t n);
static void *tree_create_data(int type, const char *data, uint32_t length);
static int tree_append(void *structure, char *key, uint32_t key_length, void *obj);
static int printer_cb (void *userdata, const char *s, uint32_t length);

#endif
