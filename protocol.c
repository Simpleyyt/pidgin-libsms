#include "protocol.h"
#include "stdarg.h"

int json_val_append_string(json_val_t *val_t, char *key, const char *val)
{
    json_val_t *elem_val = tree_create_data(JSON_STRING, val, strlen(val));
    return json_val_append_val(val_t, key, elem_val);
}

int json_val_append_val(json_val_t *val_t, char *key, json_val_t *elem_val)
{
    return tree_append(val_t, key, strlen(key), elem_val);
}

int json_val_free(json_val_t *val)
{
    int i;
    struct json_val_elem *val_elem;
    if (val->type == JSON_OBJECT_BEGIN) {
        int key_length = val->length;
        for (i = 0;i < key_length;i++) {
            val_elem = val->u.object[i];
            json_val_free(val_elem->val);            
            free(val_elem);
        }
    }
    if (val->type == JSON_ARRAY_BEGIN) {
        int array_len = val->length;
        for (i = 0;i < array_len;i++) {
            json_val_free(val->u.array[i]);
        }
    }
    return 0;
}

int json_val_pretty(json_printer *printer, json_val_t *val)
{
    int i;

    switch(val->type) {
        case JSON_OBJECT_BEGIN:
            json_print_pretty(printer, JSON_OBJECT_BEGIN, NULL, 0);
            for (i = 0;i < val->length;i++) {
                struct json_val_elem *elem = val->u.object[i];
                json_print_pretty(printer, JSON_KEY, elem->key, elem->key_length);
                json_val_pretty(printer, elem->val);
            }
            json_print_pretty(printer, JSON_OBJECT_END, NULL, 0);
            break;
        case JSON_ARRAY_BEGIN:
            json_print_pretty(printer, JSON_ARRAY_BEGIN, NULL, 0);
            for (i = 0;i < val->length;i++) {
                json_val_t *elem_val = val->u.array[i];
                json_val_pretty(printer, elem_val);
            }
            json_print_pretty(printer, JSON_ARRAY_END, NULL, 0);
            break;
        default:
            json_print_pretty(printer, val->type, val->u.data, val->length);
    }

    return 0;
}

int protocol_send_val(UdpSocket *sock, PtlHeader *header, json_val_t *val)
{
    Context ctx;
    Context ctx_a;
    char dist[20];

    context_init(&ctx_a);
    context_init(&ctx);
    protocol_encrypt_val(&ctx, header, val);
    context_update(&ctx_a, header->dist, 20);
    context_update(&ctx_a, ctx.buffer, ctx.pos);
    udp_send(sock, ctx_a.buffer, ctx_a.pos);
    context_free(&ctx);
    context_free(&ctx_a);

    return 0;
}

json_val_t *json_val_create(int is_object)
{
    return tree_create_structure(0, is_object);
}

int protocol_send_auth(UdpSocket *sock, PtlHeader *header, const char *user, const char *pwd)
{
    json_val_t *root = json_val_create(1);
    json_val_t *val = json_val_create(1);

    json_val_append_string(val, "type", "login");
    json_val_append_string(val, "user", user);
    json_val_append_string(val, "pwd", pwd);
    json_val_append_string(root, "from", header->from);
    json_val_append_string(root, "to", header->to);
    json_val_append_string(root, "ver", header->ver);
    json_val_append_val(root, "data", val);
    protocol_send_val(sock, header, root);
    json_val_free(root);
    json_val_free(val);
    free(val);
    free(root);

    return 0;
}

int protocol_init(PtlHeader *header)
{
    header->ver = "1.0";
    header->key = malloc(20 * sizeof(char));
    header->dist = malloc(20 * sizeof(char));
    protocol_debug_info("Initialize header");

    return 0;
}

int protocol_set_key(PtlHeader *header, char *user, char *pwd)
{
    sha1_context sha1_ctx;
    sha1(user, strlen(user), header->dist);
    protocol_debug_info("Setted dist");
    sha1_starts(&sha1_ctx);
    sha1_update(&sha1_ctx, user, strlen(user));
    sha1_update(&sha1_ctx, pwd, strlen(pwd));
    sha1_finish(&sha1_ctx, header->key);
    protocol_debug_info("Setted key");

    return 0;
}

int protocol_pretty_val(Context *ctx, json_val_t *val)
{
    json_printer printer;

    if (json_print_init(&printer, printer_cb, ctx)) {
        protocol_debug_error("Initialize json print error");
        return -1;
    }

    return json_val_pretty(&printer, val);
}

int protocol_encrypt_val(Context *ctx, PtlHeader *header, json_val_t *val)
{
    aes_context aes;
    unsigned char iv[16];
    int iv_off = 0;

    strncpy(iv, header->key, 16);
    protocol_pretty_val(ctx, val);
    protocol_debug_trace("Sent data:\n%s\nlength:%d\n", ctx->buffer, ctx->pos);
    aes_setkey_enc(&aes, header->key, 128);
    aes_crypt_cfb(&aes, AES_ENCRYPT, 16, &iv_off,
            iv, ctx->buffer, ctx->buffer);

    return 0;
}

json_val_t *protocol_decrypt_string(Context *ctx, PtlHeader *header, char dist[20])
{
    protocol_parser_t parser;
    json_val_t *val;
    aes_context aes;
    unsigned char iv[16];
    int iv_off = 0;

    strncpy(iv, header->key, 16);
    strncpy(dist, ctx->buffer, 20);
    aes_setkey_dec(&aes, header->key, 128);
    aes_crypt_cfb(&aes, AES_DECRYPT, 16, &iv_off,
            iv, ctx->buffer + 20, ctx->buffer + 20);
    protocol_parser_init(&parser);
    if (protocol_parser_string(&parser, ctx->buffer + 20, ctx->pos - 20) != 0)
        return NULL;
    if (!protocol_parser_is_done(&parser))
        return NULL;
    
    val = parser.parser_dom->root_structure;
    protocol_parser_free (&parser);

    return val; 
}

static int printer_cb (void *userdata, const char *s, uint32_t length) 
{
    Context *ctx =  (Context*)userdata;

    context_update(ctx, (char *)s, length);

    return 0;
}

int protocol_parser_init(protocol_parser_t *parser) 
{
    json_parser *jparser;
    json_parser_dom *dom;
    jparser = malloc(sizeof(json_parser));
    dom = malloc(sizeof(json_parser_dom));
    parser->parser = jparser;
    parser->parser_dom = dom;

    if (json_parser_dom_init(dom, tree_create_structure, tree_create_data, tree_append)) {
        protocol_debug_error("Initialize json dom error");
        return -1;
    }
    if (json_parser_init(jparser, NULL, json_parser_dom_callback, dom)) {
        protocol_debug_error("Initialize json parser error");
        return-1;
    }
    protocol_debug_info("Initialized json");

    return 0;
}

int protocol_parser_string(protocol_parser_t *parser, const char *string, uint32_t length) 
{
    int rel = json_parser_string(parser->parser, string, length, NULL);

    protocol_debug_trace("Parse string:\n%s", string);
    protocol_debug_trace("Parse length: %d", length);

    if (rel) {
        protocol_debug_error("Parser json error");
        return -1;
    }

    protocol_debug_info("Parsed json");
    return 0;
}

char *protocol_get_string(json_val_t *val, const char* key) 
{
    json_val_t *val_t = protocol_get_val(val, key); 

    if (val_t == NULL) {
        protocol_debug_error("Invalid key");
        return NULL;
    }

    if (val_t->type != JSON_STRING) {
        protocol_debug_error("Json value type isn't string");
    }
    return val_t->u.data;
}

json_val_t *protocol_get_val(json_val_t *val, const char* key) 
{
    uint32_t key_length;
    struct json_val_elem *val_elem;
    int i;

    if (val->type != JSON_OBJECT_BEGIN) {
        protocol_debug_error("Json value isn't object");
        return NULL;
    }

    key_length = val->length;
    for (i = 0;i < key_length;i++) {
        val_elem = val->u.object[i];
        if (strcmp(val_elem->key, key) == 0) {
            protocol_debug_info("Found key: %s", val_elem->key);
            val = val_elem->val;
            break;
        }
    } 
    if (i == key_length) {
        protocol_debug_error("Can't find key");
        return NULL;
    }

    return val;
}

void protocol_parser_free (protocol_parser_t *parser) 
{
    if (parser == NULL)
        return;
    if (parser->parser != NULL) {
        json_parser_free (parser->parser);
        free(parser->parser);
    }
    if (parser->parser_dom != NULL) {
        json_parser_dom_free (parser->parser_dom);
        free(parser->parser_dom);
    }
    protocol_debug_info("Free protocol parser");
}

//dom callback
static void *tree_create_structure(int nesting, int is_object)
{
    json_val_t *v = malloc(sizeof(json_val_t));
    if (v) {
        /* instead of defining a new enum type, we abuse the
         * meaning of the json enum type for array and object */
        if (is_object) {
            v->type = JSON_OBJECT_BEGIN;
            v->u.object = NULL;
        } else {
            v->type = JSON_ARRAY_BEGIN;
            v->u.array = NULL;
        }
        v->length = 0;
    }
    return v;
}

static char *memalloc_copy_length(const char *src, uint32_t n)
{
    char *dest;

    dest = calloc(n + 1, sizeof(char));
    if (dest)
        memcpy(dest, src, n);
    return dest;
}

static void *tree_create_data(int type, const char *data, uint32_t length)
{
    json_val_t *v;

    v = malloc(sizeof(json_val_t));
    if (v) {
        v->type = type;
        v->length = length;
        v->u.data = memalloc_copy_length(data, length);
        if (!v->u.data) {
            free(v);
            return NULL;
        }
    }
    return v;
}

static int tree_append(void *structure, char *key, uint32_t key_length, void *obj)
{
    json_val_t *parent = structure;
    if (key) {
        struct json_val_elem *objelem;

        if (parent->length == 0) {
            parent->u.object = calloc(1 + 1, sizeof(json_val_t *)); /* +1 for null */
            if (!parent->u.object)
                return 1;
        } else {
            uint32_t newsize = parent->length + 1 + 1; /* +1 for null */
            void *newptr;

            newptr = realloc(parent->u.object, newsize * sizeof(json_val_t *));
            if (!newptr)
                return -1;
            parent->u.object = newptr;
        }

        objelem = malloc(sizeof(struct json_val_elem));
        if (!objelem)
            return -1;

        objelem->key = memalloc_copy_length(key, key_length);
        objelem->key_length = key_length;
        objelem->val = obj;
        parent->u.object[parent->length++] = objelem;
        parent->u.object[parent->length] = NULL;
    } else {
        if (parent->length == 0) {
            parent->u.array = calloc(1 + 1, sizeof(json_val_t *)); /* +1 for null */
            if (!parent->u.array)
                return 1;
        } else {
            uint32_t newsize = parent->length + 1 + 1; /* +1 for null */
            void *newptr;

            newptr = realloc(parent->u.object, newsize * sizeof(json_val_t *));
            if (!newptr)
                return -1;
            parent->u.array = newptr;
        }
        parent->u.array[parent->length++] = obj;
        parent->u.array[parent->length] = NULL;
    }
    return 0;
}

int protocol_parser_is_done (protocol_parser_t *parser) 
{
    return json_parser_is_done(parser->parser);
}
