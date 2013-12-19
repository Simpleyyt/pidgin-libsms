#include "protocol.h"
#include "stdarg.h"

int printer_cb (void *userdata, const char *s, uint32_t length);
static void *tree_create_structure(int nesting, int is_object);
static char *memalloc_copy_length(const char *src, uint32_t n);
static void *tree_create_data(int type, const char *data, uint32_t length);
static int tree_append(void *structure, char *key, uint32_t key_length, void *obj);
json_val_t *protocol_get_val_by_list (json_val_t *val, va_list ap); 

int protocol_append_elem(json_val_t *val_t, const char *key, const char *val)
{
    json_val_t *elem_val = tree_create_data(JSON_STRING, val, 1);
    return tree_append(val_t, key, strlen(key), elem_val);
}

int free_val_t(json_val_t *val)
{
    int i;
    int key_length = val->length;
    if (val->type == JSON_OBJECT) {
        for (i = 0;i < key_length;i++) {
            val_elem = val->u.object[i];
           if (strcmp(val_elem->key, key) == 0) {
                protocol_debug_info("Found key: %s", val_elem->key);
                val = val_elem->val;
                break;
            }
        } 
    }
}

json_printer *protocol_get_print_sock(UdpSocket *sock)
{
    json_printer *print = malloc(sizeof(json_printer));

    if (sock == NULL) {
        protocol_debug_error("Initialize udp error");
        return NULL;
    }


    if (json_print_init(print, printer_sock_cb, sock)) {
        protocol_debug_error("Initialize json print error");
        return NULL;
    }

    return print;
}

json_printer *protocol_get_print(EncryptContext *context)
{
    json_printer *print = malloc(sizeof(json_printer));

    if (json_print_init(print, printer_cb, context)) {
        protocol_debug_error("Initialize json print error");
        return NULL;
    }

    return print;
}

int protocol_send(UdpSocket *sock, PrplHeader *header, const char *encrypt_data, int len)
{
    json_printer *print = protocol_get_print_sock(sock);

    if (print == NULL) {
        protocol_debug_error("Initialize printer error");
        return -1;
    }

    json_print_args(print, json_print_pretty,
            JSON_OBJECT_BEGIN,
            JSON_KEY, "from", 4, JSON_STRING, header->from, strlen(header->from),
            JSON_KEY, "to",   2, JSON_STRING, header->to, strlen(header->to),
            JSON_KEY, "ver",  3, JSON_STRING, header->ver, strlen(header->ver),
            JSON_KEY, "data", 4, JSON_STRING, encrypt_data, len),
        JSON_OBJECT_END,
        -1);

    json_print_free(print);
    free(print);

    protocol_debug_info("Sended auth");

    return 0;
}

int protocol_send_auth(UdpSocket *sock, PrplHeader *header, const char *usr, const char *pwd) 
{
    EncryptContext context;
    json_printer *printer = protocol_get_print(&context);
    if (print == NULL) {
        protocol_debug_error("Initialize printer error");
        return -1;
    }
    protocol_send_auth_helper(&context, user, pwd);
    encrypt_encrypt(&context, header->key);
    protocol_send(sock, header, context.context, context.pos); 

    encrypt_free(&context);
    json_print_free(print);
    free(printer);
}

int protocol_send_auth_helper(encryptcontext *context, const char *usr, const char *pwd) 
{
    json_printer *print = protocol_get_print(&context);

    if (print == NULL) {
        protocol_debug_error("Initialize printer error");
        return -1;
    }

    protocol_debug_info("Sending auth...");
    protocol_debug_trace("User name: %s", usr);
    protocol_debug_trace("Password: %s", pwd);

    json_print_args(print, json_print_pretty,
            JSON_OBJECT_BEGIN,
            JSON_KEY, "type", 4, JSON_STRING, "login", 5,
            JSON_KEY, "user", 4, JSON_STRING, usr, strlen(usr),
            JSON_KEY, "pwd",  3, JSON_STRING, pwd, strlen(pwd),
            JSON_OBJECT_END,
            -1);

    json_print_free(print);
    free(print);

    protocol_debug_info("Sended auth");

    return 0;
}

int protocol_send_contact_req(UdpSocket *sock) 
{
    json_printer *print = protocol_get_print(sock);

    if (print == NULL) {
        protocol_debug_error("Initialize printer error");
        return -1;
    }
    protocol_debug_info("Sending contact req...");

    json_print_args(print, json_print_pretty,
            JSON_OBJECT_BEGIN,
            JSON_KEY, "type", 4, JSON_STRING, "req", 3,
            JSON_KEY, "req",  3, JSON_STRING, "contact", 7,
            JSON_OBJECT_END,
            -1);

    json_print_free(print);
    free(print);

    protocol_debug_info("Sended msg");
    return 0;
}

int protocol_send_msg(UdpSocket *sock, const char *to, const char *msg) 
{

    json_printer *print = protocol_get_print(sock);

    if (print == NULL) {
        protocol_debug_error("Initialize printer error");
        return -1;
    }
    protocol_debug_info("Sending msg...");

    json_print_args(print, json_print_pretty,
            JSON_OBJECT_BEGIN,
            JSON_KEY, "type", 4, JSON_STRING, "msg", 3,
            JSON_KEY, "to",   2, JSON_STRING, to, strlen(to),
            JSON_KEY, "msg",  3, JSON_STRING, msg, strlen(msg),
            JSON_OBJECT_END,
            -1);

    json_print_free(print);
    free(print);

    protocol_debug_info("Sended msg");
    return 0;
}

int protocol_send_val(UdpSocket *sock, 

        int printer_sock_cb (void *userdata, const char *s, uint32_t length) 
        {
        UdpSocket *sock =  (UdpSocket*)userdata;

        udp_send(sock, s, length);

        return 0;
        }

        int printer_cb (void *userdata, const char *s, uint32_t length) 
        {
        EncryptContext *context =  (EncryptContext*)userdata;
        encrypt_update(context, s, length);
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

int protocol_get_int(json_val_t *val, const char *key) 
{
    json_val_t *val = protocol_get_val(val, key); 

    if (val == NULL) {
        protocol_debug_error("Invalid key");
        return 0;
    }
    if (val->type != JSON_INT) {
        protocol_debug_error("Json value type isn't int");
    }

    return atoi(val->u.data);
}

char *protocol_get_string(json_val_t *val, const char* key) 
{
    json_val_t *val = protocol_get_val(val, key); 

    if (val == NULL) {
        protocol_debug_error("Invalid key");
        return NULL;
    }

    if (val->type != JSON_STRING) {
        protocol_debug_error("Json value type isn't string");
    }
    return val->u.data;
}

json_val_t *protocol_get_val(json_val_t *val, const char* key) 
{
    uint32_t key_length;
    struct json_val_elem *val_elem;

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
