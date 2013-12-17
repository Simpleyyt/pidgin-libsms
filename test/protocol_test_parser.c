#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include "protocol.h"

FILE *open_filename(const char *filename, const char *opt, int is_input)
{
    FILE *input;
    if (strcmp(filename, "-") == 0)
        input = (is_input) ? stdin : stdout;
    else {
        input = fopen(filename, opt);
        if (!input) {
            fprintf(stderr, "error: cannot open %s: %s", filename, strerror(errno));
            return NULL;
        }
    }
    return input;
}
void close_filename(const char *filename, FILE *file)
{
    if (strcmp(filename, "-") != 0)
        fclose(file);
}

int process_file(protocol_parser_t *parser, FILE *input)
{
    char buffer[4096];
    int ret = 0;
    int32_t read;
    int i;

    while (1) {
        read = fread(buffer, 1, 4096, input);
        if (read <= 0)
            break;
        ret = protocol_parser_string(parser, buffer, read);
    }
    return ret;
}

int main() {
    FILE *input;
    protocol_parser_t parser;
    int ret;
    char *filename = "test.json";
    int int_value;
    json_val_t *val;

    input = open_filename(filename, "r", 1);
    if (!input)
        return 2;

    ret = protocol_parser_init(&parser);
    if (ret) {
        return ret;
    }

    ret = process_file(&parser, input);
    if (ret)
        return 1;

    ret = protocol_parser_is_done(&parser);
    if (!ret)
        return 1;

    val = protocol_get_val (parser.parser_dom->root_structure, "key2", "key1" , NULL);
    if (val == NULL)
        return 1;
    printf ("The key2->key1 value is %s\n", val->u.data);
    
    int_value = protocol_get_int_val (parser.parser_dom->root_structure, "key3", NULL);

    printf ("The key3 value is %d\n", int_value);
    close_filename(filename, input);
    return 0;
}
