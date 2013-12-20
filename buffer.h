#ifndef CONTEXT_H
#define CONTEXT_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define INIT_SIZE 1024 

typedef struct _Buffer {
    char *buffer;
    int pos;
    int size;
} Buffer;

int buffer_init(Buffer *ctx);
int buffer_update(Buffer *ctx, char *input, int ilen);
int buffer_split(Buffer *first, Buffer *second, int size);
int buffer_padding(Buffer *buffer, char c);
int buffer_free(Buffer *ctx);

#endif