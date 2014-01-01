#ifndef BUFFER_H
#define BUFFER_H

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
int buffer_padding(Buffer *buffer);
int buffer_depadding(Buffer *buffer);
int buffer_merge_all(Buffer *source, int begin, Buffer *dist);
int buffer_merge(Buffer *source, int begin, Buffer *dist, int ilen);
int buffer_free(Buffer *ctx);

#endif
