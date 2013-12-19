#ifndef CONTEXT_H
#define CONTEXT_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define INIT_SIZE 1024 

typedef struct _Context {
    char *buffer;
    int pos;
    int size;
} Context;

int context_init(Context *ctx);
int context_update(Context *ctx, char *input, int ilen);
int context_free(Context *ctx);

#endif
