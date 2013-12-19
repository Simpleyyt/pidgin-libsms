#include "context.h"

int context_init(Context *context)
{
    context->buffer = (char *)malloc(INIT_SIZE * sizeof(char));
    context->size = INIT_SIZE;
    context->pos = 0;

    return 0;
}

int context_update(Context *context, char *input, int ilen)
{
    int total = ilen + context->pos;

    if (total > context->size) {
        return -1;
    }
    strncpy(context->buffer + context->pos, input, ilen);
    context->pos = total;

    return 0;
}

int context_free(Context *context)
{
    free(context->buffer);
    context->size = 0;
    context->pos = 0;

    return 0;
}
