#include "buffer.h"

int buffer_init(Buffer *buffer)
{
    buffer->buffer = (char *)malloc(INIT_SIZE * sizeof(char));
    buffer->size = INIT_SIZE;
    buffer->pos = 0;

    return 0;
}

int buffer_update(Buffer *buffer, char *input, int ilen)
{
    int total = ilen + buffer->pos;

    if (total > buffer->size) {
        return -1;
    }
    strncpy(buffer->buffer + buffer->pos, input, ilen);
    buffer->pos = total;

    return 0;
}

int buffer_split(Buffer *first, Buffer *second, int size)
{
    buffer_update(second, first->buffer + size, first->pos -size);
    first->pos = size;
    return 0;
}

int buffer_padding(Buffer *buffer, char c)
{
    int i = 16;
    int k;
    while (i < buffer->pos) {
        i += 16;
    }
    k = i - buffer->pos;
    for (i=0;i<k;i++)
        buffer_update(buffer, &c, 1);

    return 0;
}

int buffer_free(Buffer *buffer)
{
    free(buffer->buffer);
    buffer->size = 0;
    buffer->pos = 0;

    return 0;
}