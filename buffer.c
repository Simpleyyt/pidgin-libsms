#include "buffer.h"

int buffer_init(Buffer *buffer) {
    buffer->buffer = (char *)malloc(INIT_SIZE * sizeof(char));
    buffer->size = INIT_SIZE;
    buffer->pos = 0;

    return 0;
}

int buffer_update(Buffer *buffer, char *input, int ilen) {
    int total = ilen + buffer->pos;
    int i;

    if (total > buffer->size) {
        return -1;
    }

    for (i = 0; i < ilen; i++) {
        buffer->buffer[buffer->pos] = input[i];
        buffer->pos++;
    }

    return 0;
}

int buffer_merge(Buffer *source, int begin, Buffer *dist, int ilen) {
    buffer_update(dist, source->buffer + begin, ilen);

    return 0;
}

int buffer_merge_all(Buffer *source, int begin, Buffer *dist) {
    return buffer_merge(source, begin, dist, source->pos - begin);
}

int buffer_depadding(Buffer *buffer) {
    int pos = buffer->pos - 1;
    char len;
    if (pos < 0)
        return -1;
    len = buffer->buffer[pos];
    buffer->pos = buffer->pos - len;

    return 0;
}

int buffer_padding(Buffer *buffer) {
    int i = 16;
    int len;
    char k;
    while (i <= buffer->pos) {
        i += 16;
    }
    len = i - buffer->pos;
    k = (char) len;
    for (i = 0; i < len; i++)
        buffer_update(buffer, &k, 1);

    return 0;
}

int buffer_free(Buffer *buffer) {
    free(buffer->buffer);
    buffer->size = 0;
    buffer->pos = 0;

    return 0;
}
