#include <stdio.h>
#include "protocol.h"
#include "buffer.h"

int main()
{
    FILE *fd;
    char buffer[4096];
    Buffer ctx;
    json_val_t *val;
    PtlHeader header;
    char dist[20];
    char *str;

    protocol_init(&header);
    protocol_set_key(&header, "user", "pwd");

    buffer_init(&ctx);
    if ((fd = fopen("test.dec", "r")) == NULL) {
        printf("Can't open file\n");
        return 1;
    }
    while (1) {
        int read = fread(buffer, 1, 4096, fd);
        if (read <= 0)
            break;
        buffer_update(&ctx, buffer, read);
    } 

    val = protocol_decrypt_string(&ctx, &header, dist);

    if (strncmp(dist, header.dist, 20) == 0) {
        printf("vertify succeed\n");
    } else
        printf("vertify failed\n");

    if (val == NULL) {
        printf("parse failed\n");
        return 1;
    }
    str = protocol_get_string(val, "ver");

    printf ("the val of key:\"%s\" is \"%s\"\n", "ver", str);
    
    return 0;
}
