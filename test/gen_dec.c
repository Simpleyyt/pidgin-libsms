#include <stdio.h>
#include "protocol.h"

int main()
{
    FILE *fd;
    FILE *fd_to;
    char buffer[4096];
    Context ctx;
    json_val_t *val;
    PtlHeader header;
    char dist[20];
    char *str;

    protocol_init(&header);
    protocol_set_key(&header, "user", "pwd");

    context_init(&ctx);
    if ((fd = fopen("test.json", "r")) == NULL) {
        printf("Can't open file\n");
        return 1;
    }

    while (1) {
        int read = fread(buffer, 1, 4096, fd);
        if (read <= 0)
            break;
        context_update(&ctx, buffer, read);
    } 

    if ((fd_to = fopen("test.dec", "w")) == NULL) {
        printf("Can't open file\n");
        return 1;
    }

    protocol_encrypt_string(&ctx, &header);
    fwrite(header.dist, 1, 20, fd_to);
    fwrite(ctx.buffer, 1, ctx.pos, fd_to);
    return 0;
}
