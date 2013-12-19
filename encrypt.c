#include "encrypt.h"

int encrypt_init(EncryptContext *context, aes_context *aes)
{
    context->context = (char *)malloc(INIT_SIZE * sizeof(char));
    context->size = INIT_SIZE;
    context->pos = 0;
    context->aes = aes;
    context->is_encrypted = 0;
    return 0;
}

int encrypt_update(EncryptContext *context, char *input, int ilen)
{
    int total = ilen + context->pos;
    if (total > context->size)
    {
        encrypt_debug_error("buffer is full");
        return -1;
    }
    strncpy(context->context+context->pos, input, ilen);
    context->pos = total;
    return 0;
}

char *encrypt_encrypt(EncryptContext *context, unsigned char iv[16])
{
    if (context->is_encrypted)
        return context->context;
    aes_crypt_cbc(context->aes, AES_ENCRYPT, context->pos, iv, 
            context->context, context->context);
    return context->context;
}

int encrypt_free(EncryptContext *context)
{
    free(context->context);
    context->size = 0;
    context->pos = 0;
    return 0;
}
