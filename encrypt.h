#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "crypt/aes.h"

#define INIT_SIZE 1024 

#define encrypt_tag "encrypt"

#define encrypt_debug_info(format, ...) fprintf(stdout, "%s:", encrypt_tag);\
                                        fprintf(stdout, format,## __VA_ARGS__);\
                                        fprintf(stdout, "\n")

#define encrypt_debug_error(format, ...) fprintf(stderr, "%s:", encrypt_tag);\
                                         fprintf(stderr, format,## __VA_ARGS__);\
                                         fprintf(stderr, "\n")

#ifdef  debug
#define encrypt_debug_trace(format, ...)  fprintf(stdout, "%s:", encrypt_tag);\
                                          fprintf(stdout, format,## __VA_ARGS__);\
                                          fprintf(stdout, "\n")
#else
#define encrypt_debug_trace(format, ...)  NULL
#endif

typedef struct _EncryptContext {
    char *context;
    int pos;
    int size;
    int is_encrypted;
    aes_context *aes;
} EncryptContext;

int encrypt_init(EncryptContext *context, aes_context *aes);
int encrypt_update(EncryptContext *context, char *input, int ilen);
char *encrypt_encrypt(EncryptContext *context, unsigned char iv[16]);
int encrypt_free(EncryptContext *context);
