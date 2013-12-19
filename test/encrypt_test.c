#include <stdio.h>
#include "crypt/aes.h"
#include "crypt/sha1.h"
#include "encrypt.h"
#include <string.h>

int main()
{
    aes_context aes;
    sha1_context sha;
    unsigned char key[16] = "0123456789abcdef";
    unsigned char sha_key[21] = {0};
    unsigned char iv[16] = "0123456789abcdef";
    unsigned char iv1[16] = "0123456789abcdef";
    unsigned char output[16] = "my name is yita";
    unsigned char *temp;
    EncryptContext context;
    
    encrypt_init(&context, &aes);    
    
    sha1_starts(&sha);
    sha1_update (&sha, key, 16);
    sha1_finish (&sha, sha_key);
    printf ("sha:\n%s\n", sha_key);
    
    printf ("text:\n%s\n", output);
    aes_setkey_enc(&aes, sha_key, 128);

    encrypt_update(&context,output,16);
    temp = encrypt_encrypt(&context,iv);

    //aes_crypt_cbc(&aes, AES_ENCRYPT, 16, iv, output, output);
    printf ("encrypt:\n%s\n", temp);

    aes_setkey_dec(&aes, sha_key, 128);
    aes_crypt_cbc(&aes, AES_DECRYPT, 16, iv1, temp, temp);
    printf ("decrypt:\n%s\n", temp);
    return 0;
}
