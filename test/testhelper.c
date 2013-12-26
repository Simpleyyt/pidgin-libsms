#include <stdio.h>
#include <string.h>
#include "testhelper.h"

void printHex(unsigned char *byte, int len)
{
    int i;
    for(i=0; i<len; i++)
    {
        printf("%.2x ", byte[i]);
    }
    printf("\n");
    
}
