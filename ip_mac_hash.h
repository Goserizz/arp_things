/* ip_mac hash functions */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void add (unsigned int ip, unsigned char* mac, unsigned char** hash, int mask)
{
    int index = ip >> (32 - mask);
    if (hash[index] == NULL)
        hash[index] = (unsigned char*) malloc (6);
    memcpy(hash[index], mac, 6);
}

void save (unsigned char** hash, int host_num)
{
    FILE *fp;
    if ((fp = fopen ("ip_mac.bin", "wb")) == NULL){
        printf ("Error occurs while opening the file.");
        exit (1);
    }
    for (int i = 0; i < host_num; i ++){
        if (hash[i] != NULL)
            fwrite (hash[i], sizeof (uint8_t), 6, fp);
    }
    fclose (fp);
}