#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>

#include <openssl/md5.h>
#include <openssl/des.h>

#include "common.h"

int main(int argc, char *argv[]) {
    char md5[MD5_DIGEST_LENGTH];
    int file_descript;
    unsigned long file_size;
    char *file_buffer;
    FILE *pkr_file;
    int signature_size = BITS*sizeof(DES_cblock);
    
    file_descript = open(argv[1], O_RDONLY);
    if(file_descript < 0) { 
        puts("Signed message unreadable");
        exit(-1);
    }
    
    //read signed message
    file_size = get_size_by_fd(file_descript);    
    file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);
    //copy signature
    memcpy(SG, file_buffer, signature_size);
    
    MD5((unsigned char*) (file_buffer+signature_size), file_size-signature_size, md5);
    //read PKR

    pkr_file = fopen (argv[2],"r");
    if (pkr_file!=NULL)
    {
        fread(S, sizeof(DES_cblock), 2*BITS, pkr_file);
        fread(R, sizeof(DES_cblock), 2*BITS, pkr_file);
        fclose (pkr_file);
    } else { puts("PKR unreadable"); return -1; }
    
    if (verifyMsg(md5)) puts("FAIL");
    else puts ("OK");
    
    return (0);
}
