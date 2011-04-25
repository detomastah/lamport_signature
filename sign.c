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
    FILE *pkr_file, *sig_file;
    
    file_descript = open(argv[1], O_RDONLY);
    if(file_descript < 0) {
        puts("Message unreadable");
        exit(-1);
    }
    
    file_size = get_size_by_fd(file_descript);    
    file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, file_descript, 0);

    MD5((unsigned char*) file_buffer, file_size, md5);
    generateKeys();
    signMsg(md5);
    
    //write PKR
    pkr_file = fopen (argv[3],"w");
    if (pkr_file!=NULL)
    {
        fwrite(S, sizeof(DES_cblock), 2*BITS, pkr_file);
        fwrite(R, sizeof(DES_cblock), 2*BITS, pkr_file);
        fclose (pkr_file);
    } else { puts("Cannot write PKR"); return -1; }
    
    //write signature
    sig_file = fopen (argv[2],"w");
    if (sig_file!=NULL)
    {
        fwrite(SG , sizeof(DES_cblock), BITS , sig_file);
        fwrite(file_buffer, 1, file_size, sig_file);
        fclose (sig_file);
    } else { puts("Cannot write signed message"); return -1; }
    
    if (verifyMsg(md5)) puts("FAIL");
    else puts ("OK");
    
    return (0);
}
