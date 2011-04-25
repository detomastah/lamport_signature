#define BITS 8*MD5_DIGEST_LENGTH

DES_cblock K[2*BITS]; //encrypting MD-5 hash of message, 32bytes = 128 bits
DES_cblock S[2*BITS];
DES_cblock R[2*BITS];

DES_cblock SG[BITS];

/*
void print_sg(DES_cblock *db) {
    int i;
    char *c = db;
    for(i=0; i <8; i++) {
        printf("%02x|", c[i]);
    }
    puts("");
}

void print_md5_sum(unsigned char* md) {
    int i;
    for(i=0; i <MD5_DIGEST_LENGTH; i++) {
            printf("%02x",md[i]);
    }
}
*/

unsigned long get_size_by_fd(int fd) {
    struct stat statbuf;
    if(fstat(fd, &statbuf) < 0) exit(-1);
    return statbuf.st_size;
}

void generateKeys() {
    int i=0;
    DES_key_schedule schedule;  
    for (i=0;i<2*BITS;i++) {
        DES_random_key(&K[i]);
        DES_random_key(&S[i]);
        DES_set_key(&K[i], &schedule);
        DES_ecb_encrypt( &S[i], &R[i], &schedule, DES_ENCRYPT );
    }
}

void signMsg(char *msg) {
    int i=0, j=0, ki=0, idx = 0;
    char c;

    for (i=0;i<MD5_DIGEST_LENGTH;i++) {
        c = msg[i];
        for (j=0;j<8;j++) {
            ki = idx + BITS*(1 & c);
            memcpy(&SG[idx], &K[ki], sizeof(DES_cblock));
            c = (c >> 1);
            idx++;
        }
    }
}

int verifyMsg(char *msg) {
    int i=0, j=0, ki=0, idx = 0;
    char c;
    DES_cblock E;
    DES_key_schedule schedule;  
    for (i=0;i<MD5_DIGEST_LENGTH;i++) {
        c = msg[i];
        for (j=0;j<8;j++) {
            ki = idx + BITS*(1 & c);
            DES_set_key(&SG[idx], &schedule);
            DES_ecb_encrypt( &S[ki], &E, &schedule, DES_ENCRYPT );
            if (memcmp( &E, &R[ki], sizeof(DES_cblock)) != 0) return -1;            
            c = (c >> 1);
            idx++;
        }
    }
    return 0;
}
