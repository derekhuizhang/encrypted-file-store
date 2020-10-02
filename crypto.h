#include "algo-lib/sha256.h"
#ifndef CRYPTO_H
#define CRYPTO_H

struct Metadata {
    char name[100];
    unsigned long size;
    int padding;
    BYTE iv[16];
};

BYTE* get_aes_key(char* password);

BYTE* get_hmac_hash(BYTE* aes_key, BYTE* data, long data_length);

void encrypt_cbc(FILE** archive_ptr, char* filename, BYTE* key);

void decrypt_cbc(FILE** archive_ptr, char* filename, BYTE* key);

void hash_sha(BYTE* destination, BYTE* src, long src_length, long n_times);

BYTE* get_iv();

#endif
