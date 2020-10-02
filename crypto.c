#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>

#include "crypto.h"
#include "util.h"
#include "algo-lib/sha256.h"
#include "algo-lib/aes.h"

BYTE* get_aes_key(char* password) {
    SHA256_CTX ctx;
    BYTE* buf = (BYTE*) malloc(sizeof(BYTE) * SHA256_BLOCK_SIZE);
    hash_sha(buf, password, strlen(password), 10000);
    return buf;
}

BYTE* get_hmac_hash(BYTE* aes_key, BYTE* data, long data_length) {
    // get expanded key
    char* padding = "padding";
    int expanded_key_length = SHA256_BLOCK_SIZE + strlen(padding) + 1; // add 1 bc the padding is 0-terminated

    BYTE expanded_key[expanded_key_length];
    memcpy(expanded_key, aes_key, SHA256_BLOCK_SIZE);
    memcpy(expanded_key + SHA256_BLOCK_SIZE, padding, strlen(padding) + 1);

    SHA256_CTX ctx;
    BYTE hmac_key[SHA256_BLOCK_SIZE];
    hash_sha(hmac_key, expanded_key, expanded_key_length, 1);
    
    // get inner and outer paddings
    BYTE ipad[SHA256_BLOCK_SIZE];
    BYTE opad[SHA256_BLOCK_SIZE];
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        if (i % 2 == 0) {
            ipad[i] = hmac_key[i] ^ 0x3;
            opad[i] = hmac_key[i] ^ 0x5;
            continue;
        }
        ipad[i] = hmac_key[i] ^ 0x6;
        opad[i] = hmac_key[i] ^ 0xc;
    }

    BYTE padded_data[sizeof(BYTE) * (SHA256_BLOCK_SIZE + data_length)];
    memcpy(padded_data, ipad, SHA256_BLOCK_SIZE);
    memcpy(padded_data + SHA256_BLOCK_SIZE, data, data_length);
    
    BYTE intermediate_key[SHA256_BLOCK_SIZE];
    hash_sha(intermediate_key, padded_data, SHA256_BLOCK_SIZE + data_length, 1);

    BYTE intermediate_result[2 * SHA256_BLOCK_SIZE];
    memcpy(intermediate_result, opad, SHA256_BLOCK_SIZE);
    memcpy(intermediate_result + SHA256_BLOCK_SIZE, intermediate_key, SHA256_BLOCK_SIZE);

    BYTE* result = (BYTE*) malloc(sizeof(BYTE) * SHA256_BLOCK_SIZE);
    hash_sha(result, intermediate_result, 2 * SHA256_BLOCK_SIZE, 1);
    
    return result;
}

void encrypt_cbc(FILE** archive_ptr, char* filename, BYTE* key){    
    FILE* fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "could not open file %s\n", filename);
        exit(1);
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
        
    int leftover = file_size % 16;
    BYTE* iv = get_iv();

    struct Metadata metadata;
    memset(&metadata, 0, sizeof(struct Metadata));

    strcpy(metadata.name, basename(filename));
    metadata.size = file_size + (16 - leftover);
    metadata.padding = 16 - leftover;
    memcpy(metadata.iv, iv, 16);

    fseek(*archive_ptr, 0, SEEK_END);
    fwrite(&metadata, sizeof(struct Metadata), 1, *archive_ptr);

    // cbc encryption
    WORD key_schedule[60];
    aes_key_setup(key, key_schedule, 256);

    BYTE plaintext[16];
    BYTE cipher[16];
    BYTE temp[16];

    memcpy(cipher, iv, 16);
    while (fread(plaintext, sizeof(BYTE), 16, fp) == 16) {
        // xor with previous cipher
        for (int i = 0; i < 16; i++) {
            temp[i] = cipher[i] ^ plaintext[i];
        }
        aes_encrypt(temp, cipher, key_schedule, 256);
        fwrite(cipher, sizeof(BYTE), 16, *archive_ptr);
    }

    // pad the leftover bytes
    BYTE padded[16];
    memset(padded, 0, 16);
    fseek(fp, -1 * leftover, SEEK_END);
    fread(padded, 1, leftover, fp);
    
    for (int i = 0; i < 16; i++) {
        temp[i] = cipher[i] ^ padded[i];
    }
    aes_encrypt(temp, cipher, key_schedule, 256);
    fwrite(cipher, sizeof(BYTE), 16, *archive_ptr);
    free(iv);
    fclose(fp);
}

void decrypt_cbc(FILE** archive_ptr, char* filename, BYTE* key) {
    struct Metadata metadata;
    int found_file = 0;
    
    fseek(*archive_ptr, SHA256_BLOCK_SIZE, SEEK_SET);
    while (fread(&metadata, sizeof(struct Metadata), 1, *archive_ptr)) {
        if (strcmp(metadata.name, filename) == 0) {
            found_file = 1;
            break;
        }
        fseek(*archive_ptr, metadata.size, SEEK_CUR);
    }
    if (!found_file) {
        fprintf(stderr, "could not find file %s\n", filename);
        exit(1);
    }
    long blocks = metadata.size / 16;
    int padding = metadata.padding;
    
    // cbc decryption
    WORD key_schedule[60];
    aes_key_setup(key, key_schedule, 256);


    BYTE cipher[16];
    BYTE plaintext[16];
    BYTE temp[16];
    BYTE prev[16];
    memcpy(prev, metadata.iv, 16); 

    char new_filename[110];
    snprintf(new_filename, 110, "%s.extracted", metadata.name);
    FILE* fp = fopen(new_filename, "w+b");

    for (int i = 0; i < blocks; i++) {
        fread(cipher, sizeof(BYTE), 16, *archive_ptr);
        aes_decrypt(cipher, temp, key_schedule, 256);
        
        for (int j = 0; j < 16; j++) {
            plaintext[j] = prev[j] ^ temp[j];
        }
        memcpy(prev, cipher, 16);
        if (i == blocks - 1) {
            fwrite(plaintext, sizeof(BYTE), 16 - metadata.padding, fp);
            break;
        }
        fwrite(plaintext, sizeof(BYTE), 16, fp);
    }
    fclose(fp);
}

BYTE* get_iv() {
    BYTE* data = (BYTE*) malloc(sizeof(BYTE) * 16);
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    if (fp == NULL) {
        fprintf(stderr, "error getting random values");
        exit(1);
    }
    fread(data, 1, 16, fp);
    fclose(fp);
    return data;
}

void hash_sha(BYTE* destination, BYTE* src, long src_length, long n_times) {
    SHA256_CTX ctx;
	sha256_init(&ctx);
    for (int i = 0; i < n_times; i++) {
	    sha256_update(&ctx, src, src_length);
    }
    sha256_final(&ctx, destination);
}