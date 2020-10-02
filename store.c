#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

#include "store.h"
#include "crypto.h"
#include "algo-lib/sha256.h"
#include "util.h"

void list_files(char* archivename) {
    FILE* archive = fopen(archivename, "rb");
    if (archive == NULL) {
        fprintf(stderr, "invalid archive name\n");
        exit(1); 
    }
    
    char** stored_files = get_file_names(&archive);
    char** current = stored_files;
    while (*current != NULL) { 
        fprintf(stdout, "%s\n", *current);
        free(*current);
        current++;
    }
    free(stored_files);
    fclose(archive);
}

void add_files(char* password, char* archivename, char** filenames) {
    char** name_ptr = filenames;
    while (*name_ptr != NULL) {
        // ensure that the name does not overflow
        if (strlen(basename(*name_ptr)) >= 100) {
            fprintf(stderr, "file %s exceeds the acceptable file name length of 99\n", basename(*name_ptr));
            exit(1);
        }

        // ensure that file exists
        if (access(*name_ptr, R_OK ) == -1 ) {
            fprintf(stderr, "file %s does not exist or cannot be opened\n", basename(*name_ptr));
            exit(1);
        }
        name_ptr++;
    }
    
    FILE* archive = fopen(archivename, "r+b");
    BYTE* key = get_aes_key(password);

    if (archive == NULL) {
        archive = fopen(archivename, "w+b");
        setbuf(archive, NULL);
        BYTE init[SHA256_BLOCK_SIZE];
        memset(init, (BYTE) 0, SHA256_BLOCK_SIZE);
        fwrite(init, sizeof(BYTE), SHA256_BLOCK_SIZE, archive);
    } else {
        // integrity check
        if (check_file_integrity(&archive, key) == 0) {
            fprintf(stderr, "invalid password or archive\n");
            free(key);
            fclose(archive);
            exit(1);
        }
    }

    name_ptr = filenames;
    while (*name_ptr != NULL) {
        // delete file if a matching name already exists
        try_delete_file(&archive, basename(*name_ptr));
        encrypt_cbc(&archive, *name_ptr, key);
        name_ptr++;
    }

    set_new_hash(&archive, key);
    free(key);
    fclose(archive);
}

void extract_files(char* password, char* archivename, char** filenames) {
    FILE* archive = fopen(archivename, "rb");
    if (archive == NULL) {
        fprintf(stderr, "invalid archive name\n");
        exit(1);
    }

    BYTE* key = get_aes_key(password);

    // integrity check
    if (check_file_integrity(&archive, key) == 0) {
        fprintf(stderr, "invalid password or archive\n");
        fclose(archive);
        exit(1);
    }

    if (!files_in_archive(&archive, filenames)) {
        fclose(archive);
        exit(1);
    }

    char** name_ptr = filenames;    
    while (*name_ptr != NULL) {
        decrypt_cbc(&archive, *name_ptr, key);
        name_ptr++;
    }

    free(key);
    fclose(archive);
}

void delete_files(char* password, char* archivename, char** filenames) {
    FILE* archive = fopen(archivename, "r+b");
    if (archive == NULL) {
        fprintf(stderr, "invalid archive name\n");
        exit(1);
    }

    BYTE* key = get_aes_key(password);

    // integrity check
    if (check_file_integrity(&archive, key) == 0) {
        fprintf(stderr, "invalid password or archive\n");
        fclose(archive);
        exit(1);
    }

    if (!files_in_archive(&archive, filenames)) {
        fclose(archive);
        exit(1);
    }

    char** name_ptr = filenames;
    while (*name_ptr != NULL) {
        try_delete_file(&archive, *name_ptr);
        name_ptr++;
    }

    set_new_hash(&archive, key);

    free(key);
    fclose(archive);
}

int check_file_integrity(FILE** archive_ptr, BYTE* key) {
    // integrity check
    BYTE actual_hash[SHA256_BLOCK_SIZE];

    fseek(*archive_ptr, 0, SEEK_SET);
    if (fread(actual_hash, 1, SHA256_BLOCK_SIZE, *archive_ptr) != SHA256_BLOCK_SIZE) {
        return 0;
    }
    fseek(*archive_ptr, 0, SEEK_END);
    long archive_size = ftell(*archive_ptr);
    long files_size = archive_size - SHA256_BLOCK_SIZE;
    fseek(*archive_ptr, SHA256_BLOCK_SIZE, SEEK_SET);
    
    BYTE* all_data = (BYTE*) malloc(sizeof(BYTE) * files_size);
    fread(all_data, sizeof(BYTE), files_size, *archive_ptr);
    
    BYTE* expected_hash = get_hmac_hash(key, all_data, files_size);
    if (memcmp(expected_hash, actual_hash, SHA256_BLOCK_SIZE) != 0) {
        free(expected_hash);
        free(all_data);
        return 0;
    }
    free(expected_hash);
    free(all_data);
    return 1;
}

void set_new_hash(FILE** archive_ptr, BYTE* key) {
    // create and set new hash
    fseek(*archive_ptr, 0, SEEK_END);
    long files_size = ftell(*archive_ptr) - SHA256_BLOCK_SIZE;
    fseek(*archive_ptr, SHA256_BLOCK_SIZE, SEEK_SET);

    BYTE* new_data = (BYTE*) malloc(sizeof(BYTE) * files_size);
    fread(new_data, 1, files_size, *archive_ptr);
    
    BYTE* new_hash = get_hmac_hash(key, new_data, files_size);
    fseek(*archive_ptr, 0, SEEK_SET);
    fwrite(new_hash, sizeof(BYTE), SHA256_BLOCK_SIZE, *archive_ptr);
    free(new_hash);
    free(new_data);
}

void try_delete_file(FILE** archive_ptr, char* filename) {
    fseek(*archive_ptr, 0, SEEK_END);
    long archive_size = ftell(*archive_ptr);
    struct Metadata metadata;
    BYTE* rest_data;
    long before_pos = SHA256_BLOCK_SIZE;
    long after_pos;

    fseek(*archive_ptr, SHA256_BLOCK_SIZE, SEEK_SET);
    while (fread(&metadata, sizeof(struct Metadata), 1, *archive_ptr)) {
        if (strcmp(metadata.name, filename) == 0) {
            fseek(*archive_ptr, metadata.size, SEEK_CUR);
            after_pos = ftell(*archive_ptr);
            rest_data = (BYTE*) malloc(sizeof(BYTE) * (archive_size - after_pos));
            fread(rest_data, sizeof(BYTE), archive_size - after_pos, *archive_ptr);
            ftruncate(fileno(*archive_ptr), before_pos);
            fseek(*archive_ptr, 0, SEEK_END);
            fwrite(rest_data, sizeof(BYTE), (archive_size - after_pos), *archive_ptr);
            free(rest_data);
            break;
        };
        fseek(*archive_ptr, metadata.size, SEEK_CUR);
        before_pos = ftell(*archive_ptr);
    }
}

char** get_file_names(FILE** archive_ptr) {
    fseek(*archive_ptr, SHA256_BLOCK_SIZE, SEEK_SET);

    struct Metadata metadata;
    char** filenames = (char**) malloc(sizeof(char*) * 2000); // limit to # of files
    char** current = filenames;
    while (fread(&metadata, sizeof(struct Metadata), 1, *archive_ptr)) {
        *current = (char*) malloc(sizeof(char) * (strlen(metadata.name) + 1));
        memcpy(*current, metadata.name, strlen(metadata.name) + 1);
        fseek(*archive_ptr, metadata.size, SEEK_CUR);
        current++;
    }
    *current = NULL;
    return filenames;
}

int files_in_archive(FILE** archive_ptr, char** filenames) {
    char** stored_files = get_file_names(archive_ptr); 
    char** name_ptr = stored_files;
    char** filenames_ptr = filenames;

    int match;
    while (*filenames_ptr != NULL) {
        match = 0;
        while (*name_ptr != NULL) {
            if (strcmp(*name_ptr, *filenames_ptr) == 0) {
                match = 1;
                break;
            }
            name_ptr++;
        }
        if (!match) {
            fprintf(stderr, "file %s could not be found in archive", *filenames_ptr);
            break;
        }
        filenames_ptr++;
    }

    name_ptr = stored_files;
    while(*name_ptr != NULL) {
        free(*name_ptr);
        name_ptr++;
    }
    free(stored_files);

    return match;
}