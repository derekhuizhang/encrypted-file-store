#include <stddef.h>

#include "crypto.h"

#ifndef STORE_H
#define STORE_H

void list_files(char* archivename);

void add_files(char* password, char* archivename, char** filenames);

void extract_files(char* password, char* archivename, char** filenames);

void delete_files(char* password, char* archivename, char** filenames);

int check_file_integrity(FILE** archive, BYTE* key);

void update_hash_and_count(FILE** archive, BYTE* key);

void try_delete_file(FILE** archive_ptr, char* filename);

char** get_file_names(FILE** archive_ptr);

void set_new_hash(FILE** archive_ptr, BYTE* key);

int files_in_archive(FILE** archive_ptr, char** filenames);

#endif