#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "util.h"
#include "crypto.h"

void error_with_helpmsg(char* msg) {
    fprintf(stderr, "%s\n\n", msg);
    printf("Usage:\n\n"
        "cstore list archivename\n"
        "cstore add [-p password] archivename file\n"
        "cstore extract [-p password] archivename file\n"
        "cstore delete [-p password] archivename file\n");
}

void print_file(FILE** fp) {
    fseek(*fp, 0, SEEK_END);
    long val = ftell(*fp);
    printf("\nPrinting file...\n");
    printf("file size: %ld\n", val);
    BYTE* data = malloc(sizeof(BYTE) * val);
    fseek(*fp, 0, SEEK_SET);
    fread(data, sizeof(BYTE), val, *fp);
    print_hex(data, val);
    free(data);
    printf("\n");
    fflush(stdout);
}

void print_hex(BYTE* data, int i) {
    printf("\n");
    for (int k = 0; k < i ; k++) {
        if (k % 8 == 0 && k != 0) {
            printf(" (%d) ", k);
        }
        printf("%x", data[k]);
    }
    printf("\n");
    fflush(stdout);
}