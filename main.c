#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "util.h"
#include "store.h"

int main(int argc, char **argv) {    
    if (argc < 3) {
        error_with_helpmsg("Too few arguments");
        return 1;
    }

    if (strcmp(argv[1], "list") == 0) {
        if (argc != 3) {
            error_with_helpmsg("Too many arguments");
            return 1;
        }
        list_files(argv[2]);

    } else if (strcmp(argv[1], "add") == 0) {
        if (argc >= 6 && (strcmp(argv[2], "-p") == 0)) {
            add_files(argv[3], argv[4], &argv[5]);
            return 0;
        }

        if (argc < 4)  {
            error_with_helpmsg("Too few arguments");
            return 1;
        }
        char* password = getpass("Password:");
        add_files(password, argv[2], &argv[3]);

    } else if (strcmp(argv[1], "extract") == 0) {
        if (argc >= 6 && (strcmp(argv[2], "-p") == 0)) {
            extract_files(argv[3], argv[4], &argv[5]);
            return 0;
        }

        if (argc < 4)  {
            error_with_helpmsg("Too few arguments");
            return 1;
        }
        char* password = getpass("Password:");
        extract_files(password, argv[2], &argv[3]);

    } else if (strcmp(argv[1], "delete") == 0) {
        if (argc >= 6 && (strcmp(argv[2], "-p") == 0)) {
            delete_files(argv[3], argv[4], &argv[5]);
            return 0;
        }

        if (argc < 4)  {
            error_with_helpmsg("Too few arguments");
            return 1;
        }
        char* password = getpass("Password:");
        delete_files(password, argv[2], &argv[3]);

    } else {
        error_with_helpmsg("Unidentified command");
        return 1;
    }
    return 0;
}