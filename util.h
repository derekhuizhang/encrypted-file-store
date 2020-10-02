#include <stddef.h>

#include "crypto.h"

#ifndef UTIL_H
#define UTIL_H

void error_with_helpmsg(char* msg);

void print_file(FILE** fp);

void print_hex(BYTE* data, int i);

#endif