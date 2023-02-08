/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#ifndef fdt_h
#define fdt_h

#include "libfdt.h"

//an FDT string such as compatible can contain \0 separating multiple elemebts
// so traditional C routines will fail handling them
// create an ad-hoc type to deal with this properly
typedef struct fdt_string {
    char* data;
    size_t   len;
} fdt_string_t;

#define FDT_SEPERATOR "\\0" // code to insert a '\0' in a string to allow handling of those FDT strings
#define ONE_FDT_STRING(x)   { (char*)(x), sizeof(x)}
// a little uggly but need to get this working at compile time
// sizeof static string is strlen + 1 accounting for the trailing \0
// so the length of the combined string is effectively the sum of the two sizeofs
// when concatenating the two strings, it removes the ending \0 of x so we add it again,
// but no need to account for this addition
#define TWO_FDT_STRING(x,y)   { (char*)(x "\0" y), sizeof(x) + sizeof(y)}


#define fdt_property_fdtstring(fdt, name, fdtstring) fdt_property(fdt, name, (fdtstring)->data, (int)(fdtstring)->len)

#define _FDT(exp)                                                                       \
    do {                                                                                \
        int ret = (exp);                                                                \
        if (ret < 0) {                                                                  \
            printf("Error creating device tree: %s: %s\n", #exp, fdt_strerror(ret));    \
            goto exit_return;                                                           \
        }                                                                               \
} while (0)

#endif /* fdt_h */


fdt_string_t* fdt_wrap(uint8_t* data, int len);
fdt_string_t* fdt_make_string(char* cstring);
fdt_string_t* fdt_combine_strings(fdt_string_t* s1, fdt_string_t* s2);
