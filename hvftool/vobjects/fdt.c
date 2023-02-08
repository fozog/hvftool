/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#include "fdt.h"

fdt_string_t* fdt_wrap(uint8_t* data, int len)
{
    fdt_string_t* result = malloc(sizeof(fdt_string_t));
    if (result == NULL) return NULL;
    result->data = malloc(len); // may be too big but so what
    memcpy(result->data, data, len);
    result->len = len;
    return result;
}

fdt_string_t* fdt_make_string(char* cstring)
{
    // the input string will have FDT_SEPARATOR in lieu of '\0'
    fdt_string_t* result = malloc(sizeof(fdt_string_t));
    if (result == NULL) return NULL;
    size_t ilen = strlen(cstring)+1;
    result->data = malloc(ilen); // may be too big but so what
    result->len = 0;
    int i;
    for(i=0; i< ilen; i++) {
        char c = (result->data[result->len++] = cstring[i]);
        if (c == '\\' && i < ilen-1 && cstring[i+1] == '0') {
            result->data[result->len] = '\0';
            i++; // pass the 0
        }
    }
    return result;
}

fdt_string_t* fdt_combine_strings(fdt_string_t* s1, fdt_string_t* s2)
{
    // the input string will have FDT_SEPARATOR in lieu of '\0'
    fdt_string_t* result = malloc(sizeof(fdt_string_t));
    size_t len = s1->len + s2->len ;
    result->data = malloc(len); // may be too big but so what
    result->len = len;
    memcpy(&result->data[0], s1->data, s1->len);
    memcpy(&result->data[s1->len], s2->data, s2->len);
    return result;
}

