/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#ifndef parameters_h
#define parameters_h

#include "fdt.h"


typedef enum {
    PARAM_UINT64,
    PARAM_CSTRING,
    PARAM_FDTSTRING,
    PARAM_BOOL
} param_type_t;

typedef struct parameters {
    char*               name;
    param_type_t        type;
    union {
        uint64_t        u64_value;
        bool            bool_value;
        void*           ptr_value;
        char*           cstring_value;
    };
    bool                is_mandatory;
    bool                is_set;                 // to detect it was assigned a value. Can be set at compile time to fix a parameter without automatic evaluation
    char*               description;
} parameter_t;

parameter_t* parameter_lookup(parameter_t* parameters, int count, char* name);
parameter_t*  parse_parameters(char* parameters_buufer, parameter_t* parameters, int count);

#endif /* parameters_h */
