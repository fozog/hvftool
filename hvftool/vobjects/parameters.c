/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */



#include <stdio.h>
#include <mach/error.h>
#include <stdlib.h>
#include <errno.h>

#include "parameters.h"


parameter_t* parameter_lookup(parameter_t parameters[], int count, char* name)
{
    int i;
    for(i=0; i<count; i++)
    {
        if (strcmp(name, parameters[i].name)==0) return &parameters[i];
    }
    return NULL;
}

static int update_value(parameter_t* parameters, int count, char* buffer)
{
    char param_name[128];
    char param_value[128];
    sscanf(buffer, "%[^=]=%s", param_name, param_value);
    parameter_t* param = parameter_lookup(parameters, count, param_name);
    if (param==NULL) {
        printf("Could not find paramer %s.\n", param_name);
        return -EINVAL;
    }
    if (param->type == PARAM_UINT64) {
        bool is_hex = false;
        if (strlen(param_value) >= 3)
            is_hex = param_value[0]=='0' && param_value[1]=='x';
        sscanf(param_value, is_hex ? "%llx" : "%lld", &param->u64_value);
        param->is_set = true;
    }
    else if (param->type == PARAM_BOOL) {
        if (strcmp(param_value, "true") == 0) {
            param->bool_value = true;
        }
        else if (strcmp(param_value, "false") == 0) {
            param->bool_value = false;
        }
        else {
            printf("Invalid BOOL parameter: %s=%s\n", param_name, param_value);
            return -EINVAL;
        }
        param->is_set = true;
    }
    else if (param->type == PARAM_CSTRING) {
        param->ptr_value = strdup(param_value);
        param->is_set = true;
    }
    else if (param->type == PARAM_FDTSTRING) {
        
    }
    return ERR_SUCCESS;
}

// if no parameters given, just return a copy of the default factory parameters: everything may be automatically evaluated
parameter_t*  parse_parameters(char* parameters_buufer, parameter_t* template_parameters, int count)
{
    if (template_parameters == NULL) return NULL;
    parameter_t* result = malloc(count * sizeof(parameter_t));
    memcpy(result, template_parameters, count * sizeof(parameter_t));
    int n;
    char buffer[128];
    if (parameters_buufer != NULL)
    {
        char* current=parameters_buufer;
        char* end = parameters_buufer + strlen(parameters_buufer);
        do {
            n=sscanf(current, "%[^;];", buffer);
            if (n == 1) {
                update_value(result, count, buffer); // updfate the parameter value in the array
            }
            current += strlen(buffer)+1;
        } while (current < end);
    }
    return result;
}

