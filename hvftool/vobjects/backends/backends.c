/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "parameters.h"
#include "backends.h"


#define MAX_BACKENDS 16
static backend_c* backends[MAX_BACKENDS] = { 0 };
static int backend_count = 0;

backend_c* backends_lookup(const char* key) {
    int i;
    for (i = 0; i < backend_count; i++ ) {
        if (strcmp(key, backends[i]->key) == 0) return backends[i];
    }
    return NULL;
}

/*
backend_o* backends_instantiate_old(char* backend_spec)
{
    char key[32]= {0};
    char backend_info[48] = {0};
    if (backend_spec ==NULL) return NULL;
    int n = sscanf(backend_spec, "%16[^:]:%48s", key, backend_info);

    backend_c* backend_class = backends_lookup(key);
    if (backend_class == NULL) {
        printf("Unknown namespace %s.\n", key);
        return NULL;
    }
    if (backend_class->instantiate == NULL) {
        printf("Namespace %s has no instantiator!\n", key);
        return NULL;
    }
    return backend_class->instantiate(n==2 ? backend_info : NULL);
}
*/
backend_o* backends_instantiate(char* backend_spec)
{
    
    char* effective_parameters = NULL;
    char parameters_buffer[128]= {0};
    backend_c* backend_class = NULL;
    if (backend_spec == NULL) return NULL;
    parameter_t* parameters = NULL;
    // Then deal with the vobject spec:= <factory_key>#<parameters>
    {
        char key[128]= {0};
        
        // extract the factorey_key
        int p = sscanf(backend_spec, "%128[^#]#%s", key, parameters_buffer);
        if (p<1) return NULL;
        effective_parameters = p==1 ? NULL : parameters_buffer;
        
        backend_class = backends_lookup(key);
        
        if (backend_class == NULL) {
            printf("Could not find backend %s in vobjectspec %s\n", key, backend_spec);
            return NULL;
        }
        if (backend_class->instantiate == NULL ) {
            printf("Internal error: no initialize device method for vobjtype %s\n", key);
            return NULL;
        }
    }

    // deal wih backend parameters
    if (effective_parameters != NULL)
    {
        parameters = parse_parameters(parameters_buffer, backend_class->parameters, backend_class->parameter_count);
        int i;
        for (i=0; i<backend_class->parameter_count; i++)
        {
            if (parameters[i].is_mandatory && !parameters[i].is_set) {
                printf("Missing mandatory parameter %s for %s\n", parameters[i].description, parameters_buffer);
                free(parameters);
                return NULL;
            }
        }

    }
    
    return backend_class->instantiate(parameters,  backend_class->parameter_count);
    
}


int backends_register(backend_c* e)
{
    if (backend_count >= MAX_BACKENDS - 1) return -ENOMEM;
    backends[backend_count++] = e;
    return ERR_SUCCESS;
}

int pipe_backend_init(void);
int stdio_backend_init(void);
int hostmem_backend_init(void);
int hostcpu_backend_init(void);
int mappedf_backend_init(void);

int backends_init(void)
{
    pipe_backend_init();
    stdio_backend_init();
    hostmem_backend_init();
    hostcpu_backend_init();
    mappedf_backend_init();
    return ERR_SUCCESS;
}
