/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "vobjects.h"
#include "backends.h"
#include "trace.h"
#include "fdt.h"

/*
-vobj PL011,"console",0x09000000=pipe:/tmp/hvftool
-vobj PL011,"console",0x09000000=socket:tcp:1234
-vobj PL011,"console"=pipe:/tmp/hvftool // default address in the object type
*/


mmio_range_t* vobject_register_mmio(vobject_t* vjobect, gpa_t address, size_t mmio_size)
{
    vjobect->mmio_range = mmio_assign_at(address, mmio_size);
    if (vjobect->mmio_range == NULL) {
        return NULL;
    }
    vjobect->mmio_range->handler = FACTORY_CAST(vjobect)->mmio_handler ;
    vjobect->mmio_range->vobj = vjobect;

    return vjobect->mmio_range;
}

void vobject_set_backend(vobject_t* vobj, backend_o* backend)
{
    vobj->backend = backend;
    if (backend != NULL) backend->vobj = vobj;
}

void vobject_free(vobject_t*  vobj)
{
    //TODO more cleaning needed... probably leaks here
    free(vobj->fdt_name);
    free(vobj);
}

vobject_t* vobject_alloc(vobject_factory_t* factory)
{
    if (factory == NULL) return NULL;
    if (factory->size == 0) return NULL;
    vobject_t* vobj = malloc(factory->size);
    if (vobj == NULL) return NULL;
    memset(vobj, 0, factory->size);
    vobj->factory = factory;
    // do this before handling names
    vobj->vobj_idx = factory->vobj_count++;
    /*
    if (vobj_name != NULL) {
        vobj->fdt_name = strdup(vobj_name);
    }
    else {
        char buffer[128];
        sprintf(buffer, "%s%i", factory->fdt_default_name, vobj->vobj_idx);
        vobj->fdt_name = strdup(buffer);
        
    }*/
    return vobj;
}

int vobject_terminate(vobject_t* vobj)
{
    TRACE(DEBUG_DEVICE, "Terminating device: %s\n", vobj->fdt_name);
    if (vobj->backend != NULL) {
        if (vobj->backend->factory->terminate != NULL)
            vobj->backend->factory->terminate(vobj->backend);
        vobj->backend = NULL; // just make sure we don't terminate twice...
    }
    if (vobj->factory->terminate != NULL)
        vobj->factory->terminate(vobj);
    
    return ERR_SUCCESS;
}


vobject_t* vobject_instantiate(char* factory_spec_buffer)
{
    
    vobject_factory_t* factory = NULL;
    vobject_t* vobj = NULL;
    char* vobj_parameters = NULL;
    char vobj_parameters_buufer[128]= {0};
    parameter_t* parameters ;
    // Then deal with the vobject spec:= <factory_key>#<parameters>
    {
        char factory_key[128]= {0};
        
        // extract the factorey_key
        int p = sscanf(factory_spec_buffer, "%128[^#]#%s", factory_key, vobj_parameters_buufer);
        if (p<1) return NULL;
        vobj_parameters = p==1 ? NULL : vobj_parameters_buufer;
        factory = vobjtype_lookup(factory_key);
        
        if (factory == NULL) {
            printf("Could not find vobjtype %s in vobjectspec %s\n", factory_key, factory_spec_buffer);
            return NULL;
        }
        if (factory->initialize == NULL ) {
            printf("Internal error: no initialize method for vobjtype %s\n", factory_key);
            return NULL;
        }
        vobj = vobject_alloc(factory);
        if (vobj == NULL) {
            printf("Could not create vobject for %s\n", factory_spec_buffer);
            return NULL;
        }
    }

    // deal wih vobject parameters
    if (factory->parameters != NULL)
    {
        parameters = parse_parameters(vobj_parameters, factory->parameters, factory->parameter_count);
        int i;
        for (i=0; i<factory->parameter_count; i++)
        {
            if (parameters[i].is_mandatory && !parameters[i].is_set) {
                printf("Missing mandatory parameter %s for %s\n", parameters[i].description, factory_spec_buffer);
                free(parameters);
                return NULL;
            }
        }
        
        vobj->parameters = parameters;
        vobj->parameters_count = factory->parameter_count;

        
        parameter_t* param;
        param = parameter_lookup(vobj->parameters, vobj->parameters_count, "name");
        if (param != NULL && param->is_set) {
            vobj->name = param->cstring_value;
        }
        else vobj->name = NULL;

    }
    
    return vobj;
    
}


int vobject_postprocessing(vmm_context_t* context,  vobject_t* vobj)
{
    vobject_init_post_processing_f post_process = FACTORY_CAST(vobj)->init_postprocess;
    if (post_process != NULL) return post_process(context, vobj);
    return EXIT_SUCCESS;
}

/*
 vobjspec := [<ref><:>]<factory>><parameters>[<||><backend><#><parameters>]
 parameter := <name><=><value>
 parameters := <parameter>[<;><parameters>
 */

vobject_t* vobject_create(vmm_context_t* context, const char* vobj_spec)
{
    TRACE(DEBUG_DEVICE, "creating device for: %s\n", vobj_spec);
    char reference[128] = {0};
    size_t ref_len =0;
    char factory_spec_buffer[128]= {0};
    char instantiation_spec_buffer[128]= {0};
    char* instantiation_spec = &instantiation_spec_buffer[0];

    // first, deal with overall expression:= [<ref>:]<objec_spec>||<instantiation_spec>
    {
        char* start = (char*)vobj_spec;
        int n = sscanf(vobj_spec, "%128[^:#|][:#|]", reference);
        if (n<1) return NULL;
        if (n==1) {
            // may be a reference
            ref_len = strlen(reference);
            if (vobj_spec[ref_len] == ':') {
                //this is effectively a reference
                start = (char*)&vobj_spec[ref_len+1];
            }
        }
        n = sscanf(start, "%128[^|]||%128s", factory_spec_buffer, instantiation_spec_buffer);
        if (n < 1) {
            printf("Ignoring invalid vobj specification: %s\n", vobj_spec);
            return NULL;
        }
        else if (n==1) {
            instantiation_spec = NULL;
        }
    }
    
    // create an object with parsed parameters
    vobject_t* vobj = vobject_instantiate(factory_spec_buffer);
    vobj->context = context;
    
    if (vobj != NULL)
    // deal with the possible backend
    {
        backend_o* backend = backends_instantiate(instantiation_spec);
        if (instantiation_spec!= NULL && backend == NULL) {
            vobject_free(vobj);
            return NULL;
        }
        
        vobject_set_backend(vobj, backend);

        // finaly, initiatile the vobject as parameters and backend parameters are now parsed and attached
        FACTORY_CAST(vobj)->initialize(context, vobj);
    }
    

    return vobj;

}

