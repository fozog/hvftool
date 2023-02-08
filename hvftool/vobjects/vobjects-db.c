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
#include "vmm.h"


static vobject_t* vobjects[MAX_DEVICES] = {0};
static int vobject_count=0;

static const char* vobject_specs[MAX_DEVICES];
static int vobject_spec_count;


/* ------------------------------------- */
// externall callable functions




int vobjects_populate_fdt(void* fdt)
{
    int i;
    for (i = 0; i < vobject_count; i++) {
        if (vobjects[i]->factory != NULL && vobjects[i]->factory->generate_fdt != NULL)
            vobjects[i]->factory->generate_fdt(vobjects[i], fdt);
    }
    return ERR_SUCCESS;
}

vobject_t* vobjects_find_byname(char* name)
{
    int i;
    for (i = 0; i < vobject_count; i++) {
        if (vobjects[i]->name == NULL) continue;
        if (strcasecmp(vobjects[i]->name, name)==0)
            return vobjects[i];
    }
    return NULL;
}

vobject_t* vobjects_find_bytype(char* type)
{
    int i;
    for (i = 0; i < vobject_count; i++) {
        if (strcasecmp(vobjects[i]->factory->key, type)==0)
            return vobjects[i];
    }
    return NULL;
}

int vobjects_add_spec(const char* spec)
{
    if (vobject_spec_count >= MAX_DEVICES -1) return -ENODEV;
    vobject_specs[vobject_spec_count++] = spec;
    return ERR_SUCCESS;
}

int vobjects_terminate_all(void)
{
    int i;
    for (i = 0; i < vobject_count; i++) {
        vobject_terminate(vobjects[i]);
    }
    return ERR_SUCCESS;
}

static int32_t current_phandle = 0x8000;
static int create_vobject_for_spec(vmm_context_t* context, const char* vobj_spec)
{
    vobject_t* vobj = vobject_create(context, vobj_spec);
    
    if (vobj != NULL) {
        vobj->phandle = current_phandle++;
        vobjects[vobject_count++] = vobj;
    }
    return ERR_SUCCESS;
}

int vobjects_create_all(vmm_context_t* context)
{
    int i;
    for (i = 0; i < vobject_spec_count; i++) {
        create_vobject_for_spec(context, vobject_specs[i]);
    }
    return ERR_SUCCESS;
}

int vobjects_postprocess_all(vmm_context_t* context)
{
    int i;
    for (i = 0; i < vobject_spec_count; i++) {
        vobject_postprocessing(context, vobjects[i]);
    }
    return ERR_SUCCESS;
}
