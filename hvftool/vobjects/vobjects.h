/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#ifndef vobjects_h
#define vobjects_h

#include <stdio.h>

#include "hvftool.h"
#include "mmio.h"
#include "smc.h"

struct mmio_range;
struct smc_range;
struct backend;
struct vobject_factory;
struct vobject;
struct vmm_context;

#define MAX_DEVICES 256

#include "parameters.h"

typedef void (*event_callback_f)(struct vobject* vobject);

typedef struct vobject {
    struct vobject_factory* factory;            // who created this vobject
    struct vmm_context*     context;
    char*                   fdt_name;           // as used in DT, usually derived from default name from factory but can be overriden
    char*                   name;               // to be used as references in vobject specs (vhandle related)
    uint32_t                phandle;
    struct mmio_range*      mmio_range;
    struct smc_range*       smc_range;          // some devices rely on SMC calls to be initialized, the framework allows such devices to emulate those calls.
    struct backend*         backend;
    event_callback_f        notify;             // called by backend to notify something
    parameter_t*            parameters;         //
    int                     parameters_count;
    int                     vobj_idx;           // the factory will create many object instances, this idx is used to identiy a single one.
                                                // It is also used in FDT to assign default names
} vobject_t;

void vobject_free(vobject_t*  vobj);
int vobject_terminate(vobject_t* vobj);
vobject_t* vobject_create(struct vmm_context* context, const char* vobj_spec);
int vobject_postprocessing(struct vmm_context* context,  vobject_t* vobj);

// ----------
// this is a factory type: creates vobject_t and provide common behaviors to all objects
typedef struct vobject* (*vobject_initializer_f)(struct vmm_context* context, struct vobject* vobject);
// the following function will be call on each object after all vobjects have been created
// needed for instance to allow an object to leveraged other objects passed as reference in the specificaiton: register itself to GIC root for instance
typedef int (*vobject_init_post_processing_f)(struct vmm_context* context, struct vobject* vobject);
typedef void (*vobject_terminator_f)(struct vobject* vobj);
typedef void (*vobject_fdt_generator_f)(struct vobject* vobj, void* fdt);

typedef struct vobject_factory {
    const char*             key;
    const char*             description;        // describes the vobject this factory creates. may be useless introspection but it feels good
    const char*             fdt_default_name;       // default name template for the created objects
    fdt_string_t            compatible;         // default string for fdt
    size_t                  size;               // size of the containing structure, need to set it when you register a type.
    vobject_initializer_f   initialize;
    mmio_handler_f          mmio_handler;
    smc_handler_f           smc_handler;
    vobject_terminator_f    terminate;
    vobject_fdt_generator_f generate_fdt;
    parameter_t*            parameters;
    int                     parameter_count;
    int                     vobj_count;         // number of objects created, used to populate vobject->vobj_idx
    vobject_init_post_processing_f   init_postprocess;
} vobject_factory_t;


// the pattern is that each deried vobject_t has a member called "_" and that is the first element of this object
#define VOBJECT_CAST(x)  ((vobject_t*)(x))
#define FACTORY_CAST(x)  (VOBJECT_CAST(x)->factory)




void vobject_set_backend(vobject_t* vobj, struct backend* backend);
mmio_range_t* vobject_register_mmio(vobject_t* vjobect, gpa_t address, size_t mmio_size);
void vobject_free(vobject_t* vjobect);
vobject_t* vobject_alloc(struct vobject_factory* vobjtype); // allocate an object without adding it to known devices (can fail later than allocation)


vobject_t* vobjects_find_byname(char* name);
vobject_t* vobjects_find_bytype(char* type);
int vobjects_populate_fdt(void* fdt);
int vobjects_add_spec(const char* vobject_spec);
int vobjects_postprocess_all(vmm_context_t* context);
int vobjects_create_all(struct vmm_context* context);
int vobjects_terminate_all(void);


vobject_factory_t* vobjtype_lookup(const char* emulator_key);
int vobjtype_register(vobject_factory_t* e);
int vobjtypes_init(void);



#endif /* vobjects_h */
