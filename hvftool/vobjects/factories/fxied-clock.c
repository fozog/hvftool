/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#include <stdio.h>
#include <stdlib.h>

#include <Hypervisor/Hypervisor.h>

#include <libfdt.h>

#include "hvftool.h"
#include "backends.h"
#include "vmm.h"
#include "trace.h"
#include "vcore_info.h"
#include "vcore.h"
#include "vobjects.h"
#include "backends.h"
#include "loader.h"



typedef struct {
    vobject_t _;
    uint32_t frequency;
    fdt_string_t output_names;
} fixed_clock_vobject_t;


static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj);
static void fdt_generator(struct vobject* vobj, void* fdt);

static parameter_t parameters[] = {
    {
        .name = "name",
        .type = PARAM_CSTRING,
        .description = "name of the object for reference",
        .is_mandatory = false,
    },
    {
        .name = "clock-frequency",
        .type = PARAM_UINT64,
        .description = "base frequency",
        .is_mandatory = false,
        .u64_value=24000000
    },
};

static vobject_factory_t fixed_clock_factory = {
    .key = "fixed-clock",                          // matching key for vobj selection
    .description = "Fixed clock generator",                // description
    .fdt_default_name = "clock",                                // default name for FDT
    .compatible = ONE_FDT_STRING("fixed-clock"),          // default FDT compatiblee
    .size = sizeof(fixed_clock_vobject_t),          // size of the associated vobject
    .initialize = initialize,             // ctrate vobject
    .mmio_handler = NULL,                                   // MMIO handler
    .smc_handler = NULL,                                   // SMC handler
    .terminate = NULL,                                   // object terminator
    .generate_fdt = fdt_generator,                          // FDT generator
    .parameters =       parameters,
    .parameter_count =  sizeof(parameters) / sizeof(parameter_t),
};



// -vobj fixed-clock,"apb_clk"=clock-frequency:0x16e3600,clock-output-names:clk24mhz
//TODO need to handle \\0 (note the double \ to allow string lists in FDT
static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj)
{
    if (vobj == NULL) return NULL;
    
    fixed_clock_vobject_t* fclockvobj = (fixed_clock_vobject_t*)vobj;
 
    parameter_t* param ;
    
    param = parameter_lookup(vobj->parameters, vobj->parameters_count, "clock-frequency");
    fclockvobj->frequency = (uint32_t)param->u64_value;
    
    return (vobject_t*)fclockvobj;
}

static void fdt_generator(struct vobject* vobj, void* fdt)
{
    fixed_clock_vobject_t* fclockvobj = (fixed_clock_vobject_t*)vobj;

    _FDT(fdt_begin_node(fdt, FACTORY_CAST(fclockvobj)->fdt_default_name));
    
    _FDT(fdt_property_fdtstring(fdt, "compatible", &(FACTORY_CAST(fclockvobj)->compatible)));
    _FDT(fdt_property_u32(fdt, "#clock-cells", 0));
    _FDT(fdt_property_u32(fdt, "clock-frequency",fclockvobj->frequency));
    //TODO when we have proper list of values separated with \\0, we'll have to modify the following code
    _FDT(fdt_property_fdtstring(fdt, "clock-output_names", &fclockvobj->output_names));
    _FDT(fdt_property_u32(fdt, "phandle", vobj->phandle));
    _FDT(fdt_end_node(fdt));

exit_return:; // this is for _FDT macro
    
}



int fixed_clock_init(void)
{
    return vobjtype_register(&fixed_clock_factory);
}
