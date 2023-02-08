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

#include "parameters.h"
#include "hvftool.h"
#include "backends.h"
#include "vmm.h"
#include "trace.h"
#include "vcore_info.h"
#include "vcore.h"
#include "vobjects.h"
#include "backends.h"
#include "loader.h"



typedef struct ram_vobject {
    vobject_t _;
    gpa_t start;
    gpa_t end;
    void* memory;
    bool is_secure;
    struct ram_vobject* next;
} ram_vobject_t;

static ram_vobject_t* ram_list = NULL;
static int ram_list_count = 0;


static vobject_t* initialize(struct vmm_context* context, vobject_t* vobj);
static void fdt_generator(struct vobject* vobj, void* fdt);

static parameter_t parameters[] = {
    {
        .name = "address",
        .type = PARAM_UINT64,
        .description = "GPA of the ram being added",
        .is_mandatory = true,
        .u64_value = 0
    },
    {
        .name = "secure",
        .type = PARAM_BOOL,
        .description = "Is in secure memory?",
        .is_mandatory = false,
        .bool_value = false
    },
};

static vobject_factory_t ram_factory = {
    .key= "RAM",                                  // matching key for vobj selection
    .description = "RAM (backends: hostmem, map...)",      // description
    .fdt_default_name = "ram",                                  // default name for FDT
    .compatible = ONE_FDT_STRING("memory"),               // default FDT compatiblee
    .size = sizeof(ram_vobject_t),                  // size of the associated vobject
    .initialize= initialize,                     // ctrate vobject
    .mmio_handler = NULL,                                   // MMIO handler
    .smc_handler = NULL,                                   // SMC handler
    .terminate =  NULL,                                   // object terminator
    .generate_fdt = fdt_generator ,                          // FDT generator
    .parameters = parameters,
    .parameter_count = sizeof(parameters)/sizeof(parameter_t)
};

static vobject_t* initialize(struct vmm_context* context, vobject_t* vobj)
{
    if (vobj == NULL) return NULL;
    
    ram_vobject_t* ramvobj = (ram_vobject_t*)vobj;
    memory_backend_o* mem_backend= (memory_backend_o*)ramvobj->_.backend;
    
    bool is_secure;
    gpa_t address;
    parameter_t* param = NULL;
    
    param = parameter_lookup(vobj->parameters, vobj->parameters_count, "address");
    address = param->u64_value;
    
    param = parameter_lookup(vobj->parameters, vobj->parameters_count, "secure");
    is_secure = param != NULL ? param->bool_value : false;
    
    //free(param);
    
    size_t capacity = mem_backend->get_capacity(mem_backend);
    ramvobj->start = address;
    ramvobj->is_secure = is_secure;
    ramvobj->end = address + capacity;
    ramvobj->memory = mem_backend->get_base(mem_backend);
    // while the whole flash space is in MMIO, just make sure that only a limited part triggers an MMIO exit
    // the MMIO registers of a CFI flash are mapped at the begining
    if (hv_vm_map(ramvobj->memory, address, capacity , HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC) != HV_SUCCESS) {
        printf("Could not map RAM @%llx\n", address);
        return NULL;
    }
    TRACE(DEBUG_RAM, "RAM: mapping GPA %llx-%llx into HVA %p\n", address, address+capacity, ramvobj->memory);
    gpa_t top = hvftool_config.memory_map->ram_start + capacity;
    if (top > hvftool_config.memory_map->ram_top) {
        hvftool_config.memory_map->ram_top = top;
        hvftool_config.memory_map->ram_top_free = hvftool_config.memory_map->ram_top;
        TRACE(DEBUG_RAM, "RAM: adjusting top and top_free to %llx\n", hvftool_config.memory_map->ram_top);
    }
    
    vmm_add_memory_range(ramvobj->start, ramvobj->end, ramvobj->memory, (vobject_t*)ramvobj);
    
    hvftool_config.mem_size += capacity;
    TRACE(DEBUG_RAM, "RAM: hvftool_config.mem_size is now %lx (%lldMB)\n", hvftool_config.mem_size, hvftool_config.mem_size/MEGABYTE);

    //Add front
    ramvobj->next = ram_list;
    ram_list = ramvobj;
    ram_list_count++;
    
    return (vobject_t*)ramvobj;
}

static void fdt_generator(struct vobject* vobj, void* fdt)
{
    ram_vobject_t* ramvobj = (ram_vobject_t*)vobj;

    gpa_t address = ramvobj->start;
    uint64_t capacity = ramvobj->end - ramvobj->start;
    
    fdt64_t mem_reg_prop[]    = {
        cpu_to_fdt64(address),
        cpu_to_fdt64(capacity),
    };
    char node_name[32];
    sprintf(node_name, "memory@%llx", address); // this is to avoid dtc complaining "node has a reg or ranges property, but no unit name"
    _FDT(fdt_begin_node(fdt, node_name));
    _FDT(fdt_property_string(fdt, "device_type", "memory"));
    _FDT(fdt_property(fdt, "reg", mem_reg_prop, sizeof(mem_reg_prop)));
    _FDT(fdt_end_node(fdt));
    
exit_return:; // this is for _FDT
    
}



int ram_init(void)
{
    return vobjtype_register(&ram_factory);
}
