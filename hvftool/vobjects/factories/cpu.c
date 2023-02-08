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
#include "sysinfo.h"


// CPU vobjects will be of the following structure:
typedef struct {
    vobject_t _;
    cpu_node_t* cpu;
    char* name;
    uint64_t mpidr;
    int index;
    int irq_sec_phys;
    int irq_phys;
    int irq_virt;
    int irq_hyp_phys;
    int irq_hyp_virt;
    int intid_sec_phys;
    int intid_phys;
    int intid_virt;
    int intid_hyp_phys;
    int intid_hyp_virt;
} cpu_vobject_t;

// cpu factory with some parameters (FDT need to be generated under common /cpus and need to add topology and nodes
typedef struct cpu_vobjtype {
    vobject_factory_t parent;
    bool has_fdt_been_generated;
    int current_index;
} cpu_vobject_factory_t;


cpu_vobject_t* cpus[MAX_CPUS];

int cpu_count=0;

static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj);
static void fdt_generator(struct vobject* vobj, void* fdt);
static int post_process(struct vmm_context* context, struct vobject* vobj);

static cpu_vobject_factory_t cpu_factory = {
    {
    "CPU",                                  // matching key for vobj selection
    "CPU based on host topology",           // description
    "cpu",                                  // default name for FDT
    ONE_FDT_STRING("arm,cortex-a72"),                       // default FDT compatiblee
    sizeof(cpu_vobject_t),                  // size of the associated vobject
    initialize,                             // initialize vobject
    NULL,                                   // MMIO handler
    NULL,                                   // SMC handler
    NULL,                                   // object terminator
    fdt_generator,                          // FDT generator
    .init_postprocess = post_process,
    },
    .has_fdt_been_generated = false
};

void timer_handler(struct vmm_context* context, struct vobject* vobject, vcore_t* vcore)
{
    hv_vcpu_set_vtimer_mask(vcore->vcpu_handle, false);
}

static int post_process(struct vmm_context* context, struct vobject* vobj)
{
    if (vobj == NULL) return EXIT_FAILURE;
    
    cpu_vobject_t* cpuvobj = (cpu_vobject_t*)vobj;
    
    vmm_register_interrupt(context, vobj, IRQ_PPI, cpuvobj->irq_hyp_phys, timer_handler, &cpuvobj->intid_hyp_phys);
    return EXIT_SUCCESS;
}

static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj)
{
    if (vobj == NULL) return NULL;
    
    cpu_vobject_t* cpuvobj = (cpu_vobject_t*)vobj;
    
    cpuvobj->index = cpu_factory.current_index++; // used to create cpu0, cpu1, cpu2...

    cpuvobj->mpidr = 0; // TODO: calculate this better
    
    cpuvobj->irq_phys     = PPI_TIMER_PHYS;
    cpuvobj->irq_virt     = PPI_TIMER_VIRT;
    cpuvobj->irq_hyp_phys = PPI_HYP_PHYS;
    cpuvobj->irq_hyp_virt = PPI_HYP_VIRT;

    cpus[cpu_count++] = cpuvobj;

    return (vobject_t*)cpuvobj;
}

#define ARM_COMPATIBLE "arm,cortex-a72"
static void fdt_generator(struct vobject* vobj, void* fdt)
{
    if (vobj == NULL) return ;
    
    cpu_vobject_t* cpuvobj = (cpu_vobject_t*)vobj;
    
    // this is called for every cpu object, just do it once
    if (!cpu_factory.has_fdt_been_generated) {
        cpu_backend_o* cpu_backend= (cpu_backend_o*)vobj->backend;
        int i;
        _FDT(fdt_begin_node(fdt, "cpus"));
        //https://www.kernel.org/doc/Documentation/devicetree/bindings/arm/cpus.txt
        _FDT(fdt_property_cell(fdt, "#address-cells", 0x1)); // should be 2, can be 1 if cpu count is small
        _FDT(fdt_property_cell(fdt, "#size-cells", 0x0));

        for(i=0; i< cpu_count; i++) {
            
            char buffer[128];
            sprintf(buffer, "cpu@%d",cpus[i]->index );
            _FDT(fdt_begin_node(fdt, buffer));
            
            vobject_t* psci = vobjects_find_bytype("psci");
            _FDT(fdt_property_string(fdt, "enable-method",psci != NULL ? "psci" : "spin-table"));
            
            uint64_t mpidr = cpus[i]->mpidr;
            fdt32_t mpidr_prop[1] = {
                cpu_to_fdt32(mpidr & 0x0FFFFFF)
            };
            _FDT(fdt_property(fdt, "reg", mpidr_prop, sizeof(mpidr_prop)));
            
            fdt_string_t* backend = cpu_backend->get_compatible(cpu_backend);
            fdt_string_t* combined = fdt_combine_strings(backend, &(FACTORY_CAST(vobj)->compatible));
            _FDT(fdt_property_fdtstring(fdt, "compatible", combined));
            free(combined);
            //free(backend);
            
            _FDT(fdt_end_node(fdt));
        }
        
        // generate the template for all PPIs connected with each timer and each pmu of each core
        
        uint32_t interrupts_prop[]    = {
            cpu_to_fdt32(0x00000001), cpu_to_fdt32(cpuvobj->irq_phys),        cpu_to_fdt32(0x00000004),
            cpu_to_fdt32(0x00000001), cpu_to_fdt32(cpuvobj->irq_virt),        cpu_to_fdt32(0x00000004),
            cpu_to_fdt32(0x00000001), cpu_to_fdt32(cpuvobj->irq_hyp_phys),    cpu_to_fdt32(0x00000004),
            cpu_to_fdt32(0x00000001), cpu_to_fdt32(cpuvobj->irq_hyp_virt),    cpu_to_fdt32(0x00000004),
        };
        
        // the following describes the template for each timer associated with each core
        _FDT(fdt_end_node(fdt));
        _FDT(fdt_begin_node(fdt, "timer"));
        fdt_string_t compatible = TWO_FDT_STRING("arm,armv8-timer", "arm,armv7-timer");
        _FDT(fdt_property_fdtstring(fdt, "compatible", &compatible));
        _FDT(fdt_property(fdt, "interrupts", interrupts_prop, sizeof(interrupts_prop)));
        _FDT(fdt_property(fdt, "allways-on", NULL, 0));
        _FDT(fdt_end_node(fdt));

        cpu_factory.has_fdt_been_generated = true;
    }

exit_return:; // this is for _FDT
    
}



int cpu_init(void)
{
    return vobjtype_register((vobject_factory_t*)&cpu_factory);
}
