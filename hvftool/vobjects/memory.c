/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#include <stdio.h>
#include <stdlib.h>

#include <Hypervisor/Hypervisor.h>

#include "backends.h"
#include "vmm.h"
#include "trace.h"
#include "vcore_info.h"
#include "vcore.h"
#include "emulators.h"
#include "devices.h"
#include "backends.h"
#include "loader.h"

//TODO find the right size

typedef struct {
    device_t parent_clazz;
    void* base;
} memory_device_t;


static int mem_mmio_handler(vmm_context_t* context, vcore_t* vcore, arm_hv_vcpu_exit_t* arm_cpu_exit, mmio_range_t* range);
static device_t* mem_create_device(const char* device_name, gpa_t address, backend_o* backend);

static emulator_t eumulator = { "Memory", "Abstract memory (can be RAM, ROM, NOR, NAND...", mem_mmio_handler, mem_create_device};


static int mem_mmio_handler(vmm_context_t* context, vcore_t* vcore, arm_hv_vcpu_exit_t* arm_cpu_exit, mmio_range_t* range)
{
    uint32_t iss = arm_cpu_exit->exception.syndrome & 0x1FFFFFF; // 25 bits (0 to 24; bit 24 is a valid bit)
    bool is_write = (iss >> 6) & 1;
    //uint32_t sas = (iss >> 22) & 3;
    //uint32_t len = 1 << sas;
    //int dfsc = iss & 0x3F;
    //bool s1ptw = (iss >> 7) & 1;
    uint32_t srt = (iss >> 16) & 0x1f;
    //uint32_t cm = (iss >> 8) & 0x1;
    uint64_t val = 0;
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    gva_t pc;
    hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
    
    // just ignore any control register for now
    uint64_t offset = arm_cpu_exit->exception.physical_address - range->start;

    //block_backend_o* block = (block_backend_o*)range->device->backend;
    //cfi_device_t* cfidev = (cfi_device_t*)range->device;
    
    switch(offset) {
        default:
            if (is_write) {
                if (srt!=31)  hv_vcpu_get_reg(vcpu, srt, &val); // in the case 31, this is wzr!
                vcore_disassemble_one(context, vcore, "MEM");
                printf("CFI: ignore write x%d (=%llx) to %llx\n", srt, val, arm_cpu_exit->exception.physical_address - range->start);
            }
            else {
                vcore_disassemble_one(context, vcore, "MEM");
                printf("CFI: ignore read access from %llx to register x%d\n", arm_cpu_exit->exception.physical_address - range->start, srt);
            }
    }

mmio_continue:
    hv_vcpu_set_reg(vcpu, HV_REG_PC, pc+4);
    
    return VMM_CONTINUE;
}



static device_t* mem_create_device(const char* device_name, gpa_t address, backend_o* backend)
{
    device_t* dev = malloc(sizeof(memory_device_t));
    if (dev == NULL) return NULL;
    dev->name = device_name;
    block_backend_o* flash = (block_backend_o*)backend;
    size_t capacity = flash->get_capacity(flash);
    // record the whiole space as MMIO
    dev->mmio_range = mmio_assign_at(address, capacity);
    if (dev->mmio_range == NULL) {
        free(dev);
        return NULL;
    }
    dev->mmio_range->handler = mem_mmio_handler;
    dev->backend = backend;
    dev->mmio_range->device = dev;
    
    cfi_device_t* cfidev = (memory_device_t*)dev;
    
    cfidev->memory = flash->get_base_memory(flash);
    // while the whole flash space is in MMIO, just make sure that only a limited part triggers an MMIO exit
    // the MMIO registers of a CFI flash are mapped at the begining
    if (hv_vm_map(cfidev->memory + CFI_MMIO_RESERVED, address + CFI_MMIO_RESERVED, capacity - CFI_MMIO_RESERVED, HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC) != HV_SUCCESS) {
        printf("Could not map CFI flash\n");
        free(dev);
        return NULL;
    }
    
/*
    void* fdt = hvftool_config.fdt;
 
    uint64_t mmio_reg_prop[]    = {
        cpu_to_fdt64(address),
        cpu_to_fdt64(0x1000),
    };
    uint64_t clock_reg_prop[]    = {
        cpu_to_fdt64(0x8000),
        cpu_to_fdt64(0x8000),
    };
    char node_name[32];
    sprintf(node_name, "pl011@%llx", address); // this is to avoid dtc complaining "node has a reg or ranges property, but no unit name"
    _FDT(fdt_begin_node(fdt, node_name));
    _FDT(fdt_property_string(fdt, "compatible", "arm,pl011\0arm,primecell"));
    _FDT(fdt_property_string(fdt, "clock-names", "uartclk\0apb_pclk"));
    _FDT(fdt_property(fdt, "clocks", clock_reg_prop, sizeof(clock_reg_prop)));
    _FDT(fdt_property(fdt, "reg", mmio_reg_prop, sizeof(mmio_reg_prop)));
    _FDT(fdt_end_node(fdt));
*/
    
exit_return:
    return dev;
}


int mem_init(void)
{
    return emulators_register(&eumulator);
}
