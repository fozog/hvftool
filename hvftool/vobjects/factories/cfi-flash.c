/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

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
#include "cfi-flash-internal.h"


static vmm_action_t cfi_mmio_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit, mmio_range_t* range);
static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj);
static void cfi_terminate(struct vobject* vobj);
static void fdt_generator(struct vobject* vobj, void* fdt);


static parameter_t parameters[] = {
    {
        .name = "address",
        .type = PARAM_UINT64,
        .description = "GPA of the ram being added",
        .is_mandatory = true,
        .u64_value = 0
    },
};

static vobject_factory_t cfi_factory = {
    "CFI",                                  // matching key for vobj selection
    "Common Flash Interface",               // description
    "cfi-flash",                            // default name for FDT
    ONE_FDT_STRING("cfi-flash"),                            // default FDT compatiblee
    sizeof(cfi_vobject_t),                  // size of the associated vobject
    initialize,                     // ctrate vobject
    cfi_mmio_handler,                       // MMIO handler
    NULL,                                   // SMC handler
    cfi_terminate,                          // object terminator
    fdt_generator,                           // FDT generator
        .parameters = parameters,
        .parameter_count = sizeof(parameters)/sizeof(parameter_t)
};


static vmm_action_t cfi_mmio_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit, mmio_range_t* range)
{
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    gva_t PC;
    hv_vcpu_get_reg(vcpu, HV_REG_PC, &PC);
 
    uint32_t iss = cpu_exit->exception.syndrome & 0x1FFFFFF; // 25 bits (0 to 24; bit 24 is a valid bit)
    bool is_write = (iss >> 6) & 1;
    vmm_action_t action = VMM_CONTINUE;

    cfi_vobject_t* cfivobj = (cfi_vobject_t*)range->vobj;
    TRACE(DEBUG_CFI_OPERATIONS, "cfi_mmio_handler called on %s\n", VOBJECT_CAST(cfivobj)->fdt_name);
    
    if (is_write) {
        
        action = cfi_write_handler(context, vcore, cpu_exit, range);
    
        mmio_range_t* range = VOBJECT_CAST(cfivobj)->mmio_range;
        /* Adjust our mapping status accordingly. */
        if (!cfivobj->is_mapped && cfivobj->read_mode == READ_ARRAY) {
            if (hv_vm_protect(range->start, range->end - range->start,  HV_MEMORY_READ | HV_MEMORY_EXEC) != HV_SUCCESS) {
                printf("CFI Could not re-map for READ_ARRAY MODE @%llx\n",  range->start);
                return VMM_ABORT_REQUESTED;
            }
            cfivobj->is_mapped = true;
        }
        else if (cfivobj->is_mapped && cfivobj->read_mode != READ_ARRAY) {
            if (hv_vm_protect(range->start, range->end - range->start, HV_MEMORY_EXEC) != HV_SUCCESS) {
                printf("CFI Could not re-map for READ_ARRAY MODE @%llx\n",  range->start);
                return VMM_ABORT_REQUESTED;
            }
            cfivobj->is_mapped = false;
        }

        
    }
    else {

           action = cfi_read_handler(context, vcore, cpu_exit, range);
        
    }
    
    if (action == VMM_CONTINUE)
        hv_vcpu_set_reg(vcpu, HV_REG_PC, PC+4);
    
    return action;
}

void static cfi_set_u8(uint8_t* cfi, int index, uint8_t value)
{
    cfi[index] = value;
}

void static cfi_set_u16(uint8_t* cfi, int index, uint16_t value)
{
    cfi[index] = value & 0x0FF;
    cfi[index+1] = (value >> 8) & 0x0FF;
}

void static cfi_set_u32(uint8_t* cfi, int index, uint32_t value)
{
    cfi[index] = value & 0x0FF;
    cfi[index+1] = (value >> 8) & 0x0FF;
    cfi[index+2] = (value >> 16) & 0x0FF;
    cfi[index+3] = (value >> 24) & 0x0FF;
}

static inline int log2(uint64_t x)
{
    int n;
    if (x==0) return -1;
    if (x==1) return ERR_SUCCESS;
    n = sizeof(uint64_t) * 8 - __builtin_clzl(x - 1);
    if ((1 << n) != x) return -1;
    return n;
}

static void init_cfi(uint8_t* cfi, uint64_t capacity)
{
    /* CFI query identification string */
    cfi_set_u8(cfi,  0x10, 'Q');
    cfi_set_u8(cfi,  0x11, 'R');
    cfi_set_u8(cfi,  0x12, 'Y');

    /* presence of additional tables */
    cfi_set_u16(cfi, 0x13, 1);                  /* primary command set: Intel/Sharp extended */
    cfi_set_u16(cfi, 0x15, CFI_QRY_STANDARD);   /* address of primary extended query table, see below*/
    cfi_set_u16(cfi, 0x17, 0);                  /* alternative command set: unused */
    cfi_set_u16(cfi, 0x19, 0);                  /* address of alternative extended query table*/

    /* voltage and timings */
    cfi_set_u8(cfi,  0x1b, 0x45);               /* minimum Vcc voltage: 4.5V */
    cfi_set_u8(cfi,  0x1c, 0x55);               /* maximum Vcc voltage: 5.5V */
    cfi_set_u8(cfi,  0x1d, 0x00);               /* minimum Vpp voltage: 0.0V (unused) */
    cfi_set_u8(cfi,  0x1e, 0x00);               /* maximum Vpp voltage: 0.0V *(unused) */
    cfi_set_u8(cfi,  0x1f, 0x01);               /* timeout for single word program: 2 us */
    cfi_set_u8(cfi,  0x20, 0x01);               /* timeout for multi-byte program: 2 us */
    cfi_set_u8(cfi,  0x21, 0x01);               /* timeout for block erase: 2 ms */
    cfi_set_u8(cfi,  0x22, 0x00);               /* timeout for full chip erase: not supported */
    cfi_set_u8(cfi,  0x23, 0x00);               /* max timeout for single word program: 1x */
    cfi_set_u8(cfi,  0x24, 0x00);               /* max timeout for mulit-byte program: 1x */
    cfi_set_u8(cfi,  0x25, 0x00);               /* max timeout for block erase: 1x */
    cfi_set_u8(cfi,  0x26, 0x00);               /* max timeout for chip erase: not supported */

    /* flash geometry */
    cfi_set_u8(cfi,  0x27, log2(capacity));     /* for 64 mega bytes n=26 */
    cfi_set_u16(cfi, 0x28, 0);                  /* interface width, JEP137: 0={x8} , 5=x{16 and x32} */
    cfi_set_u16(cfi, 0x2A, PROGRAM_BUFF_SIZE_BITS); /* Maximum number of bytes in multi-byte program = 2^n ; 8-> 256 bytes */
    cfi_set_u8(cfi,  0x2C, 1);                  /* Number of Erase Block Regions within device: 1 */
    uint16_t sector_size = (uint16_t)(FLASH_BLOCK_SIZE / 256) ;    /* bits 31- 16 = number of 256 bytes in a block, 64KB=256 */
    uint16_t nblocks =  (uint16_t)(capacity / FLASH_BLOCK_SIZE - 1); /* nits 15-0 = Number of Erase Blocks of identical size within the Erase Block Region minus one */
    cfi_set_u32(cfi, 0x2D, ((uint32_t)sector_size << 16) | (uint32_t)nblocks);/* Erase Block Region Information */
                                                        
    /* Intel primary algorithm extended query table */
    
    cfi_set_u8(cfi,  CFI_QRY_STANDARD + 0x00, 'P');
    cfi_set_u8(cfi,  CFI_QRY_STANDARD + 0x01, 'R');
    cfi_set_u8(cfi,  CFI_QRY_STANDARD + 0x02, 'I');

    cfi_set_u8(cfi,  CFI_QRY_STANDARD + 0x03, '1');     /* version 1.0 */
    cfi_set_u8(cfi,  CFI_QRY_STANDARD + 0x04, '0');

    cfi_set_u32(cfi, CFI_QRY_STANDARD + 0x05, 0);       /* optional features: instant lock & pm-read */
    cfi_set_u8(cfi,  CFI_QRY_STANDARD + 0x09, 0);       /* no functions after suspend */
    cfi_set_u16(cfi, CFI_QRY_STANDARD + 0x0A, 0);       /* only lock bit supported */
    cfi_set_u8(cfi,  CFI_QRY_STANDARD + 0x0C, 0x50);    /* best Vcc value: 5.0V */
    cfi_set_u8(cfi,  CFI_QRY_STANDARD + 0x0D, 0);       /* best Vpp value: 0.0V (unused) */
    cfi_set_u8(cfi,  CFI_QRY_STANDARD + 0x0E, 1);       /* number of protection register fields */
    cfi_set_u32(cfi, CFI_QRY_STANDARD + 0x0F, 0);       /* protection field 1 description */

}

static void cfi_terminate(struct vobject* vobj)
{
    cfi_vobject_t* cfivobj = (cfi_vobject_t*)vobj;
    // when we lead here, the backend is already terminated.
    hv_vm_unmap(cfivobj->start, cfivobj->end - cfivobj->start);
    cfivobj->flash_memory = NULL; // before NULLING, the pointer was pointing to a location that was not mapped anymore (backend terminated)
}

static vobject_t* initialize(struct vmm_context* context, struct vobject* vobj)
{
    if (vobj == NULL) return NULL;
    
    cfi_vobject_t* cfivobj = (cfi_vobject_t*)vobj;
    memory_backend_o* mem_backend= (memory_backend_o*)cfivobj->_.backend;

    gpa_t address;
    parameter_t* param = parameter_lookup(vobj->parameters, vobj->parameters_count, "address");
    address = param->u64_value;
    free(param);
    
    size_t capacity = mem_backend->get_capacity(mem_backend);
	capacity += 65536-1;
	capacity &= ~(65536-1);
    cfivobj->start = address;
    cfivobj->end = address + capacity;
    cfivobj->flash_memory = mem_backend->get_base(mem_backend);

    mmio_range_t* range = vobject_register_mmio(vobj, address, capacity);
    if (range == NULL) {
        vobject_free(vobj);
        return NULL;
    }
    
    memset(cfivobj->program_buffer, 0, PROGRAM_BUFF_SIZE);
    cfivobj->block_address = ~0ULL;
    cfivobj->buff_written = 0;
    
    size_t bm_size = (capacity / FLASH_BLOCK_SIZE / sizeof(uint64_t) / 8) + 8;
    cfivobj->lock_bm = malloc(bm_size);
    memset(cfivobj->lock_bm, 0, bm_size);
    
    init_cfi(cfivobj->cfi_info, capacity);
    
	int result;
    if ((result = hv_vm_map(cfivobj->flash_memory, address, capacity,  HV_MEMORY_READ | HV_MEMORY_EXEC)) != HV_SUCCESS) {
        printf("CFI Could not map CFI @%llx, err=%s\n", address, strerror(errno));
        //TODO dealloc mdio_range
        free(cfivobj);
        return NULL;
    }
    
    // VM will just read or execute in place until a write happens
    cfivobj->read_mode = READ_ARRAY;
    cfivobj->is_mapped = true;
    
    TRACE(DEBUG_RAM, "CFI: mapping GPA %llx-%llx into HVA %p\n", address, address+capacity, cfivobj->flash_memory);
    
    vmm_add_memory_range(cfivobj->start, cfivobj->end, cfivobj->flash_memory, (vobject_t*)cfivobj);
    
    return (vobject_t*)cfivobj;
}

static void fdt_generator(struct vobject* vobj, void* fdt)
{
    cfi_vobject_t* cfivobj = (cfi_vobject_t*)vobj;
    


    gpa_t address = cfivobj->start;
    uint64_t capacity = cfivobj->end - cfivobj->start;
    
    uint64_t flash_reg_prop[]    = {
        cpu_to_fdt64(address),
        cpu_to_fdt64(capacity),
    };
    
    char name_buffer[64];
    sprintf(name_buffer, "flash@%llx", address);
    
    _FDT(fdt_begin_node(fdt, name_buffer));
    // bank-width supposed to be mandatory but U-Boot does not uses it
    // it uses CONFIG_SYS_FLASH_CFI_WIDTH, which assumes 8bits for QEMU
    //CONFIG_SYS_FLASH_CFI_WIDTH_8BIT=y
    //# CONFIG_SYS_FLASH_CFI_WIDTH_16BIT is not set
    //# CONFIG_SYS_FLASH_CFI_WIDTH_32BIT is not set
    //# CONFIG_SYS_FLASH_CFI_WIDTH_64BIT is not set
    //CONFIG_SYS_FLASH_CFI_WIDTH=0x1
    
    _FDT(fdt_property_cell(fdt, "bank-width", 1));
    _FDT(fdt_property_cell(fdt, "#address-cells", 0x1));
    _FDT(fdt_property_cell(fdt, "#size-cells", 0x1));
    _FDT(fdt_property_fdtstring(fdt, "compatible", &(FACTORY_CAST(cfivobj)->compatible)));
    _FDT(fdt_property_string(fdt, "label", "System-firmware"));
    _FDT(fdt_property(fdt, "reg", &flash_reg_prop, sizeof(flash_reg_prop)));
    _FDT(fdt_end_node(fdt));
    
    cfivobj->state = CFI_STATE_READY;
    

exit_return:; // this is for _FDT
    
}


int cfi_init(void)
{
    return vobjtype_register(&cfi_factory);
}
