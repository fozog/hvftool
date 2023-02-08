/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#include <Hypervisor/Hypervisor.h>

#include <libfdt.h>

#include "hvftool.h"
#include "vmm.h"
#include "mmio.h"

#include "trace.h"
#include "backends.h"
#include "cfi-flash-internal.h"
#include "vcore_info.h"
#include "vcore.h"




/* CFI commands */
#define CFI_CMD_LOCK_BLOCK            0x01
#define CFI_CMD_ALTERNATE_WORD_PROGRAM        0x10
#define CFI_CMD_ERASE_BLOCK_SETUP        0x20
#define CFI_CMD_WORD_PROGRAM            0x40
#define CFI_CMD_CLEAR_STATUS_REG        0x50
#define CFI_CMD_LOCK_BLOCK_SETUP        0x60
#define CFI_CMD_READ_STATUS_REG            0x70
#define CFI_CMD_READ_JEDEC_DEVID        0x90
#define CFI_CMD_READ_CFI_QUERY            0x98
#define CFI_CMD_CONFIRM                0xd0
#define CFI_CMD_BUFFERED_PROGRAM_SETUP        0xe8
#define CFI_CMD_READ_ARRAY            0xff

#define CFI_STATUS_PROTECT_BIT        0x02
#define CFI_STATUS_PROGRAM_LOCK_BIT    0x10
#define CFI_STATUS_ERASE_CLEAR_LOCK_BIT    0x20
#define CFI_STATUS_LOCK_ERROR        CFI_STATUS_PROGRAM_LOCK_BIT |    \
                    CFI_STATUS_PROTECT_BIT
#define CFI_STATUS_ERASE_ERROR        CFI_STATUS_ERASE_CLEAR_LOCK_BIT | \
                    CFI_STATUS_PROGRAM_LOCK_BIT
#define CFI_STATUS_READY        0x80


#define DEV_ID_MASK 0x7ff


static inline void set_bit(int nr, unsigned long *addr)
{
        addr[nr / sizeof(uint64_t)] |= 1UL << (nr % sizeof(uint64_t));
}

static inline void clear_bit(int nr, unsigned long *addr)
{
        addr[nr / sizeof(uint64_t)] &= ~(1UL << (nr % sizeof(uint64_t)));
}

static inline int test_bit(unsigned int nr, const unsigned long *addr)
{
        return ((1UL << (nr % sizeof(uint64_t))) &
                (((unsigned long *)addr)[nr / sizeof(uint64_t)])) != 0;
}


static bool block_is_locked(cfi_vobject_t* cfidev, uint64_t offset)
{
    int block_nr = (int)(offset / FLASH_BLOCK_SIZE);

    return test_bit(block_nr, cfidev->lock_bm);
}


static void lock_block(cfi_vobject_t *cfidev, uint64_t faddr, bool lock)
{
    int block_nr = (int)(faddr / FLASH_BLOCK_SIZE);

    if (lock)
        set_bit(block_nr, cfidev->lock_bm);
    else
        clear_bit(block_nr, cfidev->lock_bm);
}



#define DEV_ID_MASK 0x7ff
static uint16_t read_dev_id(cfi_vobject_t* cfidev, uint64_t offset_fromflash)
{
    switch ((offset_fromflash & DEV_ID_MASK) / CFI_BUS_WIDTH) {
    case 0x0:                /* vendor ID */
        return 0x0000;
    case 0x1:                /* device ID */
        return 0xffff;
    case 0x2:
        return block_is_locked(cfidev, offset_fromflash & ~DEV_ID_MASK);
    default:            /* Ignore the other entries. */
        return ERR_SUCCESS;
    }
}


vmm_action_t cfi_read_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit, mmio_range_t* range)
{
    // MMIO context
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    uint32_t iss = cpu_exit->exception.syndrome & 0x1FFFFFF; // 25 bits (0 to 24; bit 24 is a valid bit)
    uint32_t sas = (iss >> 22) & 3;
    uint32_t len = 1 << sas;
    uint32_t srt = (iss >> 16) & 0x1f;

    // prepares operational environment
    uint16_t cfi_value = 0;
    cfi_vobject_t* cfidev = (cfi_vobject_t*)range->vobj;
    uint64_t offset_fromflash = cpu_exit->exception.physical_address - range->start;

    vmm_action_t action = VMM_CONTINUE;

    //TRACE(DEBUG_CFI_OPERATIONS, "CFI: read %d bytes into x%d to offset 0x%02llx for %s\n", len, srt, offset_fromflash, cfidev->parent_clazz.name);
    
    switch (cfidev->read_mode) {
    case READ_ARRAY:
        /* just copy the requested bytes from the array */
            action = vmm_do_mmio_read(context, vcore, cpu_exit) == 0 ? VMM_CONTINUE : VMM_ABORT_REQUESTED;
        //memcpy(data, cfidev->flash_memory + offset_fromflash, len);
        return action;
    case READ_STATUS_REG:
        cfi_value = cfidev->sr;
        break;
    case READ_JEDEC_DEVID:
        cfi_value = read_dev_id(cfidev, offset_fromflash);
        break;
    case READ_CFI_QUERY:
        cfi_value = cfidev->cfi_info[offset_fromflash];
        break;
    }
    uint64_t val = 0;;
    uint8_t* data = (uint8_t*)&val;
    switch (len) {
    case 1:
        *data = cfi_value;
        break;
    case 8:
            memset(data + 4, 0, 4);
        /* fall-through */
    case 4:
        if (CFI_NR_FLASH_CHIPS == 2)
            memcpy(data + 2, &cfi_value, 2);
        else
            memset(data + 2, 0, 2);
        /* fall-through */
    case 2:
        memcpy(data, &cfi_value, 2);
        break;
    default:
        printf("CFI flash: illegal access length %d for read mode %d", len, cfidev->read_mode);
        break;
    }
    
    hv_vcpu_set_reg(vcpu, srt, val);
    return action;
}
/* Reset the program buffer state to prepare for follow-up writes. */
static void buffer_prepare(cfi_vobject_t *cfidev)
{
    memset(cfidev->program_buffer, 0, sizeof(cfidev->program_buffer));
    cfidev->block_address = ~0ULL;
    cfidev->buff_written = 0;
}


/*
 * Any writes happening in "READY" state don't actually write to the memory,
 * but are really treated as commands to advance the state machine and select
 * the next action.
 * Change the state and modes according to the value written. The address
 * that value is written to does not matter and is ignored.
 */
static void cfi_flash_write_ready(cfi_vobject_t* cfidev , uint8_t command)
{
    switch (command) {
    case CFI_CMD_READ_JEDEC_DEVID:
        //printf("CFI: CFI_CMD_READ_JEDEC_DEVID\n");
        cfidev->read_mode = READ_JEDEC_DEVID;
        break;
    case CFI_CMD_READ_STATUS_REG:
        //printf("CFI: CFI_CMD_READ_STATUS_REG\n");
        cfidev->read_mode = READ_STATUS_REG;
        break;
    case CFI_CMD_READ_CFI_QUERY:
        //printf("CFI: CFI_CMD_READ_CFI_QUERY\n");
        cfidev->read_mode = READ_CFI_QUERY;
        break;
    case CFI_CMD_CLEAR_STATUS_REG:
        //printf("CFI: CFI_CMD_CLEAR_STATUS_REG\n");
        cfidev->sr = CFI_STATUS_READY;
        break;
    case CFI_CMD_WORD_PROGRAM:
        //printf("CFI: CFI_CMD_WORD_PROGRAM\n");
    case CFI_CMD_ALTERNATE_WORD_PROGRAM:
        //printf("CFI: CFI_CMD_WORD_PROGRAM\n");
        cfidev->state = WORD_PROGRAM;
        cfidev->read_mode = READ_STATUS_REG;
        break;
    case CFI_CMD_LOCK_BLOCK_SETUP:
        //printf("CFI: CFI_CMD_LOCK_BLOCK_SETUP\n");
        cfidev->state = LOCK_BLOCK_SETUP;
        break;
    case CFI_CMD_ERASE_BLOCK_SETUP:
        //printf("CFI: CFI_CMD_ERASE_BLOCK_SETUP\n");
        cfidev->state = ERASE_BLOCK_SETUP;
        cfidev->read_mode = READ_STATUS_REG;
        break;
    case CFI_CMD_BUFFERED_PROGRAM_SETUP:
        //printf("CFI: CFI_CMD_BUFFERED_PROGRAM_SETUP\n");
        buffer_prepare(cfidev);
        cfidev->state = BUFFERED_PROGRAM_SETUP;
        cfidev->read_mode = READ_STATUS_REG;
        break;
    case CFI_CMD_CONFIRM:
        printf("CFI flash: unexpected confirm command 0xd0\n");
        break;
    default:
        printf("CFI flash: unknown command 0x%x\n", command);
        /* fall-through */
    case CFI_CMD_READ_ARRAY:
    case 0xF0: // AMD version of READ_ARRAY
        //printf("CFI: CFI_CMD_READ_ARRAY\n");
        cfidev->read_mode = READ_ARRAY;
        break;
    }
}



static void word_program( cfi_vobject_t *cfidev,
             uint64_t faddr, void *data, int len)
{
    if (block_is_locked(cfidev, faddr)) {
        cfidev->sr |= CFI_STATUS_LOCK_ERROR;
        return;
    }

    memcpy(cfidev->flash_memory + faddr, data, len);
}


static bool buffer_write(cfi_vobject_t *cfidev,
             uint64_t faddr, void *buffer, int len)
{
    unsigned int buff_addr;

    if (cfidev->buff_written >= cfidev->buffer_length)
        return false;

    /*
     * The first word written into the buffer after the setup command
     * happens to be the base address for the buffer.
     * All subsequent writes need to be within this address and this
     * address plus the buffer size, so keep this value around.
     */
    if (cfidev->block_address == ~0ULL)
        cfidev->block_address = faddr;

    if (faddr < cfidev->block_address)
        return false;
    buff_addr = (unsigned int)(faddr - cfidev->block_address);
    if (buff_addr >= PROGRAM_BUFF_SIZE)
        return false;

    memcpy(cfidev->program_buffer + buff_addr, buffer, len);
    cfidev->buff_written += len;

    return true;
}

static void buffer_confirm(cfi_vobject_t *cfidev)
{
    if (block_is_locked(cfidev, cfidev->block_address)) {
        cfidev->sr |= CFI_STATUS_LOCK_ERROR;
        return;
    }
    memcpy(cfidev->flash_memory + cfidev->block_address,
           cfidev->program_buffer, cfidev->buff_written);
    
    if (VOBJECT_CAST(cfidev)->backend->factory->sync != NULL)
        VOBJECT_CAST(cfidev)->backend->factory->sync(VOBJECT_CAST(cfidev)->backend);
}

static void block_erase_confirm(cfi_vobject_t *cfidev, uint64_t faddr)
{
    if (block_is_locked(cfidev, faddr)) {
        cfidev->sr |= CFI_STATUS_LOCK_ERROR;
        return;
    }

    memset(cfidev->flash_memory + faddr, 0xff, FLASH_BLOCK_SIZE);
    
    if (VOBJECT_CAST(cfidev)->backend->factory->sync != NULL)
        VOBJECT_CAST(cfidev)->backend->factory->sync(VOBJECT_CAST(cfidev)->backend);
}


vmm_action_t cfi_write_handler(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit, mmio_range_t* range)
{
    // MMIO context
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    uint32_t iss = cpu_exit->exception.syndrome & 0x1FFFFFF; // 25 bits (0 to 24; bit 24 is a valid bit)
    uint32_t sas = (iss >> 22) & 3;
    uint32_t len = 1 << sas;
    uint32_t srt = (iss >> 16) & 0x1f;
    
    // prepares operational environment
    cfi_vobject_t* cfivobj = (cfi_vobject_t*)range->vobj;
    uint64_t offset_fromflash = cpu_exit->exception.physical_address - range->start;

    vmm_action_t action = VMM_CONTINUE;
        
    uint64_t val = 0;
    hv_vcpu_get_reg(vcpu, srt, &val);
    uint8_t* data = (uint8_t*)&val;
    uint8_t command = (val & 0xFF);

    TRACE(DEBUG_CFI_OPERATIONS, "CFI: write %d bytes x%d (=%llx) to offset 0x%02llx for %s\n", len, srt, val, offset_fromflash, VOBJECT_CAST(cfivobj)->fdt_name);
    
    switch (cfivobj->state) {
            
    case READY:
        cfi_flash_write_ready(cfivobj, command);
        action = VMM_CONTINUE;
        break;
    
    case LOCK_BLOCK_SETUP:
        switch (command & 0xff) {
        case CFI_CMD_LOCK_BLOCK:
            //printf("CFI: CFI_CMD_LOCK_BLOCK\n");
            lock_block(cfivobj, offset_fromflash, true);
            cfivobj->read_mode = READ_STATUS_REG;
            break;
        case CFI_CMD_CONFIRM:
            //printf("CFI: CFI_CMD_CONFIRM\n");
            lock_block(cfivobj, offset_fromflash, false);
            cfivobj->read_mode = READ_STATUS_REG;
            break;
        default:
            //printf("CFI: CFI_STATUS_ERASE_ERROR\n");
            cfivobj->sr |= CFI_STATUS_ERASE_ERROR;
            break;
        }
        cfivobj->state = READY;
        break;

    case WORD_PROGRAM:
        //printf("CFI: WORD_PROGRAM\n");
        word_program(cfivobj, offset_fromflash, data, len);
        cfivobj->read_mode = READ_STATUS_REG;
        cfivobj->state = READY;
        break;

    case BUFFER_WRITE:
        //printf("CFI: BUFFER_WRITE\n");
        if (buffer_write(cfivobj, offset_fromflash, data, len))
            break;

        if ((command & 0xff) == CFI_CMD_CONFIRM) {
            buffer_confirm(cfivobj);
            cfivobj->read_mode = READ_STATUS_REG;
        } else {
            //printf("CFI flash: BUFFER_WRITE: expected CONFIRM(0xd0), got 0x%x @ 0x%llx\n", command, offset_fromflash);
            cfivobj->sr |= CFI_STATUS_PROGRAM_LOCK_BIT;
        }
        cfivobj->state = READY;
        break;

    case BUFFERED_PROGRAM_SETUP:
        //printf("CFI: BUFFERED_PROGRAM_SETUP\n");
        cfivobj->buffer_length = (command + 1) * CFI_BUS_WIDTH;
        if (cfivobj->buffer_length > PROGRAM_BUFF_SIZE)
            cfivobj->buffer_length = PROGRAM_BUFF_SIZE;
        cfivobj->state = BUFFER_WRITE;
        cfivobj->read_mode = READ_STATUS_REG;
        break;

    case ERASE_BLOCK_SETUP:
        //printf("CFI: ERASE_BLOCK_SETUP\n");
        if ((command & 0xff) == CFI_CMD_CONFIRM)
            block_erase_confirm(cfivobj, offset_fromflash);
        else
            cfivobj->sr |= CFI_STATUS_ERASE_ERROR;

        cfivobj->state = READY;
        cfivobj->read_mode = READ_STATUS_REG;
        break;
             
    default:
        vcore_disassemble_one(context, vcore, "CFIbadCmd");
        vcore_print_general_regs(vcore, 4);
        action = vcore_interactive_debug(context, vcore, cpu_exit, VMM_ABORT_REQUESTED);
    break;
    }
    
    return action;
}
