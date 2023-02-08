/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#ifndef cfi_flash_internal_h
#define cfi_flash_internal_h

#include <Hypervisor/Hypervisor.h>

#include "vobjects.h"
#include "vmm.h"
#include "hvftool.h"


/*
 * Those states represent a subset of the CFI flash state machine.
 */
typedef enum cfi_flash_state {
    READY,
    LOCK_BLOCK_SETUP,
    WORD_PROGRAM,
    BUFFERED_PROGRAM_SETUP,
    BUFFER_WRITE,
    ERASE_BLOCK_SETUP,
} cfi_flash_state_e;

/*
 * The device can be in several **Read** modes.
 * We don't implement the asynchronous burst mode.
 */
typedef enum cfi_read_mode {
    READ_ARRAY,
    READ_STATUS_REG,
    READ_JEDEC_DEVID,
    READ_CFI_QUERY,
} cfi_read_mode_e;


// the standard CFI query region is 49 bytes, see JDEC 68.01
#define CFI_QRY_STANDARD    49
// based on other code observations
#define INTEL_QRY           19
#define CFI_QRY_HVFTOOL     (CFI_QRY_STANDARD + INTEL_QRY)

// this implementation forces the block size to 64KB, 1 chip, x8 width
#define FLASH_BLOCK_SIZE    (256*KILOBYTE)
#define CFI_NR_FLASH_CHIPS  1
#define CFI_BUS_WIDTH       1

#define PROGRAM_BUFF_SIZE_BITS            8
#define PROGRAM_BUFF_SIZE            (1U << PROGRAM_BUFF_SIZE_BITS)
#define PROGRAM_BUFF_SIZE_BITS_PER_CHIP                    \
    (PROGRAM_BUFF_SIZE_BITS + 1 - CFI_NR_FLASH_CHIPS)


typedef struct {
    vobject_t           _;
    gpa_t               start;
    gpa_t               end;
    void*               flash_memory;
    cfi_flash_state_e   state;
    bool                is_mapped;  // is_mapped is true when VM can access the memory in READ
    cfi_read_mode_e     read_mode;
    uint8_t             sr; // status register
    uint8_t             cfi_info[CFI_QRY_HVFTOOL];
    
    uint8_t              program_buffer[PROGRAM_BUFF_SIZE];
    unsigned long        *lock_bm;
    uint64_t            block_address;
    unsigned int        buff_written;
    unsigned int        buffer_length;
    
} cfi_vobject_t;


#define CFI_STATE_READY                 0

struct vmm_context;
struct vcore;
struct hv_vcpu_exit;
struct mmio_range;

vmm_action_t cfi_read_handler(struct vmm_context* context, struct vcore* vcore, hv_vcpu_exit_t* cpu_exit, struct mmio_range* range);
vmm_action_t cfi_write_handler(struct vmm_context* context, struct vcore* vcore, hv_vcpu_exit_t* cpu_exit, struct mmio_range* range);

#endif /* cfi_flash_internal_h */
