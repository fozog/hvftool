/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#ifndef vmm_h
#define vmm_h

#include <sys/signal.h>
#include <Hypervisor/Hypervisor.h>
#include <mach/mach_types.h>
#include <semaphore.h>

#include "hvftool.h"
#include "hvf_internals.h"

#include "vcore_emulate.h"

struct vobject;

// VBAR_EL1 of the guest will be set at one of the two values
// this will allow identification of the expected behavior:
//Emulate all the exception levels of a processor
// the addresses have to be selected so that they are not in the
// guest address space
#define EMULATION_VBAR_ADDRESS      0xf0000000ULL
// Normal behavior of Exception level 1 only guests
#define UNTRAPPED_VBAR_ADDRESS      0xf1000000ULL

// Return from traps, place it at 3GB for the moment to allow simple TFA MMU handling
//#define INJECTION_VBAR_ADDRESS      0xC0000000ULL
#define INJECTION_VBAR_ADDRESS      (1024*1024ULL)

#define IS_IN_EMULATION_TABLE(x)    (((x) >= EMULATION_VBAR_ADDRESS) && ((x) < EMULATION_VBAR_ADDRESS + 16 * 128))
// when VBAR_EL1 is not set (not trying to emulate)
#define IS_IN_UNTRAPPED_TABLE(x)    (((x) >= UNTRAPPED_VBAR_ADDRESS) && ((x) < UNTRAPPED_VBAR_ADDRESS + 16 * 128))
#define IS_IN_INJECTION_TABLE(x)    (((x) >= INJECTION_VBAR_ADDRESS) && ((x) < INJECTION_VBAR_ADDRESS + 16 * 128))



#define MAX_CPUS            1

#define IRQ_SGI_BASE        0
#define IRQ_PPI_BASE        16
#define IRQ_SPI_BASE        32

#define PPI_TIMER_PHYS      0xd
#define PPI_TIMER_VIRT      0xe
#define PPI_HYP_PHYS        0xb
#define PPI_HYP_VIRT        0xa

#define SGI_TO_INTID(x)     (IRQ_SGI_BASE+(x))
#define PPI_TO_INTID(x)     (IRQ_PPI_BASE+(x))
#define SPI_TO_INTID(x)     (IRQ_SPI_BASE+(x))

/* ---------------------------------------- */

#define  SIG_IPI    SIGUSR1


/* ---------------------------------------- */

typedef struct {
  mach_msg_header_t header;
  // no body is needed

  // Suitable for use with the default trailer type - no custom trailer
  // information requested using `MACH_RCV_TRAILER_TYPE`, or just the explicit
  // `MACH_RCV_TRAILER_NULL` type.
  mach_msg_trailer_t trailer;
} WFIMessage;


typedef struct vcore {
    hv_vcpu_config_t    config;
    hv_vcpu_t           vcpu_handle;
    uint32_t            midr;
    int                 index;
    hv_vcpu_exit_t*     cpu_exit;
    arm_guest_context_t* hvf_guest_context;
    bool                is_secure_state;
    gva_t               skip_until; // assistance to pass load/store exclusives when doint singlestep
    gva_t               irq_enter; // when debugging irq handling, need to stop injecting pending interrupts as it is disbaling singlestep
    gva_t               emulation_breakpoint_for_post_done;
    bool                is_single_stepping;
    uint64_t            stepped_instructions;
    uint64_t            exclusive_sections;
    uint64_t            skipped_instructions; // because of exclusive sections
    uint64_t            vm_exits;
    uint64_t            vm_emulation;
    uint64_t            vm_exits_mmio;
    uint64_t            vbar_el1;
    bool                pending_irq;
    sigset_t            wfi_mask;
    pthread_cond_t      wfi_cond;
    pthread_mutex_t     wfi_mutex;
    struct              vmm_context* context;
    uint64_t            cntfrq_hz;
    uint64_t            vtimer_offset;
	uint64_t		    cpsr;	// current emulation CPSR
    emulation_action_t  finish_action;
    gva_t               finish_emulation_at;
} vcore_t;

typedef struct vmm_context {
    void*       memory_pointer;
    gpa_t       program_load_address;
    size_t      memory_size;
    gva_t       memory_top;
    uint32_t    page_size;
    gpa_t       text_begining;
    gva_t       entry;
    vcore_t*    vcore[MAX_CPUS];
    int         vcore_count;
    struct vobject*  interrupt_parent; // GIC object to be used as interrupt controller
	uint32_t* exception_table;
    struct {
        const char* path;
        void* buffer;
        size_t size;
        struct load_command* commands;
        struct segment_command_64* text_segment;
        void* __linkedit_segment_content;
        gpa_t rebase_gpa;
        void* rebase_base;
        int rebase_count;
    } executable; // structures to handle the mch-o executable being loaded in guest memory
} vmm_context_t;


/* ---------------------------------------- */
// Address space organization & memory map

#define PHYSICAL_ADDRESS_SPACE (1ULL << 36)


typedef struct memory_map {
    gpa_t   rom_start;
    gpa_t   rom_end;
    
    gpa_t   mmio_start;
    gpa_t   mmio_top;       // first allocation will be made here
    gpa_t   mmio_end;
    
    gpa_t   ram_start;
    gpa_t   ram_bottom;     // Allocate stuff like FDT in the case of QEMU memory map
    gpa_t   ram_top_free;   // in the first RAM slot, the top of the RAM is used to place things such as FDT, EXECUTABLE for MACHO memory map
    gpa_t   ram_top;        // top of first RAM slot
    gpa_t   ram_end;        // end of address space, between ram_top and ram_end there is nothing
    
    gpa_t   sec_ram_start;
    gpa_t   sec_ram_bottom;     // Allocate stuff like FDT in the case of QEMU memory map
    gpa_t   sec_ram_top_free;   // in the first RAM slot, the top of the RAM is used to place things such as FDT, EXECUTABLE for MACHO memory map
    gpa_t   sec_ram_top;        // top of first RAM slot
    gpa_t   sec_ram_end;        // end of address space, between ram_top and ram_end there is nothing
	
    gpa_t   fdt_start;      // QEMU uses a fixed memory zone to pass information to the booted payload
    gpa_t   fdt_top;        // end of fdt data = start + fdt_totalsize(fdt_start)
    gpa_t   fdt_end;        // end of reserved space for FDT (page aligned, effectively <PAGESIZE> for the moment)
    
    gpa_t   reset_address;  // the first instruction to execute when entering a VM. Address 0 is a valid address. used for ROM emulation
} memory_map_t;


/* ---------------------------------------- */
/* PSCI stuff */


#define PSCI_0_2_FN_BASE 0x84000000
#define PSCI_0_2_FN(n) (PSCI_0_2_FN_BASE + (n))

#define PSCI_0_2_64BIT 0x40000000
#define PSCI_0_2_FN64_BASE \
        (PSCI_0_2_FN_BASE + PSCI_0_2_64BIT)
#define PSCI_0_2_FN64(n) (PSCI_0_2_FN64_BASE + (n))

#define PSCI_0_2_FN_PSCI_VERSION        PSCI_0_2_FN(0)
#define PSCI_0_2_FN_CPU_SUSPEND         PSCI_0_2_FN(1)
#define PSCI_0_2_FN_CPU_OFF             PSCI_0_2_FN(2)
#define PSCI_0_2_FN_CPU_ON              PSCI_0_2_FN(3)
#define PSCI_0_2_FN_AFFINITY_INFO       PSCI_0_2_FN(4)
#define PSCI_0_2_FN_MIGRATE             PSCI_0_2_FN(5)
#define PSCI_0_2_FN_MIGRATE_INFO_TYPE   PSCI_0_2_FN(6)
#define PSCI_0_2_FN_MIGRATE_INFO_UP_CPU PSCI_0_2_FN(7)
#define PSCI_0_2_FN_SYSTEM_OFF          PSCI_0_2_FN(8)
#define PSCI_0_2_FN_SYSTEM_RESET        PSCI_0_2_FN(9)
#define PSCI_1_0_FN_SYSTEM_RESET2       PSCI_0_2_FN(10)

typedef  enum {
    VMM_CONTINUE,
    VMM_EXIT_REQUESTED,
    VMM_ABORT_REQUESTED
} vmm_action_t;


struct vcore; // defined in vcore.h
struct vobject;

typedef enum irq_type {
    IRQ_SGI,
    IRQ_PPI,
    IRQ_SPI,
    IRQ_LPI
} irq_type_e;

typedef void (*irq_eoi_handler_f)(struct vmm_context* context, struct vobject* vobject, struct vcore* vcore);

int vmm_do_mmio_read(vmm_context_t* context, vcore_t* vcore, hv_vcpu_exit_t* cpu_exit);

int vmm_set_memory_map(const char* name);

void vmm_dump_paging_level(struct vmm_context* context, gpa_t table_pa, uint64_t base,  int level, int tsz);

gpa_t vmm_gva_to_gpa(vcore_t* vcore, gva_t gva);
hva_t vmm_gva_to_hva(vcore_t* vcore, gva_t gva);
hva_t vmm_gpa_to_hva(vmm_context_t* context, gpa_t gpa);



void* vmm_get_hostpointer_for(gpa_t address);
int vmm_add_memory_range(gpa_t address, gpa_t end, void* memory, struct vobject* dev);

void* vmm_inject_fdt(vmm_context_t* context, void* fdt);

vcore_t* vmm_lookup_vcore_byaffinity(vmm_context_t* context, uint32_t affinity);
int vmm_vcore_create(vmm_context_t* context, struct vcore** vcore);
int vmm_run(vmm_context_t* context);
int vmm_smc_handler(vmm_context_t* context, struct vcore* vcore, hv_vcpu_exit_t* cpu_exit);
int vmm_mmio_handler(vmm_context_t* context, struct vcore* vcore, hv_vcpu_exit_t* cpu_exit);

int vmm_inject_irq_for(vmm_context_t* context, struct vobject* vobj);
int vmm_register_interrupt_controller(vmm_context_t* context, struct vobject* vobj);
int vmm_register_interrupt(vmm_context_t* context, struct vobject* vobj, irq_type_e type, uint64_t info, irq_eoi_handler_f eoi_handler, int* intid);

int vmm_create(vmm_context_t* context);

#endif /* vmm_h */
