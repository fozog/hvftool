/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#ifndef hvftool_h
#define hvftool_h

#define KILOBYTE (1ULL*1024)
#define MEGABYTE (1024*KILOBYTE)
#define GIGABYTE (1024*MEGABYTE)

#include <Hypervisor/Hypervisor.h>

//TODO get this better
// FDT helper. need to define exit_return in all functions using it
#define _FDT(exp)                                                                       \
    do {                                                                                \
        int ret = (exp);                                                                \
        if (ret < 0) {                                                                  \
            printf("Error creating device tree: %s: %s\n", #exp, fdt_strerror(ret));    \
            goto exit_return;                                                           \
        }                                                                               \
} while (0)


typedef hv_ipa_t gpa_t; // guest physical address, can cover non RAM as MMIO
typedef uint64_t gva_t; // guest virtual address, difficult to translate if paging is in function
typedef uint64_t hva_t; // host virtual address in the hvftool memory space (i.e. can cast to void* in this program);

typedef enum {
    NONZERO     = 0x80,
    SHORT       = 0x00,
    LONG        = 0x01,
    DETAILED    = 0x02,
    FULL        = 0x03
} detail_t;

typedef enum {
    SINGLE_NONE,
    SINGLE_BATCH,
    SINGLE_INTERACTIVE,
    SINGLE_INTERACTIVE_TO_BATCH, // just a way to avoid double print of the first instruction when we transition
    SINGLE_SILENT                // look for a particular instruction
} single_step_mode_t;

#define INVALID_PC       ((uint64_t)-1) // there are no circumstances where a non aligned address, VA or PA that can be this address
#define INVALID_ADDRESS  ((uint64_t)-1) // this data address cannot be a PA; if VA that can be only an EL1 address with tagging (bits 52-63) all 1s so not plausible too
#define POISON_ADDRESS   ((uint64_t)-8) // this data address cannot be a PA; if VA that can be only an EL1 address with tagging (bits 52-63) all 1s so not plausible too

struct memory_map;

typedef struct {
    struct memory_map* memory_map;

    gpa_t effective_reset_address;
    size_t mem_size;            // calculated from aggregagting RAM devices: RAM can have holes

    const char* extra_symbols;  // an executable (probably ELF) file used to debug; set this to the ROM program you use and embedded in a CFI-FLASH device.
    const char* program_path;

    void* fdt;                  // points to a place in mapped guest memory where the FDT is placed
    const char* fdt_path;
    char* fdt_spec[16];
    int fdtspec_count;
    
    /* debug related stuff*/
    gva_t self_move;            // programms may self move themselves to a new location (U-Boot in Qemu for instance)
    gva_t breakpoint;           // convention: if breakpoint address is 1 then it will be replaced by entry point, 2 look for the symbol
    char* breakpoint_symbol;
    gva_t watchpoint;
    single_step_mode_t ss_mode;
    uint64_t trace_bitmap;
    bool dump_reset_sysregs;
    detail_t reset_sysregs_detail;
    bool enable_simulation;     // enable SoC simulation with EL3, secure world and processor feature emulation
} hvftool_config_t;

extern hvftool_config_t hvftool_config;

#endif /* hvftool_h */
