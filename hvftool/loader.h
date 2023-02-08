/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#ifndef loader_h
#define loader_h

#include <stdio.h>
#include "vmm.h"

typedef struct disassembly {
    struct disassembly* next;
    gva_t    address;
    char*       text;
} disassembly_t;

typedef struct symbol {
    char*       name;
    gva_t    start;
    gva_t    end;
    disassembly_t* code;
} symbol_t;

symbol_t* loader_symbol(const char* name);
gva_t loader_symbol_address(const char* name);
int loader_parse_symbols(vmm_context_t* context, const char* path);
int loader_load_rom(vmm_context_t* context, const char* path);
int loader_load_program(vmm_context_t* context, const char* program);
int loader_parse_coff_into_vm(vmm_context_t* context);
int loader_parse_macho_into_vm(vmm_context_t* context);

char* loader_disassemble_at(vcore_t* vcore, gva_t address, char** symbolic_location);

int loader_load_all(void);
int loader_add_spec(char* spec);

#endif /* loader_h */
