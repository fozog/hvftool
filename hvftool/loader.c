/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#include "loader.h"
#include "trace.h"

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <string.h>

#include <mach-o/loader.h>
#include <mach-o/fixup-chains.h>
#include <sys/sysctl.h>

#include "parameters.h"
#include "vcore.h"

// U-Boot has 2700 symbols, minimal linux 16400
static symbol_t symbol_table[32768];
static int symbol_count = 0;
static bool was_symbol_loaded_via_map = false;

static gva_t symbol_gpa_to_gva_offset = 0;
static bool relocate_symbols_to_load_address = false;

#define MAX_SPECS 8
char* load_specs[MAX_SPECS] = {0};
int load_spec_count = 0;


static int load_binary_at(vmm_context_t* context, char* path, gpa_t address)
{
    int binary_file = open(path, O_RDONLY);
    struct stat file_stat;
    
    if (fstat(binary_file, &file_stat) < 0) {
        printf("Error: cannot stat %s\n", path);
        return -EIO;
    };
 
    void* target = (void*)vmm_gpa_to_hva(context, address);
    
    if (read(binary_file, target, file_stat.st_size) < 0) {
        printf("Could not read %s: %s\n", path, strerror(errno));
        close(binary_file);
        return -EIO;
    }

    TRACE(DEBUG_PREPARE_PROGRAM,"Exceutable loaded @%p\n", path);
    
    close(binary_file);
    
    return ERR_SUCCESS;
}



static int load_executable(vmm_context_t* context, const char* program)
{
    int executable_file = open(program, O_RDONLY);
    struct stat execcutable_stat;
    
    if (fstat(executable_file, &execcutable_stat) < 0) {
        printf("Error: cannot stat %s\n", program);
        return -EIO;
    };
    
    if (execcutable_stat.st_size < context->page_size) {
        printf("Invalid executable size: should be at least PAGESIZE=%d\n", context->page_size);
        return -EINVAL;
    }

    // now lets place it in memory
    void* executable_buffer;
    context->program_load_address = hvftool_config.memory_map->ram_start;
    executable_buffer = (void*)vmm_gpa_to_hva(context, context->program_load_address);
    context->memory_pointer = executable_buffer;
    context->executable.path = program;
    context->executable.buffer = executable_buffer;
    context->executable.size = execcutable_stat.st_size;
    
    if (read(executable_file, executable_buffer, execcutable_stat.st_size) < 0) {
        printf("Could not read %s\n", program);
        close(executable_file);
        return -EIO;
    }

    TRACE(DEBUG_PREPARE_PROGRAM,"Exceutable loaded @%p\n", executable_buffer);
    
    close(executable_file);
    
    return ERR_SUCCESS;
}

int loader_load_program(vmm_context_t* context, const char* path)
{
    return load_executable(context, path);
}

symbol_t* loader_symbol_by_address(uint64_t address)
{
	int i=0;
	for( /* cached start */ ; i < symbol_count; i++) {
		if ((address >= symbol_table[i].start && address < symbol_table[i].end)) {
			return &symbol_table[i];
		}
	}
	return NULL;
}

int loader_parse_map(vmm_context_t* context, const char* path)
{
	char buf[1024];
	FILE *map_reader = fopen(path, "r");
	symbol_t* current_symbol=NULL;
	symbol_t* last_symbol=NULL;
	bool has_last = false;
	while (fgets(buf, sizeof(buf), map_reader) != NULL) {
		uint64_t address;
		char symbol[128];
		if (sscanf(buf, "%llx %[^\n]",&address, symbol) == 2) {
			if (relocate_symbols_to_load_address) address += hvftool_config.effective_reset_address;
			if (has_last) {
				last_symbol->end = address -1;
			}
			current_symbol = &symbol_table[symbol_count];
			current_symbol->name = strdup(symbol);
			current_symbol->start = address;
			current_symbol->code = NULL;
			symbol_count++;
			last_symbol = current_symbol;
			//printf("Found symbol [%s] = %llx\n", symbol, address);
		}
		else {
			printf("Error parsing map line %s\n", buf);
		}
		has_last = true;
	}
	if (has_last) {
		last_symbol->end = last_symbol->start + 128; /*TODO: this is just FAKE!! */
	}
	was_symbol_loaded_via_map = true;
	return 0;
}

#define PRINTABLE(x) ( (x >=32 && x <= 127) ? x : '?')


int loader_parse_symbols(vmm_context_t* context, const char* path)
{
    char OBJDUMP_COMMAND[1024];
    // strange behavior workarround: there is a too many symbolic link problem if I just use objdump, so I use the full path
    snprintf(OBJDUMP_COMMAND, sizeof(OBJDUMP_COMMAND), "\"/Applications/Xcode 14.1.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/llvm-objdump\" -d '%s'", path);
    FILE *disassembler = popen(OBJDUMP_COMMAND, "r");
    char buf[1024];
    bool is_in_symbol = false;
    symbol_t* current_symbol = &symbol_table[symbol_count];
    gva_t last_address = 0;
    int i=0;
    // the following bulds the symbol table and records disassembly; starts at the first symbol,
    // any prior data will be just ignored
    while (fgets(buf, sizeof(buf), disassembler) != NULL) {
        gva_t address;
        int ignore0, ignore1, ignore2, ignore3;
        char content[128];
         if (sscanf(buf, "%llx <%[^>]>:",&address, content) == 2) {
        //printf("Found symbol [%s] = %llx\n", symbol, address);
		if (!was_symbol_loaded_via_map) {
			if (relocate_symbols_to_load_address) address += hvftool_config.effective_reset_address;
			if (is_in_symbol) {
				current_symbol->end = last_address + 4;
				symbol_count++;
				current_symbol = &symbol_table[symbol_count];
			}
			current_symbol->name = strdup(content);
			current_symbol->start = address;
			is_in_symbol = true;
		}
        }
        else if (sscanf(buf, "%llx: %x %x %x %x %[^\n]",&address, &ignore0, &ignore1, &ignore2, &ignore3, content) == 6) {
            //printf("%llx: %s\n", address, content);
            if (is_in_symbol || was_symbol_loaded_via_map) {
                disassembly_t* code = malloc(sizeof(disassembly_t));
                if (relocate_symbols_to_load_address) address += hvftool_config.effective_reset_address;
                if (was_symbol_loaded_via_map) {
                    current_symbol = loader_symbol_by_address(address);
                }
                if (current_symbol != NULL) {
                    code->address = address;
                    code->text = strdup(content); // removes address and newline
                    for(i=0; i<strlen(code->text); i++)
                        if (code->text[i] == '\t') code->text[i]=' ';
                    code->next = NULL;
                    if (current_symbol->code == NULL) {
                        current_symbol->code = code;
                    }
                    else {
                        // adds at the end
                        disassembly_t* current_code = current_symbol->code;
                        while (current_code->next != NULL) {
                            current_code = current_code->next;
                        }
                        current_code->next = code;
                    }
                }
                else {
                    printf("could not find symbol for %llx\n", address);
                }
            }
            last_address = address;
        }
    }
    if (is_in_symbol) {
        current_symbol->end = last_address + 4;
        symbol_count++;
        current_symbol = &symbol_table[symbol_count];
    }
    pclose(disassembler);

    return ERR_SUCCESS;
    
}


/*
 
 ~/optee/optee_os/scripts/gen_tee_bin.py
 
 magic = 0x4554504f  # 'OPTE'
 version = 2
 flags = 0
 nb_images = 1 if paged_size == 0 else 2
 outf.write(struct.pack('<IBBHI', magic, version, arch_id, flags,
                        nb_images))
 outf.write(struct.pack('<IIII', init_load_addr[0], init_load_addr[1],
                        0, init_size))
 if nb_images == 2:
     outf.write(struct.pack('<IIII', 0xffffffff, 0xffffffff, 1, paged_size))
 */
int loader_parse_coff_into_vm(vmm_context_t* context)
{
    uint8_t* header = (uint8_t*)context->executable.buffer;
    if (header[0]!='M' || header[1]!='Z') return -1;
    // this may be a COFF, lets check more.
    context->entry = context->program_load_address;
    return ERR_SUCCESS;
}

int loader_parse_macho_into_vm(vmm_context_t* context) {

    void* target = NULL;
    
    struct mach_header* header = (struct mach_header*)context->executable.buffer;
    if (header->magic != MH_MAGIC_64) {
        printf("Only supports MACH64 architectures\n");
        return -ENOTSUP;
    }
    
    struct mach_header_64* header64 = (struct mach_header_64*)context->executable.buffer;
    
    int cputype;
    unsigned long cputype_size = sizeof(cputype);
    if (sysctlbyname("hw.cputype", &cputype, &cputype_size, NULL, 0) < 0) {
        printf("Cannot get page size\n");
        return -ENOTSUP;
    };
    if (cputype != header64->cputype) {
        printf("Incompatible cputype: cpu=%x executable=%x\n", cputype, header64->cputype);

        return -ENOTSUP;
    }
    
    if (header64->filetype != MH_EXECUTE) {
        printf("Supports only executable files/n");
        return -ENOTSUP;
    }
    
    struct load_command* command = (struct load_command*)(header64 + 1);
    context->executable.commands = command;

    
    int i;
    for (i=0; i< header64->ncmds; i++) {

        TRACE(DEBUG_PREPARE_VM,"command %d: %x %d\n", i, command->cmd, command->cmdsize);

        if (command->cmd == LC_SEGMENT_64) {
            struct segment_command_64* seg_cmd = (struct segment_command_64*)command;
           
            struct section_64* section = (struct section_64*)(seg_cmd + 1);
  
            if(strcmp(seg_cmd->segname, "__TEXT") == 0) {
                context->executable.text_segment = seg_cmd;
                context->text_begining = seg_cmd->vmaddr;
            }
            
            if (strcmp(seg_cmd->segname, "__PAGEZERO") != 0) { // NOT __PAGEZERO

                TRACE(DEBUG_PREPARE_VM,"Loading segement %s @ %llx-%llx filesize=%lld\n",
                       seg_cmd->segname, seg_cmd->vmaddr, seg_cmd->vmaddr + seg_cmd->vmsize -1 , seg_cmd->filesize);
                
                // we assume that the first byte of the guest VM memory region (context->memory_pointer) will be mapped at context->text_begining
                
                target = context->memory_pointer + seg_cmd->vmaddr - context->text_begining; //(void*)vmm_gva_to_hva(context, seg_cmd->vmaddr);
                memcpy(target, context->executable.buffer + seg_cmd->fileoff, seg_cmd->filesize);
                
                int s;
                for (s=0; s<seg_cmd->nsects; s++) {

                    TRACE(DEBUG_PREPARE_VM,"    %s/%s: %lld bytes @%llx flags=%x\n",
                           section[s].segname, section[s].sectname, section[s].size, section[s].addr, section[s].flags);
                    if(strcmp(section[s].segname, "__DATA") == 0 && strcmp(section[s].sectname, "__data") == 0)  {
                        context->executable.rebase_gpa = section[s].addr;
                        context->executable.rebase_base = context->memory_pointer + context->executable.rebase_gpa - context->text_begining; /* assume this is only relocations for the moment */
                        context->executable.rebase_count = (int)(section[s].size / sizeof(uint64_t));
                        if (context->executable.rebase_count != 2) printf("!!!!!CHANGE IN PROGRAM, ADAPT REBASE!!!!!\n");
                    }
                }
                if(strcmp(seg_cmd->segname, "__LINKEDIT") == 0 ) {
                    context->executable.__linkedit_segment_content = context->executable.buffer + seg_cmd->fileoff;

                    TRACE_BEGIN( DEBUG_LINKEDIT) {
                    int i;
                    int* array = (int*)(context->executable.__linkedit_segment_content);
                    for(i = 0; i< seg_cmd->filesize /4; i++) {
                        char* b = (char*)(&array[i]);
                        printf("%04x: %08x %c%c%c%c\n", i*4, array[i], PRINTABLE(b[0]), PRINTABLE(b[1]), PRINTABLE(b[2]), PRINTABLE(b[3]));
                    }
                    } TRACE_END
                }
            }

        }
        else if (command->cmd == LC_MAIN) {
            struct entry_point_command* entry = (struct entry_point_command*)command;
            context->entry = context->text_begining + entry->entryoff;
            TRACE(DEBUG_PREPARE_VM,"LC_Main: %llx\n", context->entry);
            
        }
        else if (command->cmd == LC_DYLD_CHAINED_FIXUPS) {
            TRACE_BEGIN( DEBUG_PREPARE_VM | DEBUG_LINKEDIT) {
                struct linkedit_data_command* le = (struct linkedit_data_command*)command;
                struct dyld_chained_fixups_header* chain = (struct dyld_chained_fixups_header*)(context->executable.buffer + le->dataoff);
                struct dyld_chained_starts_in_image* starts = (struct dyld_chained_starts_in_image*)((void*)(chain) + chain->starts_offset);

                printf("LC_DYLD_CHAINED_FIXUPS %d bytes @ %x in __LINKEDIT\n",  le->datasize, le->dataoff);
                TRACE_BEGIN(DEBUG_LINKEDIT) {
                    int i;
                    int* array = (int*)(context->executable.buffer + le->dataoff);
                    for(i = 0; i< le->datasize /4; i++) {
                        printf("%04x ", array[i]);
                    }
                    printf("\n");
                    printf("chain version %d count=%d\n", chain->fixups_version, chain->imports_count);
                    printf("seg_count=%d\n", starts->seg_count);
                } TRACE_END
            } TRACE_END
        }
        command = (struct load_command*)((void*)command + command->cmdsize);
    }
    
    /* VERY BAD HACK... */
    /* use dyld_info -fixups hvf-viewer to check what needs to be done */
    uint64_t* rebase_target = context->executable.rebase_base;

    TRACE(DEBUG_REBASE, "Rebase base: %llx (%p) %d\n", context->executable.rebase_gpa, context->executable.rebase_base, context->executable.rebase_count);

    for (i=0; i< context->executable.rebase_count; i++) {
        gva_t relocated = (rebase_target[i] & 0xFFFFFFFF) + context->text_begining;

        TRACE(DEBUG_REBASE, "Relocating @%llx to %llx\n", rebase_target[i], relocated);

        rebase_target[i] = relocated;
    }
    
    loader_parse_symbols(context, context->executable.path);
    
    return ERR_SUCCESS;
}


static int             cached_index = 0;
static disassembly_t*  cached_code = NULL;

symbol_t* loader_symbol(const char* name)
{
    int i;
    for(i=0; i<symbol_count; i++)
    {
        if (strcmp(symbol_table[i].name, name) == 0) return &symbol_table[i];
    }
    return NULL;
}

gva_t loader_symbol_address(const char* name)
{
    int i;
    for(i=0; i<symbol_count; i++)
    {
        if (strcmp(symbol_table[i].name, name) == 0) return symbol_table[i].start;
    }
    return -1;
}

char* loader_disassemble_at(vcore_t* vcore, gva_t origin_address, char** symbolic_location_p) {
    int i;
    if (IS_IN_EMULATION_TABLE(origin_address)) {
        return NULL;
    }
    //TODO CHECK IF MMU ENABLED
    gva_t address = origin_address;
    if (hvftool_config.self_move !=0) address = origin_address > hvftool_config.self_move ? origin_address - hvftool_config.self_move : origin_address;
    if ((address & 3) != 0) {
        printf("Disassembly requested at unaligned address %016llx\n", origin_address);
        *symbolic_location_p = NULL;
        return "";
    }
    if (symbol_gpa_to_gva_offset != 0)
    {
        // symbols are known in GVA and the GVA may not be available from the beginning
        // so we only do the following when we have symbol_gpa_to_gva_offset
        //TODO: if we have TFA, OP-TEE U-boot this may be driven by the memory location. 
        uint64_t sctlr_el1;
        hv_vcpu_get_sys_reg(vcore->vcpu_handle, HV_SYS_REG_SCTLR_EL1, &sctlr_el1);
        bool is_MMU_ON = (sctlr_el1 & 1) != 0;
        if (is_MMU_ON) {
            // there is need of a jump after setting MMU bit in SCTLR to get the paging operational
            // lets not switch until we see high address bits as all 1s
            if (address < symbol_gpa_to_gva_offset)
                address = address - (hvftool_config.memory_map->ram_bottom) + symbol_gpa_to_gva_offset;
        }
        else {
            address = address - (hvftool_config.memory_map->ram_bottom) + symbol_gpa_to_gva_offset;
        }
    }
    i = 0;
    if (cached_index != 0 && (address >= symbol_table[cached_index].start && address < symbol_table[cached_index].end )) {
        i = cached_index;
    }
    else {
        cached_index = 0;
        cached_code = NULL;
    }
    for( /* cached start */ ; i < symbol_count; i++) {

        //printf("checking %llx-%llx %s\n", symbol_table[i].start, symbol_table[i].end, symbol_table[i].name);
        if ((address >= symbol_table[i].start && address < symbol_table[i].end)) {
            // found the function, now find the line
            disassembly_t* current_code = symbol_table[i].code;
            if (cached_code != NULL && address >= cached_code->address)
                current_code = cached_code;
            while (current_code != NULL) {
                if(address == current_code->address){
                    cached_index = i;
                    cached_code = current_code;
                    uint64_t offset = address -  symbol_table[i].start;
                    char* buffer = malloc(strlen(symbol_table[i].name)+16);
                    sprintf(buffer, "%s+%04llx", symbol_table[i].name, offset);
                    *symbolic_location_p = buffer;
                    return current_code->text;
                }
                current_code = current_code->next;
            }
        }
    }
    printf("Disassembly not found for address %016llx\n", address);
    *symbolic_location_p = NULL;
    return "";
}

/*
fffffc0000000000
*/

parameter_t load_parameters[]= {
    {
        .name = "path",
        .type = PARAM_CSTRING,
        .description = "file path",
        .is_mandatory = true,
        .ptr_value = NULL
    },
    {
        // byt default, gva=gpa, MMU on with identity mapping or off, ffffffc008000000 for Linux
        .name = "symbol-gva",
        .type = PARAM_UINT64,
        .description = "The virtual address that corresponds to the gpa of byte 0 of the load location",
        .is_mandatory = false,
        .u64_value = 0
    },
	{
	    // byt default, gva=gpa, MMU on with identity mapping or off, ffffffc008000000 for Linux
	    .name = "relocate",
	    .type = PARAM_BOOL,
	    .description = "The program is location independent and the symbols need to be updated with the load address",
	    .is_mandatory = false,
	    .bool_value = false
	},
	{
	    .name = "map",
	    .type = PARAM_CSTRING,
	    .description = "File used to get synbols from a proprietary map file (<address> <symbol>",
	    .is_mandatory = false,
	    .ptr_value = NULL
	},
    {
        .name = "objdump",
        .type = PARAM_CSTRING,
        .description = "File used to get disassembly using objdump -d",
        .is_mandatory = false,
        .ptr_value = NULL
    },
    {
        .name = "address",
        .type = PARAM_UINT64,
        .description = "where to load the file",
        .is_mandatory = false,
        .ptr_value = NULL
    },
};

extern vmm_context_t vmm_context;

#define LOAD_PARAMETERS_COUNT (sizeof(load_parameters)/sizeof(parameter_t))
int loader_load_all(void)
{
    int i;
    for(i=0; i<load_spec_count; i++) {
        parameter_t* param = parse_parameters(load_specs[i], load_parameters, LOAD_PARAMETERS_COUNT) ;
        if (param == NULL) {
            printf("Error in parsing -load %s.\n", load_specs[i]);
            return -EINVAL;
        }

	parameter_t* p;
	    
        p = parameter_lookup(param, LOAD_PARAMETERS_COUNT, "address");
        uint64_t address = p->is_set ?  p->u64_value : hvftool_config.memory_map->ram_bottom;

	p = parameter_lookup(param, LOAD_PARAMETERS_COUNT, "path");
        char* path = p->ptr_value;
        load_binary_at(&vmm_context, path, address);
	
	hvftool_config.effective_reset_address = hvftool_config.memory_map->ram_bottom;
        //if (p!= NULL) free(p);
        
        p = parameter_lookup(param, LOAD_PARAMETERS_COUNT, "relocate");
	if (p->is_set)
	    relocate_symbols_to_load_address = true;
	//if (p!= NULL) free(p);

	    p = parameter_lookup(param, LOAD_PARAMETERS_COUNT, "map");
	    // otherwise, just use the same file
	    if (p->is_set) {
		if (p->ptr_value != NULL) path = p->ptr_value; // change the path to the specified file
		loader_parse_map(&vmm_context, path);
	    }
	    
	p = parameter_lookup(param, LOAD_PARAMETERS_COUNT, "objdump");
        // otherwise, just use the same file
        if (p->is_set) {
            if (p->ptr_value != NULL) path = p->ptr_value; // change the path to the specified file
            loader_parse_symbols(&vmm_context, path);
        }
        //if (p!= NULL) free(p);

        // this is used to find symbols while MMU is not yet on
        // the lowest symbok is loaded at the gpa selected above
        // by tdefault this should be the _TEXT segment address found from the objdump
        p = parameter_lookup(param, LOAD_PARAMETERS_COUNT, "symbol-gva");
        if (p->is_set)
            symbol_gpa_to_gva_offset = p->u64_value;
	

    }
    return 0;
}

int loader_add_spec(char* spec)
{
    if (load_spec_count >= MAX_SPECS - 1) return -ENOMEM;
    load_specs[load_spec_count++] = spec;
    return ERR_SUCCESS;
}
