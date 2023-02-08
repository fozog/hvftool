/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */

#include <stdio.h>
#include <errno.h>

#include "vcore_info.h"
#include "vcore.h"
#include "vmm.h"

// let's try to keep this private in the vcore domain
extern sys_reg_info_t sys_regs_metadata[];

static char* SPACER = "                                                                                ";


static const char* decode_nibble_at(uint64_t value, int bits, const char* desc[])
{
    return desc[((value >> bits) & 0x0F)];
}

static int not_implemented(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s<no detail print implemented>\n", spacing, SPACER);
    }
    return ERR_SUCCESS;
}


static const char* generic_desc[] = {
    "Not implemented",
    "implemented",
    "invalid(2)"
    "invalid(3)",
};

// ------------------------------
// DBGBCR Debug control registers decoding


int dbg_cr(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    //int index = (reg - HV_SYS_REG_DBGBVR0_EL1) / 4;
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s%s: %01llx\n", spacing, SPACER, "Enabled", (value >> 0) & 0x1);
        printf("%.*s%s: %01llx\n", spacing, SPACER, "PMC", (value >> 1) & 0x3);
        printf("%.*s%s: %01llx\n", spacing, SPACER, "Res0", (value >> 3) & 0x3);
        printf("%.*s%s: %s\n", spacing, SPACER, "BAS", (decode_nibble_at(value, 5, (const char* []){
            "0x0, invalid.",
            "0x1, invalid.",
            "0x2, invalid.",
            "0x3, DBGBCR - Use for T32 instructions.",
            "0x4, invalid.",
            "0x5, invalid.",
            "0x6, invalid.",
            "0x7, invalid.",
            "0x8, invalid.",
            "0x9, invalid.",
            "0xa, invalid.",
            "0xb, invalid.",
            "0xc, DBGBCR+2 - Use for T32 instructions.",
            "0xd, invalid.",
            "0xe, invalid.",
            "0xf, DBGBCR - Use for A64 and A32 instructions",
        })));
        printf("%.*s%s: %01llx\n", spacing, SPACER, "Res0", (value >> 9) & 0xF);
        printf("%.*s%s: %01llx\n", spacing, SPACER, "HMC", (value >> 13) & 0x1);
        printf("%.*s%s: %01llx\n", spacing, SPACER, "SSC", (value >> 14) & 0x3);
        printf("%.*s%s: %01llx\n", spacing, SPACER, "LBN", (value >> 16) & 0xF);
        printf("%.*s%s: %s\n", spacing, SPACER, "BT", (decode_nibble_at(value, 20, (const char* []){
            "0x0, Unlinked instruction address match.",
            "0x1, Instruction address match linked to a Context matching breakpoint.",
            "0x2, Unlinked Context ID match. When FEAT_VHE is implemented, EL2 is using AArch64.",
            "0x3, Linked Context ID match. When FEAT_VHE is implemented, EL2 is using AArch64.",
            "0x4, invalid.",
            "0x5, invalid.",
            "0x6, Unlinked CONTEXTIDR_EL1 match.",
            "0x7, Linked CONTEXTIDR_EL1 match.",
            "0x8, Unlinked VMID match.",
            "0x9, Linked VMID match.",
            "0xa, Unlinked VMID and Context ID match.",
            "0xb, Linked VMID and Context ID match.",
            "0xc, Unlinked CONTEXTIDR_EL2 match.",
            "0xd, Linked CONTEXTIDR_EL2 match.",
            "0xe, Unlinked Full Context ID match.",
            "0xf, Linked Full Context ID match.",
        })));
        printf("%.*s%s: %01llx\n", spacing, SPACER, "LBN", (value >> 24) & 0xFFFFFFFFFF);
    }
    return ERR_SUCCESS;
}

// ------------------------------
// DFR Debug features registers decoding


int dfr0_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s<no detail print implemented>\n", spacing, SPACER);
    }
    return ERR_SUCCESS;
}

int dfr1_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s<no detail print implemented>\n", spacing, SPACER);
    }
    return ERR_SUCCESS;
}


// ------------------------------
// ESR registers decoding

static const char* sas_desc[] = {
    "byte",
    "halfword",
    "word",
    "doubleword"
};

static const char* dfsc_desc[] = {
    "Address size fault, level 0 of translation or translation table base register.",
    "Address size fault, level 1.",
    "Address size fault, level 2.",
    "Address size fault, level 3.",
    "Translation fault, level 0.",
    "Translation fault, level 1.",
    "Translation fault, level 2.",
    "Translation fault, level 3.",
    "Access flag fault, level 0.",
    "Access flag fault, level 1.",
    "Access flag fault, level 2.",
    "Access flag fault, level 3.",
    "Permission fault, level 0.",
    "Permission fault, level 1.",
    "Permission fault, level 2.",
    "Permission fault, level 3.",
    "Synchronous External abort, not on translation table walk or hardware update of translation table.",
    "Synchronous Tag Check Fault.",
    "",
    "Synchronous External abort on translation table walk or hardware update of translation table, level -1.",
    "Synchronous External abort on translation table walk or hardware update of translation table, level 0.",
    "Synchronous External abort on translation table walk or hardware update of translation table, level 1.",
    "Synchronous External abort on translation table walk or hardware update of translation table, level 2.",
    "Synchronous External abort on translation table walk or hardware update of translation table, level 3.",
    "Synchronous parity or ECC error on memory access, not on translation table walk.",
    "",
    "",
    "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level -1.",
    "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level 0.",
    "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level 1.",
    "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level 2.",
    "Synchronous parity or ECC error on memory access on translation table walk or hardware update of translation table, level 3.",
    "",
    "Alignment fault.",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "Address size fault, level -1.",
    "",
    "Translation fault, level -1.",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "",
    "TLB conflict abort.",
    "Unsupported atomic hardware update fault.",
    "IMPLEMENTATION DEFINED fault (Lockdown).",
    "IMPLEMENTATION DEFINED fault (Unsupported Exclusive or Atomic access).",
    "",
    "",
    "",
};

static int iss_decode(uint32_t class, uint32_t iss, int spacing, detail_t detail)
{
    switch(class) {
        case SMC_EXCEPTION: { // SVC instruction execution in AArch64 state.
            uint16_t imm16 = iss & 0xFFFF; // immediate value of SVC instruction
            printf("%.*sSVC #0x%04x\n", spacing, SPACER, imm16);
        }
        break;
        case BREAKPOINT_EXCEPTION: { // Trapped MSR, MRS or System instruction execution in AArch64 state, that is not reported using EC 0b000000, 0b000001, or 0b000111.
            uint16_t imm16 = iss & 0x3F; //  ISFC == 0x22
            printf("%.*sBreakppoint Exception #%d\n", spacing, SPACER, imm16);
        }
        break;
        case MRS_EXCPETION: { // Trapped MSR, MRS or System instruction execution in AArch64 state, that is not reported using EC 0b000000, 0b000001, or 0b000111.
            bool is_msr = (iss & 1) == 0; // write access
            uint16_t crm = (iss >> 9) & 0xf;
            uint16_t rt = (iss >> 5) & 0xf;
            printf("%.*s%s rt=x%d crm=%d\n", spacing, SPACER, is_msr ? "MSR" : "MRS", rt, crm);
        }
        break;
        case DATA_ABORT_EXCEPTION: { // Data Abort from a lower Exception level.
            bool is_valid = ((iss >> 24) & 1) != 0;
            if (is_valid) {
                int dfsc = iss & 0x3F;
                bool is_write = (iss >> 6) & 1;
                bool s1ptw = (iss >> 7) & 1;
                uint32_t sas = (iss >> 22) & 3;
                uint32_t len = 1 << sas;
                uint32_t srt = (iss >> 16) & 0x1f;
                uint32_t cm = (iss >> 8) & 0x1;
                printf("%.*s%s\n", spacing, SPACER, is_write ? "write operation": "read operation");
                printf("%.*s%s\n", spacing, SPACER, s1ptw==0 ? "Fault not on a stage 2 translation for a stage 1 translation table walk." : "Fault on the stage 2 translation of an access for a stage 1 translation table walk.");
                printf("%.*sSyndrome Access Size=%s\n", spacing, SPACER, sas_desc[sas]);
                printf("%.*slen=%x\n", spacing, SPACER, len);
                printf("%.*sSyndrome Register Transfer=x%d\n", spacing, SPACER, srt);
                printf("%.*scm=%x\n", spacing, SPACER, cm);
                printf("%.*sData Fault Status Code=%s\n", spacing, SPACER, dfsc_desc[dfsc]);
            }
        }
        break;
    };
    return ERR_SUCCESS;
}

// ESR_EL1

static const char* el1_class_description[] = {
    "Unknown reason.",
    "Trapped WF* instruction execution.",
    "",
    "Trapped MCR or MRC access with (coproc==0b1111) that is not reported using EC 0b000000.",
    "Trapped MCRR or MRRC access with (coproc==0b1111) that is not reported using EC 0b000000.",
    "Trapped MCR or MRC access with (coproc==0b1110).",
    "Trapped LDC or STC access.",
    "Access to SVE, Advanced SIMD or floating-point functionality trapped by CPACR_EL1.FPEN, CPTR_EL2.FPEN, CPTR_EL2.TFP, or CPTR_EL3.TFP control.",
    "",
    "",
    "Trapped execution of an LD64B, ST64B, ST64BV, or ST64BV0 instruction.",
    "",
    "Trapped MRRC access with (coproc==0b1110).",
    "Branch Target Exception.",
    "Illegal Execution state.",
    "",
    "",
    "SVC instruction execution in AArch32 state.",
    "",
    "",
    "",
    "SVC instruction execution in AArch64 state.",
    "",
    "",
    "Trapped MSR, MRS or System instruction execution in AArch64 state, that is not reported using EC 0b000000, 0b000001, or 0b000111.",
    "Access to SVE functionality trapped as a result of CPACR_EL1.ZEN, CPTR_EL2.ZEN, CPTR_EL2.TZ, or CPTR_EL3.EZ, that is not reported using EC 0b000000.",
    "",
    "",
    "Exception from a Pointer Authentication instruction authentication failure",
    "",
    "",
    "",
    "Instruction Abort from a lower Exception level.",
    "Instruction Abort taken without a change in Exception level.",
    "PC alignment fault exception.",
    "",
    "Data Abort from a lower Exception level.",
    "Data Abort taken without a change in Exception level.",
    "SP alignment fault exception.",
    "",
    "Trapped floating-point exception taken from AArch32 state.",
    "",
    "",
    "",
    "Trapped floating-point exception taken from AArch64 state.",
    "",
    "",
    "SError interrupt.",
    "Breakpoint exception from a lower Exception level.",
    "Breakpoint exception taken without a change in Exception level.",
    "Software Step exception from a lower Exception level.",
    "Software Step exception taken without a change in Exception level.",
    "Watchpoint exception from a lower Exception level.",
    "Watchpoint exception taken without a change in Exception level.",
    "",
    "",
    "BKPT instruction execution in AArch32 state.",
    "",
    "",
    "",
    "BRK instruction execution in AArch64 state.",
    "",
    "",
    "",
};

int esr_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    uint32_t iss = value & 0xFFFFFF;
    uint32_t class = (value >> 26 ) &0x3F;
    spacing += 4;
    printf("%.*sEC=%x %c %s\n", spacing, SPACER, class, detail == FULL ? '-' : ' ', detail == FULL ? el1_class_description[class] : "");
    printf("%.*sISS=%x\n", spacing, SPACER, iss);
    if (detail == FULL) iss_decode(class, iss, spacing + 4,  detail);
    return ERR_SUCCESS;
}

// ESR_EL2
// not a register you can set,n but the one that is readable in the exit structure
// almost same as EL1 except in has at least one special class

static const char* el2_class_description[] = {
    "Unknown reason.",
    "Trapped WF* instruction execution.",
    "",
    "Trapped MCR or MRC access with (coproc==0b1111) that is not reported using EC 0b000000.",
    "Trapped MCRR or MRRC access with (coproc==0b1111) that is not reported using EC 0b000000.",
    "Trapped MCR or MRC access with (coproc==0b1110).",
    "Trapped LDC or STC access.",
    "",
    "",
    "",
    "Trapped execution of an LD64B, ST64B, ST64BV, or ST64BV0 instruction.",
    "",
    "Trapped MRRC access with (coproc==0b1110).",
    "Branch Target Exception.",
    "Illegal Execution state.",
    "",
    "",
    "SVC instruction execution in AArch32 state.",
    "HVC instruction execution in AArch32 state, when HVC is not disabled.", // EL2 specific
    "SMC instruction execution in AArch32 state, when SMC is not disabled.", // EL2 specific
    "",
    "SVC instruction execution in AArch64 state.",
    "HVC instruction execution in AArch64 state, when HVC is not disabled.", // EL2 specific
    "SMC instruction execution in AArch32 state, when SMC is not disabled.", // EL2 specific
    "Trapped MSR, MRS or System instruction execution in AArch64 state, that is not reported using EC 0b000000, 0b000001, or 0b000111.",
    "Access to SVE functionality trapped as a result of CPACR_EL1.ZEN, CPTR_EL2.ZEN, CPTR_EL2.TZ, or CPTR_EL3.EZ, that is not reported using EC 0b000000.",
    "Trapped ERET, ERETAA, or ERETAB instruction execution.", // EL2 specific
    "",
    "Exception from a Pointer Authentication instruction authentication failure",
    "",
    "",
    "",
    "Instruction Abort from a lower Exception level.",
    "Instruction Abort taken without a change in Exception level.",
    "PC alignment fault exception.",
    "",
    "Data Abort from a lower Exception level.",
    "Data Abort taken without a change in Exception level.",
    "SP alignment fault exception.",
    "",
    "Trapped floating-point exception taken from AArch32 state.",
    "",
    "",
    "",
    "Trapped floating-point exception taken from AArch64 state.",
    "",
    "",
    "SError interrupt.",
    "Breakpoint exception from a lower Exception level.",
    "Breakpoint exception taken without a change in Exception level.",
    "Software Step exception from a lower Exception level.",
    "Software Step exception taken without a change in Exception level.",
    "Watchpoint exception from a lower Exception level.",
    "Watchpoint exception taken without a change in Exception level.",
    "",
    "",
    "BKPT instruction execution in AArch32 state.",
    "",
    "",
    "",
    "BRK instruction execution in AArch64 state.",
    "",
    "",
    "",
};

int esr_el2(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    uint32_t iss = value & 0xFFFFFF;
    uint32_t class = (value >> 26 ) &0x3F;
    spacing += 4;
    printf("%.*sEC=%x %c %s\n", spacing, SPACER, class, detail == FULL ? '-' : ' ', detail == FULL ? el2_class_description[class] : "");
    printf("%.*sISS=%x\n", spacing, SPACER, iss);
    if (detail == FULL) iss_decode(class, iss, spacing + 4,  detail);
    return ERR_SUCCESS;
}

// ------------------------------
// ISAR - Instruction Set Attribute Registers

char* __decode_isa_at(uint64_t value, int bits, char* isa, int spacing, detail_t detail, char* desc[], int ndescs)
{
    int index= ((value >> bits) & 0x0F);
    if (index == 0) return "";
    if (index > ndescs)
        printf("%.*s%s: invalid index %d\n", spacing, SPACER, isa, index);
    else
        printf("%.*s%s: %s\n", spacing, SPACER, isa, desc[index-1]);
    return NULL;
}

#define DECODE_ISA_AT(value, bits, isa, spacing, detail, desc) __decode_isa_at(value, bits, isa, spacing, detail, desc, sizeof(desc)/sizeof(char*))

int isar0_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        DECODE_ISA_AT(value, 4, "AES", spacing, detail, ((char* []){
            "1, AESE, AESD, AESMC, and AESIMC.",
            "2, AESE, AESD, AESMC, AESIMC and PMULL/PMULL2."
        }));
        DECODE_ISA_AT(value, 8, "SHA1", spacing, detail, ((char* []){
            "1, SHA1C, SHA1P, SHA1M, SHA1H, SHA1SU0, and SHA1SU1",
        }));
        DECODE_ISA_AT(value, 12, "SHA2", spacing, detail, ((char* []){
            "1, SSHA256H, SHA256H2, SHA256SU0, and SHA256SU1.",
            "2, SSHA256H, SHA256H2, SHA256SU0, SHA256SU1, SHA512H, SHA512H2, SHA512SU0, and SHA512SU1.",
        }));
        DECODE_ISA_AT(value, 16, "CRC32", spacing, detail, ((char* []){
            "1, CRC32B, CRC32H, CRC32W, CRC32X, CRC32CB, CRC32CH, CRC32CW, and CRC32CX.",
        }));
        DECODE_ISA_AT(value, 20, "Atomic", spacing, detail, ((char* []){
            "1, LDADD, LDCLR, LDEOR, LDSET, LDSMAX, LDSMIN, LDUMAX, LDUMIN, CAS, CASP, and SWP.",
        }));
        DECODE_ISA_AT(value, 28, "RDM", spacing, detail, ((char* []){
            "1, SQRDMLAH and SQRDMLSH.",
        }));
        DECODE_ISA_AT(value, 32, "SHA3", spacing, detail, ((char* []){
            "1, EOR3, RAX1, XAR, and BCAX.",
        }));
        DECODE_ISA_AT(value, 36, "SM3", spacing, detail, ((char* []){
            "1, SM3SS1, SM3TT1A, SM3TT1B, SM3TT2A, SM3TT2B, SM3PARTW1, and SM3PARTW2.",
        }));
        DECODE_ISA_AT(value, 40, "SM4", spacing, detail, ((char* []){
            "1, SM4E and SM4EKEY.",
        }));
        DECODE_ISA_AT(value, 44, "DP - Dot Product", spacing, detail, ((char* []){
            "1, UDOT and SDOT.",
        }));
        DECODE_ISA_AT(value, 48, "FHM", spacing, detail, ((char* []){
            "1, FMLAL and FMLSL.",
        }));
        DECODE_ISA_AT(value, 52, "TS", spacing, detail, ((char* []){
            "1, FCFINV, RMIF, SETF16, and SETF8.",
            "2, CFINV, RMIF, SETF16, SETF8, AXFLAG, and XAFLAG."
        }));
        DECODE_ISA_AT(value, 56, "TLB", spacing, detail, ((char* []){
            "1, Outer shareable TLB maintenance instructions are implemented.",
            "2, Outer shareable and TLB range maintenance instructions are implemented."
        }));
        DECODE_ISA_AT(value, 60, "RNDR", spacing, detail, ((char* []){
            "1, RNDR and RNDRRS .",
        }));
    }
    return ERR_SUCCESS;
}

int isar1_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        DECODE_ISA_AT(value, 0, "DP - Data Persistence writeback", spacing, detail, ((char* []){
            "1, DC CVAP.",
            "2, DC CVAP and DC CVADP."
        }));
        DECODE_ISA_AT(value, 4, "APA - DQARMA5 algorithm", spacing, detail, ((char* []){
            "1, Address Authentication using the QARMA5 algorithm is implemented, with the HaveEnhancedPAC() and HaveEnhancedPAC2() functions returning FALSE.",
            "2, Address Authentication using the QARMA5 algorithm is implemented, with the HaveEnhancedPAC() function returning TRUE and the HaveEnhancedPAC2() function returning FALSE.",
            "3, Address Authentication using the QARMA5 algorithm is implemented, with the HaveEnhancedPAC2() function returning TRUE, the HaveFPAC() function returning FALSE, the HaveFPACCombined() function returning FALSE, and the HaveEnhancedPAC() function returning FALSE.",
            "4, Address Authentication using the QARMA5 algorithm is implemented, with the HaveEnhancedPAC2() function returning TRUE, the HaveFPAC() function returning TRUE, the HaveFPACCombined() function returning FALSE, and the HaveEnhancedPAC() function returning FALSE.",
            "5, Address Authentication using the QARMA5 algorithm is implemented, with the HaveEnhancedPAC2() function returning TRUE, the HaveFPAC() function returning TRUE, the HaveFPACCombined() function returning TRUE, and the HaveEnhancedPAC() function returning FALSE.",
        }));
        DECODE_ISA_AT(value, 8, "API - IMPLEMENTATION DEFINED algorithm is implemented in the PE for address authentication", spacing, detail, ((char* []){
            "1, Address Authentication using an IMPLEMENTATION DEFINED algorithm is implemented, with the HaveEnhancedPAC() and HaveEnhancedPAC2() functions returning FALSE.",
            "2, Address Authentication using an IMPLEMENTATION DEFINED algorithm is implemented, with the HaveEnhancedPAC() function returning TRUE, and the HaveEnhancedPAC2() function returning FALSE.",
            "3, Address Authentication using an IMPLEMENTATION DEFINED algorithm is implemented, with the HaveEnhancedPAC2() function returning TRUE, and the HaveEnhancedPAC() function returning FALSE.",
            "4, Address Authentication using an IMPLEMENTATION DEFINED algorithm is implemented, with the HaveEnhancedPAC2() function returning TRUE, the HaveFPAC() function returning TRUE, the HaveFPACCombined() function returning FALSE, and the HaveEnhancedPAC() function returning FALSE.",
            "5, Address Authentication using an IMPLEMENTATION DEFINED algorithm is implemented, with the HaveEnhancedPAC2() function returning TRUE, the HaveFPAC() function returning TRUE, the HaveFPACCombined() function returning TRUE, and the HaveEnhancedPAC() function returning FALSE.",
        }));
        DECODE_ISA_AT(value, 12, "JSCVT - JavaScript conversion from double precision floating point values to integers", spacing, detail, ((char* []){
            "1, FJCVTZS .",
        }));
        DECODE_ISA_AT(value, 16, "FCMA", spacing, detail, ((char* []){
            "1, FCMLA and FCADD.",
        }));
        DECODE_ISA_AT(value, 20, "LRCPC", spacing, detail, ((char* []){
            "1,  LDAPUR*, and STLUR*.",
            "2, LDAPR*, LDAPUR*, and STLUR*",
        }));
        DECODE_ISA_AT(value, 24, "GPA", spacing, detail, ((char* []){
            "1, Generic Authentication using the QARMA5 algorithm is implemented. This includes the PACGA instruction.",
        }));
        DECODE_ISA_AT(value, 28, "GPI", spacing, detail, ((char* []){
            "1, Generic Authentication using an IMPLEMENTATION DEFINED algorithm is implemented. This includes the PACGA instruction.",
        }));
        DECODE_ISA_AT(value, 32, "FRINTTS", spacing, detail, ((char* []){
            "1, FRINT32Z, FRINT32X, FRINT64Z, and FRINT64X.",
        }));
        DECODE_ISA_AT(value, 36, "SB", spacing, detail, ((char* []){
            "1, SB.",
        }));
        DECODE_ISA_AT(value, 40, "SPECRES", spacing, detail, ((char* []){
            "1, CFP RCTX, DVP RCTX, and CPP RCTX.",
        }));
        DECODE_ISA_AT(value, 44, "BF16", spacing, detail, ((char* []){
            "1, BFCVT, BFCVTN, BFCVTN2, BFDOT, BFMLALB, BFMLALT, and BFMMLA.",
        }));
        DECODE_ISA_AT(value, 48, "DGH", spacing, detail, ((char* []){
            "1, Data Gathering Hint is implemented.",
        }));
        DECODE_ISA_AT(value, 52, "I8MM - Advanced SIMD and Floating-point Int8 matrix multiplication", spacing, detail, ((char* []){
            "1, SMMLA, SUDOT, UMMLA, USMMLA, and USDOT.",
        }));
        DECODE_ISA_AT(value, 56, "XS", spacing, detail, ((char* []){
            "1, The XS attribute, the TLBI and DSB instructions with the nXS qualifier, and the HCRX_EL2.{FGTnXS, FnXS} fields are supported.",
        }));
        DECODE_ISA_AT(value, 60, "LS64", spacing, detail, ((char* []){
            "1, LD64B and ST64B.",
            "2, LD64B, ST64B, and ST64BV.",
            "3, LD64 and ST64B* instructions, the ACCDATA_EL1 register, and their associated traps are supported."
        }));
    }
    return ERR_SUCCESS;
}

// ------------------------------
// MAIR
char* dev_attributes[] = {
    "Device-nGnRnE memory",
    "Device-nGnRE memory",
    "Device-nGRE memory",
    "Device-GRE memory"
};

char* xsdev_attributes[] = {
    "XSDevice-nGnRnE memory",
    "XSDevice-nGnRE memory",
    "XSDevice-nGRE memory",
    "XSDevice-GRE memory"
};

char* normal_attributes[] = {
    "unpredictable",
    "Normal memory, Outer Write-Through Transient, R!A, WA",
    "Normal memory, Outer Write-Through Transient, RA, W!A",
    "Normal memory, Outer Write-Through Transient, RA, WA",

    "Normal memory, Outer Non-cacheable",
    "Normal memory, Outer Write-Back Transient, R!A, WA",
    "Normal memory, Outer Write-Back Transient, RA, W!A",
    "Normal memory, Outer Write-Back Transient, RA, WA",

    "Normal memory, Outer Write-Through Non-Transient, R!A, W!A",
    "Normal memory, Outer Write-Through Non-Transient, R!A, WA",
    "Normal memory, Outer Write-Through Non-Transient, RA, W!A",
    "Normal memory, Outer Write-Through Non-Transient, RA, WA",

    "Normal memory, Outer Write-Back Non-Transient, R!A, W!A",
    "Normal memory, Outer Write-Back Non-Transient, R!A, WA",
    "Normal memory, Outer Write-Back Non-Transient, RA, W!A",
    "Normal memory, Outer Write-Back Non-Transient, RA, WA",
};

char* normal_attributes2[] = {
    "unpredictable",
    "Normal memory, Inner Write-Through Transient, R!A, WA",
    "Normal memory, Inner Write-Through Transient, RA, W!A",
    "Normal memory, Inner Write-Through Transient, RA, WA",

    "Normal memory, Inner Non-cacheable",
    "Normal memory, Inner Write-Back Transient, R!A, WA",
    "Normal memory, Inner Write-Back Transient, RA, W!A",
    "Normal memory, Inner Write-Back Transient, RA, WA",

    "Normal memory, Inner Write-Through Non-Transient, R!A, W!A",
    "Normal memory, Inner Write-Through Non-Transient, R!A, WA",
    "Normal memory, Inner Write-Through Non-Transient, RA, W!A",
    "Normal memory, Inner Write-Through Non-Transient, RA, WA",

    "Normal memory, Inner Write-Back Non-Transient, R!A, W!A",
    "Normal memory, Inner Write-Back Non-Transient, R!A, WA",
    "Normal memory, Inner Write-Back Non-Transient, RA, W!A",
    "Normal memory, Inner Write-Back Non-Transient, RA, WA",
};

char* decode_mair_at(uint64_t value, int i) {
    unsigned char tag = (unsigned char)(value >> i);
    if ((tag & ~(0b1100)) == 0b00) {
        return dev_attributes[(tag >> 2) & 0b11];
    }
    else if ((tag & ~(0b1100)) == 0b01) {
        return xsdev_attributes[(tag >> 2) & 0b11];
    }
    else if (tag == 0b01000000) {
        return "Normal Inner Non-cacheable, Outer Non-cacheable memory with the XS attribute set to 0";
    }
    else if (tag == 0b10100000) {
        return "Normal Inner Write-through Cacheable, Outer Write-through Cacheable, Read-Allocate, No-Write Allocate, Non-transient memory with the XS attribute set to 0";
    }
    else if (tag == 0b11110000) {
        return "agged Normal Inner Write-Back, Outer Write-Back, Read-Allocate, Write-Allocate Non-transient memory";
    }
    else if (((tag > 4) & 0b1111) != 0) {
        return normal_attributes[((tag > 4) & 0b1111)];
    }
    else if ((tag & 0b1111) != 0) {
        return normal_attributes2[tag & 0b1111];
    }
    return "unpredictable";
}

int MAIR_EL1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        int i;
        for (i = 0; i < 8; i++) {
            printf("%.*sMAIR[%d]: %s\n", spacing, SPACER, i, decode_mair_at(value, i * 8));
        }
    }
    return ERR_SUCCESS;
}

// ------------------------------
// MFR -  Memory Feature Registers

int mfr0_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s%s: %s\n", spacing, SPACER, "Physical Address Range", decode_nibble_at(value, 0, (const char* []){
            "32 bits, 4GB.",
            "36 bits, 64GB.",
            "40 bits, 1TB.",
            "42 bits, 4TB.",
            "44 bits, 16TB.",
            "48 bits, 256TB.",
            "52 bits, 4PB.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "ASIDBits", decode_nibble_at(value, 4, (const char* []){
            "0, 8 bits.",
            "1, 16 bits",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "BigEnd", decode_nibble_at(value, 8, (const char* []){
            "No mixed-endian support",
            "Mixed-endian support.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "SNSMmem", decode_nibble_at(value, 12, (const char* []){
            "Does not support a distinction between Secure and Non-secure Memory.",
            "Does support a distinction between Secure and Non-secure Memory.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "BigEndEL0", decode_nibble_at(value, 16, (const char* []){
            "No mixed-endian support at EL0. The SCTLR_EL1.E0E bit has a fixed value.",
            "Mixed-endian support at EL0. The SCTLR_EL1.E0E bit can be configured.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "TGran16", decode_nibble_at(value, 20, (const char* []){
            "16KB granule not supported.",
            "16KB granule supported.",
            "16KB granule supports 52-bit input and output addresses.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "TGran64", decode_nibble_at(value, 24, (const char* []){
            "64KB granule supported.",
            "invalid(1)",
            "invalid(2)",
            "invalid(3)",
            "invalid(4)",
            "invalid(5)",
            "invalid(6)",
            "invalid(7)",
            "invalid(8)",
            "invalid(9)",
            "invalid(10)",
            "invalid(11)",
            "invalid(12)",
            "invalid(13)",
            "invalid(14)",
            "64KB granule not supported.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "TGran4", decode_nibble_at(value, 28, (const char* []){
            "4KB granule not supported.",
            "4KB granule supports 52-bit input and output addresses.",
            "invalid(2)",
            "invalid(3)",
            "invalid(4)",
            "invalid(5)",
            "invalid(6)",
            "invalid(7)",
            "invalid(8)",
            "invalid(9)",
            "invalid(10)",
            "invalid(11)",
            "invalid(12)",
            "invalid(13)",
            "invalid(14)",
            "4KB granule not supported.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "TGran16_2", decode_nibble_at(value, 32, (const char* []){
            "Support for 16KB granule at stage 2 is identified in the ID_AA64MMFR0_EL1.TGran16 field.",
            "16KB granule not supported at stage 2.",
            "16KB granule supported at stage 2.",
            "16KB granule at stage 2 supports 52-bit input and output addresses.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "TGran64_2", decode_nibble_at(value, 36, (const char* []){
            "Support for 64KB granule at stage 2 is identified in the ID_AA64MMFR0_EL1.TGran64 field.",
            "64KB granule not supported at stage 2.",
            "64KB granule supported at stage 2.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "TGran4_2", decode_nibble_at(value, 40, (const char* []){
            "Support for 4KB granule at stage 2 is identified in the ID_AA64MMFR0_EL1.TGran4 field.",
            "4KB granule not supported at stage 2.",
            "4KB granule supported at stage 2.",
            "4KB granule at stage 2 supports 52-bit input and output addresses.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "ExS - context synchronizing exception entry and exit", decode_nibble_at(value, 44, (const char* []){
            "All exception entries and exits are context synchronization events.",
            "Non-context synchronizing exception entry and exit are supported.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "FGT - Fine-Grained Trap controls", decode_nibble_at(value, 56, generic_desc));
        printf("%.*s%s: %s\n", spacing, SPACER, "ECV - Enhanced Counter Virtualization", decode_nibble_at(value, 60, (const char* []){
            "not implemented.",
            "Supports CNTHCTL_EL2.{EL1TVT, EL1TVCT, EL1NVPCT, EL1NVVCT, EVNTIS}, CNTKCTL_EL1.EVNTIS, CNTPCTSS_EL0 counter views, and CNTVCTSS_EL0 counter views. Extends the PMSCR_EL1.PCT, PMSCR_EL2.PCT, TRFCR_EL1.TS, and TRFCR_EL2.TS fields.",
            "Supports CNTHCTL_EL2.{EL1TVT, EL1TVCT, EL1NVPCT, EL1NVVCT, EVNTIS}, CNTKCTL_EL1.EVNTIS, CNTPCTSS_EL0 counter views, and CNTVCTSS_EL0 counter views. Extends the PMSCR_EL1.PCT, PMSCR_EL2.PCT, TRFCR_EL1.TS, and TRFCR_EL2.TS fields; for CNTHCTL_EL2.ECV and CNTPOFF_EL2"
        }));
    }
    return ERR_SUCCESS;
}

int mfr1_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s%s: %s\n", spacing, SPACER, "HAFDBS -  Access flag and Dirty state in translation tables.", decode_nibble_at(value, 0, (const char* []){
            "Hardware update of the Access flag and dirty state are not supported.",
            "Hardware update of the Access flag is supported.",
            "Hardware update of both the Access flag and dirty state is supported.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "VMIDBits", decode_nibble_at(value, 4, (const char* []){
            "0, 8 bits.",
            "1, 16 bits",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "VH - Virtualization Host Extensions", decode_nibble_at(value, 8, (const char* []){
            "not supported",
            "supported",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "HPDS - Hierarchical Permission Disables", decode_nibble_at(value, 12, (const char* []){
            "Disabling of hierarchical controls not supported.",
            "Disabling of hierarchical controls supported with the TCR_EL1.{HPD1, HPD0}, TCR_EL2.HPD or TCR_EL2.{HPD1, HPD0}, and TCR_EL3.HPD bits.",
            "Disabling of hierarchical controls supported with the TCR_EL1.{HPD1, HPD0}, TCR_EL2.HPD or TCR_EL2.{HPD1, HPD0}, and TCR_EL3.HPD bits <AND> ossible hardware allocation of bits[62:59] of the translation table descriptors from the final lookup level for IMPLEMENTATION DEFINED use.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "LO - LORegions", decode_nibble_at(value, 16, (const char* []){
            "not supported",
            "supported",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "PAN - Privileged Access Never", decode_nibble_at(value, 20, (const char* []){
            "not supported",
            "supported",
            "supported and AT S1E1RP and AT S1E1WP instructions supported.",
            "supported, AT S1E1RP and AT S1E1WP instructions supported, and SCTLR_EL1.EPAN and SCTLR_EL2.EPAN bits supported."
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "SpecSEI -  SError interrupt exceptions from speculative reads of memory", decode_nibble_at(value, 24, (const char* []){
            "The PE never generates an SError interrupt due to an External abort on a speculative read.",
            "The PE might generate an SError interrupt due to an External abort on a speculative read.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "XNX", decode_nibble_at(value, 28, (const char* []){
            "Distinction between EL0 and EL1 execute-never control at stage 2 not supported.",
            "Distinction between EL0 and EL1 execute-never control at stage 2 supported.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "TWED - delayed trapping of WFE", decode_nibble_at(value, 32, (const char* []){
            "Configurable delayed trapping of WFE is not supported.",
            "Configurable delayed trapping of WFE is supported.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "ETS", decode_nibble_at(value, 36, (const char* []){
            "not supported",
            "supported",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "HCX", decode_nibble_at(value, 40, (const char* []){
            "HCRX_EL2 and its associated EL3 trap are not supported.",
            "HCRX_EL2 and its associated EL3 trap are supported.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "AFP - context synchronizing exception entry and exit", decode_nibble_at(value, 44, (const char* []){
            "The FPCR.{AH, FIZ, NEP} fields are not supported.",
            "The FPCR.{AH, FIZ, NEP} fields are supported.",
        }));
        printf("%.*s%s: %s\n", spacing, SPACER, "nTLBPA", decode_nibble_at(value, 48, (const char* []){
            "The intermediate caching of translation table walks might include non-coherent caches of previous valid translation table entries since the last completed relevant TLBI applicable to the PE",
            "The intermediate caching of translation table walks does not include non-coherent caches of previous valid translation table entries since the last completed TLBI applicable to the PE",
        }));
    }
    return ERR_SUCCESS;
}

int mfr2_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s<no detail print implemented>\n", spacing, SPACER);
    }
    return ERR_SUCCESS;
}


// ------------------------------
// PFR -  Processor Feature Registers


static const char* fp_desc[] = {
    "Implemented",
    "implemented, with half precision support",
    "invalid(2)"
    "Not implemented",
};

static const char* el0_desc[] = {
    "invalid(0)",
    "can be executed in AArch64 state only.",
    "can be executed in either AArch64 or AArch32 state.",
    "invalid(3)"
};

static const char* el2_desc[] = {
    "Not implemented",
    "implemented, can be executed in AArch64 state only.",
    "implemented, can be executed in either AArch64 or AArch32 state.",
    "invalid(3)"
};


int pfr0_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*sEL0: %s\n", spacing, SPACER, decode_nibble_at(value, 0, el0_desc));
        printf("%.*sEL1: %s\n", spacing, SPACER, decode_nibble_at(value, 4, el0_desc));
        printf("%.*sEL2: %s\n", spacing, SPACER, decode_nibble_at(value, 8, el2_desc));
        printf("%.*sEL3: %s\n", spacing, SPACER, decode_nibble_at(value, 12, el2_desc));
        printf("%.*sFloating point: %s\n", spacing, SPACER, decode_nibble_at(value, 16, fp_desc));
        printf("%.*sAdvanced SIMD: %s\n", spacing, SPACER, decode_nibble_at(value, 20, fp_desc));
        printf("%.*sGIC: %s\n", spacing, SPACER, decode_nibble_at(value, 24, (const char* []){
            "Not implemented",
            "implemented, v3.0 & v4.0 supported",
            "invalid(2)"
            "implemented, v4.1 supported",
        }));
        printf("%.*sRAS: %s\n", spacing, SPACER, decode_nibble_at(value, 28, (const char* []){
            "0, Not implemented",
            "1, implemented",
            "2, FEAT_RASv1p1 implemented and, if EL3 is implemented, FEAT_DoubleFault implemented"
            "invalid(3)",
        }));
        printf("%.*sSVE: %s\n", spacing, SPACER, decode_nibble_at(value, 32, generic_desc));
        printf("%.*sSEL2: %s\n", spacing, SPACER, decode_nibble_at(value, 36, generic_desc)); // not a typo: same values
        printf("%.*sMPAM: %s\n", spacing, SPACER, decode_nibble_at(value, 40, (const char* []){
            "0, check PFR1/MPAM for effective behavior",
            "1, check PFR1/MPAM for effective behavior",
            "invalid(2)"
            "invalid(3)",
        }));
        printf("%.*sAMU: %s\n", spacing, SPACER, decode_nibble_at(value, 44, (const char* []){
            "Not implemented",
            "Implemented, v1",
            "Implemented, v1p1"
            "invalid(3)",
        }));
        printf("%.*sData Independent Timing: %s\n", spacing, SPACER, decode_nibble_at(value, 44, (const char* []){
            "AArch64 does not guarantee constant execution time of any instructions.",
            "AArch64 provides the PSTATE.DIT mechanism to guarantee constant execution time of certain instructions.",
            "invalid(2)",
            "invalid(3)",
        }));
        printf("%.*sSpeculative use of out of context branch targets (CSV2): %s\n", spacing, SPACER, decode_nibble_at(value, 56, (const char* []){
            "This PE does not disclose whether branch targets trained in one hardware-described context can exploitatively control speculative execution in a different hardware-described context.",
            "Branch targets trained in one hardware-described context can exploitatively control speculative execution in a different hardware-described context only in a hard-to-determine way. Contexts do not include the SCXTNUM_ELx register contexts. Support for the SCXTNUM_ELx registers is defined in ID_AA64PFR1_EL1.CSV2_frac.",
            "Branch targets trained in one hardware-described context can exploitatively control speculative execution in a different hardware-described context only in a hard-to-determine way. The SCXTNUM_ELx registers are supported and the contexts include the SCXTNUM_ELx register contexts.",
            "invalid(3)",
        }));
        printf("%.*sSpeculative use of out of context branch targets (CSV3): %s\n", spacing, SPACER, decode_nibble_at(value, 60, (const char* []){
            "This PE does not disclose whether data loaded under speculation with a permission or domain fault can be used to form an address or generate condition codes or SVE predicate values to be used by other instructions in the speculative sequence.",
            "Data loaded under speculation with a permission or domain fault cannot be used to form an address or generate condition codes or SVE predicate values to be used by other instructions in the speculative sequence.",
            "invalid(2)",
            "invalid(3)",
        }));
    }

    return ERR_SUCCESS;
}

int pfr1_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*sBranch Target Identification: %s\n", spacing, SPACER, decode_nibble_at(value, 0, generic_desc));
        printf("%.*sSpeculative Store Bypassing controls in AArch64 state: %s\n", spacing, SPACER, decode_nibble_at(value, 4, (const char* []){
            "Not implemented",
            "implemented, mark regions that are Speculative Store Bypass Safe.",
            "mark regions that are Speculative Store Bypassing Safe, and the MSR and MRS instructions to directly read and write the PSTATE.SSBS field.",
            "invalid(3)"
        }));
        printf("%.*sMemory Tagging Extension: %s\n", spacing, SPACER, decode_nibble_at(value, 8, (const char* []){
            "Not implemented",
            "implemented, Instructions only.",
            "Full Memory Tagging Extension is implemented.",
            "Memory Tagging Extension is implemented with support for asymmetric Tag Check Fault handling."
        }));
        printf("%.*sRAS: %s\n", spacing, SPACER, decode_nibble_at(value, 12, (const char* []){
            "0, If ID_AA64PFR0_EL1.RAS == 0b0001, RAS Extension implemented.",
            "If ID_AA64PFR0_EL1.RAS == 0b0001, as 0b0000 and adds support for: Additional ERXMISC<m>_EL1 System registers...",
            "invalid(2)",
            "invalid(3)"
        }));
        printf("%.*sMPAM: %s\n", spacing, SPACER, decode_nibble_at(value, 16, (const char* []){
            "0, If ID_AA64PFR0_EL1.MPAM == 0b0000, MPAM Extension not implemented; If ID_AA64PFR0_EL1.MPAM == 0b0001, MPAM Extension v1.0 is implemented.",
            "1, If ID_AA64PFR0_EL1.MPAM == 0b0000, implements MPAM v0.1, which is like v1.1 but reduces support for Secure PARTIDs; If ID_AA64PFR0_EL1.MPAM == 0b0001, implements MPAM v1.1 and adds support for MPAM2_EL2.TIDR to provide trapping of MPAMIDR_EL1 when MPAMHCR_EL2 is not present.",
            "invalid(2)",
            "invalid(3)"
        }));
        printf("%.*sCSV2: %s\n", spacing, SPACER, decode_nibble_at(value, 20, (const char* []){
            "0, This PE does not disclose whether branch targets trained in one hardware-described context can exploitatively control speculative execution in a different hardware-described context. The SCXTNUM_ELx registers are not supported.",
            "1, IIf ID_AA64PFR0_EL1.CSV2 is 0b0001, branch targets trained in one hardware-described context can exploitatively control speculative execution in a different hardware-described context only in a hard-to-determine way",
            "2, If ID_AA64PFR0_EL1.CSV2 is 0b0001, branch targets trained in one hardware-described context can exploitatively control speculative execution in a different hardware-described context only in a hard-to-determine way.",
            "invalid(3)"

        }));
        
    }
    return ERR_SUCCESS;
}

#define BIT_AT(n, bitname, v1, v2) printf("%.*s%s(%d): %s\n", spacing, SPACER, bitname, n, ((value >> 0) & 1) != 0 ? v1 : v2)

int scr_el3(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        BIT_AT(0, "NS",
               "EL0 and EL1 are in secure mode",
               "Lower than EL3 is non-secure"
               );
        BIT_AT(1, "IRQ",
               "When executing at Exception levels below EL3, physical IRQ interrupts are not taken to EL3. When executing at EL3, physical IRQ interrupts are not taken.",
               "When executing at any Exception level, physical IRQ interrupts are taken to EL3."
               );
        BIT_AT(2, "FIQ",
               "When executing at Exception levels below EL3, physical FIQ interrupts are not taken to EL3. When executing at EL3, physical FIQ interrupts are not taken.",
               "When executing at any Exception level, physical FIQ interrupts are taken to EL3."
               );
        BIT_AT(3, "EA",
               "When executing at Exception levels below EL3, External aborts and SError interrupts are not taken to EL3. In addition, when executing at EL3: SError interrupts are not taken. External aborts are taken to EL3.",
               "When executing at any Exception level, External aborts and SError interrupts are taken to EL3."
               );
        BIT_AT(7, "SMC",
               "SMC instructions are enabled at EL3, EL2 and EL1.",
               "SMC instructions are UNDEFINED."
               );
        // strange definition as it is opposite to SMC!
        BIT_AT(8, "HCE",
               "HVC instructions are UNDEFINED.",
               "HVC instructions are enabled at EL3, EL2, and EL1."
               );
        //TODO: continue...
    }
    return ERR_SUCCESS;
}

// ------------------------------

int sctlr_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "M", "MMU for EL1 is ",
               (const char* []){
                "(0) disabled.",
                "(1) Enabled.",
                }[((value >> 0) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "A", "Alignment check is ",
               (const char* []){
                "(0) disabled.",
                "(1) Enabled.",
                }[((value >> 1) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "C", "Data accesses are ",
               (const char* []){
                "(0) unached.",
                "(1) cached.",
                }[((value >> 2) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "SA", "SP Alignment check for EL1 is ",
               (const char* []){
                "(0) disabled.",
                "(1) Enabled.",
                }[((value >> 3) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "SA0", "SP Alignment check for EL0 is ",
               (const char* []){
                "(0) disabled.",
                "(1) Enabled.",
                }[((value >> 4) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "CP15BEN", "For AARCH32, execution of the CP15DMB, CP15DSB, and CP15ISB instructions is",
               (const char* []){
                "(0) undefined.",
                "(1) Enabled.",
                }[((value >> 5) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "UMA", "MSR at EL0",
               (const char* []){
                "(0) are trapped.",
                "(1) do not trigger any trap.",
                }[((value >> 9) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "I", "Instruction cacheability is ",
               (const char* []){
                "(0) disabled.",
                "(1) Enabled.",
                }[((value >> 12) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "DZE", " DC ZVA instructions at EL0",
               (const char* []){
                "(0) are trapped.",
                "(1) do not trigger any trap.",
                }[((value >> 14) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "UCT", "CTR_EL0 accesss at EL0",
               (const char* []){
                "(0) are trapped.",
                "(1) do not trigger any trap.",
                }[((value >> 15) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "nTWI", "WFI instructions at EL0",
               (const char* []){
                "(0) are trapped.",
                "(1) do not trigger any trap.",
                }[((value >> 16) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "nTWE", "WFE instructions at EL0",
               (const char* []){
                "(0) are trapped.",
                "(1) do not trigger any trap.",
                }[((value >> 18) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "nTWI", "WFI instructions at EL0",
               (const char* []){
                "(0) are trapped.",
                "(1) do not trigger any trap.",
                }[((value >> 16) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "WXN", "",
               (const char* []){
                "(0) no effect.",
                "(1) Any region that is writable in the EL1&0 translation regime is forced to XN for accesses from software executing at EL1&0.",
                }[((value >> 19) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "E0E", "Explicit data accesses at EL3, and stage 1 translation table walks in the EL1&0 translation regime are ",
               (const char* []){
                "(0) little-endian.",
                "(1) big-endian.",
                }[((value >> 24) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "EE", "Explicit data accesses at EL3, and stage 1 translation table walks in the EL1&0 translation regime are ",
               (const char* []){
                "(0) little-endian.",
                "(1) big-endian.",
                }[((value >> 25) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "UCI", "Cache maintenance instructions at EL0",
               (const char* []){
                "(0) are trapped.",
                "(1) do not trigger any trap.",
                }[((value >> 16) & 1)]
        );
    }
    return ERR_SUCCESS;
}


int sctlr_el3(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "M", "MMU for EL3 is ",
               (const char* []){
                "(0) disabled.",
                "(1) Enabled.",
                }[((value >> 0) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "A", "Alignment check is ",
               (const char* []){
                "(0) disabled.",
                "(1) Enabled.",
                }[((value >> 1) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "C", "Data accesses are ",
               (const char* []){
                "(0) unached.",
                "(1) cached.",
                }[((value >> 2) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "SA", "SP Alignment check is ",
               (const char* []){
                "(0) disabled.",
                "(1) Enabled.",
                }[((value >> 3) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "I", "Instruction cacheability is ",
               (const char* []){
                "(0) disabled.",
                "(1) Enabled.",
                }[((value >> 12) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "WXN", "",
               (const char* []){
                "(0) no effect.",
                "(1) Any region that is writable in the EL3 translation regime is forced to XN for accesses from software executing at EL3.",
                }[((value >> 19) & 1)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "EE", "Explicit data accesses at EL3, and stage 1 translation table walks in the EL3 translation regime are ",
               (const char* []){
                "(0) little-endian.",
                "(1) big-endian.",
                }[((value >> 19) & 1)]
        );
    }
    return ERR_SUCCESS;
}

// ------------------------------

int tcr_el1(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s%s, %s: %lld bits\n", spacing, SPACER, "T0SZ", "Size of TTBR0_EL1 region",
               64 - ((value >> 0) & 0x3f)
        );
        printf("%.*s%s: TLB miss triggers %s\n", spacing, SPACER, "EPD0", ((value >> 7) & 1) == 0 ? "page walk" : "translation fault");
        printf("%.*s%s: %s\n", spacing, SPACER, "IRGN0", (const char* []){
                "(0) Normal memory, Inner Non-cacheable.",
                "(1) Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable.",
                "(2) Normal memory, Inner Write-Through Read-Allocate No Write-Allocate Cacheable.",
                "(3) Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable."
                }[((value >> 8) & 3)]
        );
        printf("%.*s%s: %s\n", spacing, SPACER, "ORGN0", (const char* []){
                "(0) Normal memory, Inner Non-cacheable.",
                "(1) Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable.",
                "(2) Normal memory, Inner Write-Through Read-Allocate No Write-Allocate Cacheable.",
                "(3) Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable."
                }[((value >> 10) & 3)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "SH0", "Shareability attribute for TTBR0 table walks",
               (const char* []){
                "(0) Non-shareable.",
                "(1) Reserved.",
                "(2) Outer Shareable.",
                "(3) Inner Shareable."
                }[((value >> 12) & 3)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "TG0", "TTBR0 Granule size",
               (const char* []){
                "(0) 4KB.",
                "(1) 64KB.",
                "(2) 16KB.",
                "(3) Reserved."
                }[((value >> 14) & 3)]
        );
        printf("%.*s%s, %s: %lld bits\n", spacing, SPACER, "T1SZ", "Size of TTBR1_EL1 region",
               64 - ((value >> 16) & 0x3f)
        );
        printf("%.*s%s: ASID defined by %s\n", spacing, SPACER, "A1", ((value >> 22) & 1) == 0 ? "TTBR0" : "TTBR1");
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "TG1", "TTBR1 Granule size",
               (const char* []){
                "(0) 4KB.",
                "(1) 64KB.",
                "(2) 16KB.",
                "(3) Reserved."
                }[((value >> 30) & 3)]
        );
        printf("%.*s%s: TLB miss triggers %s\n", spacing, SPACER, "EPD1", ((value >> 23) & 1) == 0 ? "page walk" : "translation fault");
        printf("%.*s%s: %s\n", spacing, SPACER, "IRGN1", (const char* []){
                "(0) Normal memory, Inner Non-cacheable.",
                "(1) Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable.",
                "(2) Normal memory, Inner Write-Through Read-Allocate No Write-Allocate Cacheable.",
                "(3) Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable."
                }[((value >> 24) & 3)]
        );
        printf("%.*s%s: %s\n", spacing, SPACER, "ORGN1", (const char* []){
                "(0) Normal memory, Inner Non-cacheable.",
                "(1) Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable.",
                "(2) Normal memory, Inner Write-Through Read-Allocate No Write-Allocate Cacheable.",
                "(3) Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable."
                }[((value >> 26) & 3)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "SH1", "Shareability attribute for TTBR1 table walks",
               (const char* []){
                "(0) Non-shareable.",
                "(1) Reserved.",
                "(2) Outer Shareable.",
                "(3) Inner Shareable."
                }[((value >> 28) & 3)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "TG1", "TTBR1 granule size",
               (const char* []){
                "(0) 4KB.",
                "(1) 64KB.",
                "(2) 16KB.",
                "(3) Reserved."
                }[((value >> 30) & 3)]
        );
        printf("%.*s%s,%s: %s\n", spacing, SPACER, "IPS", "Intermediate Physical Address Size",
               (const char* []){
                "(0) 32 bits, 4GB.",
                "(1) 36 bits, 64GB.",
                "(2) 40 bits, 1TB.",
                "(3) 42 bits, 4TB",
                "(4) 44 bits, 16TB",
                "(5) 48 bits, 256TB",
                "(6) 52 bits, 4PB",
                "(7) undefined"
                }[((value >> 32) & 7)]
        );
        printf("%.*s%s: %s\n", spacing, SPACER, "AS", (const char* []){
                "(0) The upper 8 bits of TTBR0 and TTBR1 are ignored for TLB allocation and matching.",
                "(1) The upper 16 bits of TTBR0 and TTB1 are used for TLB allocation and matching.",
                }[((value >> 36) & 1)]
        );
        printf("%.*s%s: %s\n", spacing, SPACER, "TBI0", (const char* []){
                "(0) Top Byte used in the address calculation.",
                "(1) Top Byte ignored in the address calculation.",
                }[((value >> 37) & 1)]
        );
        printf("%.*s%s: %s\n", spacing, SPACER, "TBI1", (const char* []){
                "(0) Top Byte used in the address calculation.",
                "(1) Top Byte ignored in the address calculation.",
                }[((value >> 37) & 1)]
        );
    }
    return ERR_SUCCESS;
}

int tcr_el3(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    if (detail >= FULL) {
        spacing +=4;
        printf("%.*s%s, %s: %lld bits\n", spacing, SPACER, "T0SZ", "Size of TTBR0_EL3 region",
               64 - ((value >> 0) & 0x3f)
        );
        printf("%.*s%s: %s\n", spacing, SPACER, "IRGN0", (const char* []){
                "(0) Normal memory, Inner Non-cacheable.",
                "(1) Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable.",
                "(2) Normal memory, Inner Write-Through Read-Allocate No Write-Allocate Cacheable.",
                "(3) Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable."
                }[((value >> 8) & 3)]
        );
        printf("%.*s%s: %s\n", spacing, SPACER, "ORGN0", (const char* []){
                "(0) Normal memory, Inner Non-cacheable.",
                "(1) Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable.",
                "(2) Normal memory, Inner Write-Through Read-Allocate No Write-Allocate Cacheable.",
                "(3) Normal memory, Inner Write-Back Read-Allocate No Write-Allocate Cacheable."
                }[((value >> 10) & 3)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "SH0", "Shareability attribute for TTBR0 table walks",
               (const char* []){
                "(0) Non-shareable.",
                "(1) Reserved.",
                "(2) Outer Shareable.",
                "(3) Inner Shareable."
                }[((value >> 12) & 3)]
        );
        printf("%.*s%s, %s: %s\n", spacing, SPACER, "TG0", "TTBR0 Granule size",
               (const char* []){
                "(0) 4KB.",
                "(1) 64KB.",
                "(2) 16KB.",
                "(3) Reserved."
                }[((value >> 14) & 3)]
        );
        
        printf("%.*s%s,%s: %s\n", spacing, SPACER, "IPS", "Intermediate Physical Address Size",
               (const char* []){
                "(0) 32 bits, 4GB.",
                "(1) 36 bits, 64GB.",
                "(2) 40 bits, 1TB.",
                "(3) 42 bits, 4TB",
                "(4) 44 bits, 16TB",
                "(5) 48 bits, 256TB",
                "(6) 52 bits, 4PB",
                "(7) undefined"
                }[((value >> 16) & 7)]
        );
        printf("%.*s%s: %s\n", spacing, SPACER, "TBI", (const char* []){
                "(0) Top Byte used in the address calculation.",
                "(1) Top Byte ignored in the address calculation.",
                }[((value >> 20) & 1)]
        );
    }
    return ERR_SUCCESS;
}

// ------------------------------
// Common code



char* vcore_get_sys_reg_name(hv_sys_reg_t reg)
{
    int i = get_index(reg);
    if (i>=0) return sys_regs_metadata[i].name;
    return "unknown";
}

char* vcore_get_sys_reg_desc(hv_sys_reg_t reg)
{
    int i = get_index(reg);
    if (i>=0) return sys_regs_metadata[i].description;
    return "";
}

int vcore_print_sys_reg(hv_sys_reg_t reg, uint64_t value, int spacing, detail_t detail)
{
    int i = get_index(reg);
    if (i>=0) {
        if (detail == SHORT || detail == NONZERO) {
            if ((value != 0 && detail == NONZERO) || (detail == SHORT)) printf("%.*s%s=%llx\n", spacing, SPACER, sys_regs_metadata[i].name, value);
        }
        else {
            if (((detail & NONZERO) && value !=0) || !(detail & NONZERO)) {
                printf("%.*s%s=%llx %s\n", spacing, SPACER, sys_regs_metadata[i].name, value, sys_regs_metadata[i].description);
                detail &= ~NONZERO;
                if (detail == DETAILED || detail == FULL) {
                    formatter_f formatter = sys_regs_metadata[i].formatter != NULL ? sys_regs_metadata[i].formatter : not_implemented;
                    formatter(reg, value,   spacing, detail);
                }
            }
        }
        return ERR_SUCCESS;
    }
    printf("Unknown register %x\n", (int)reg);
    return ERR_SUCCESS;
}

#define FORMAT_1DIGIT  " x%d=%016llx "
#define FORMAT_2DIGITS  "x%d=%016llx "
int vcore_print_general_regs(vcore_t* vcore, int spacing)
{
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    int i, j;
    uint64_t value;
    for (i=0; i<4; i++) {
        printf("%.*s", spacing, SPACER);
        for (j=0; j<7; j++) {
            int reg_index = i*7+j;
            hv_vcpu_get_reg(vcpu, reg_index, &value);
            printf(reg_index < 10 ? FORMAT_1DIGIT : FORMAT_2DIGITS, reg_index, value);
        }
        printf("\n");
    }
    gva_t fp, lr, pc;
    uint64_t cpsr;
    hv_vcpu_get_reg(vcpu, HV_REG_X28, &value);
    hv_vcpu_get_reg(vcpu, HV_REG_FP, &fp);
    hv_vcpu_get_reg(vcpu, HV_REG_LR, &lr);
    hv_vcpu_get_reg(vcpu, HV_REG_PC, &pc);
    hv_vcpu_get_reg(vcpu, HV_REG_CPSR, &cpsr);
    printf("%.*sx28=%016llx\n", spacing, SPACER, value);
    printf("%.*s FP=%016llx  LR=%016llx  PC=%016llx\n", spacing, SPACER, fp, lr, pc);
    printf("%.*sCPSR=%016llx\n", spacing, SPACER, cpsr);
    gva_t sp_el0, sp_el1;
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL0, &sp_el0);
    hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_SP_EL1, &sp_el1);
    printf("%.*s SP0=%016llx  SP1=%016llx\n", spacing, SPACER, sp_el0, sp_el1);
    return ERR_SUCCESS;
}

int vcore_print_sys_regs(vcore_t* vcore, int spacing, detail_t detail)
{
    int i;
    hv_vcpu_t vcpu = vcore->vcpu_handle;
    int register_count = vcore_get_sys_reg_count();
    for(i = 0; i < register_count; i++) {
        if (sys_regs_metadata[i].id == 0) continue; // we hit the marker
        uint64_t value=0;
        if (sys_regs_metadata[i].minimal_el > 1) {
            value = sys_regs_metadata[i].value;
        }
        else {
            hv_vcpu_get_sys_reg(vcpu, sys_regs_metadata[i].id, &value);
        }
        vcore_print_sys_reg( sys_regs_metadata[i].id, value, spacing, detail);
    }
    return ERR_SUCCESS;
}
