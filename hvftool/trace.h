/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#ifndef trace_h
#define trace_h

#include <sys/unistd.h>

#include "hvftool.h"

#define DEBUG_EXIT              0x0001
#define DEBUG_EXCEPTION         0x0002
#define DEBUG_PREPARE_VM        0x0004
#define DEBUG_PREPARE_PROGRAM   0x0008
#define DEBUG_REBASE            0x0010
#define DEBUG_LINKEDIT          0x0020
#define DEBUG_MMIO              0x0040
#define DEBUG_IA                0x0080
#define VERBOSE_STARTUP         0x0100
#define DEBUG_PL011             0x0200
#define DEBUG_DEVICE            0x0400
#define DEBUG_RAM               0x0800
#define DEBUG_FDT               0x1000
#define DEBUG_CFI_OPERATIONS    0x2000
#define DEBUG_GIC               0x4000
#define DEBUG_GIC_FULL          0x8000
#define DEBUG_PSCI              0x10000

extern uint64_t trace_bitmap;

#define VA_ARGS(...) , ##__VA_ARGS__
#define TRACE(what, format, ...) {if ((hvftool_config.trace_bitmap & (what)) != 0) printf(format VA_ARGS(__VA_ARGS__)); }
#define TRACE_BEGIN(what)   if ((hvftool_config.trace_bitmap & (what)) != 0) {
#define TRACE_END           }



#endif /* trace_h */
