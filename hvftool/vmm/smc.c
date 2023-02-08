/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */


#include <stdlib.h>
#include <errno.h>

#include "smc.h"

#define MAX_RANGES  64

static smc_range_t* ranges[MAX_RANGES];
static int range_count=0;


smc_range_t* smc_lookup(gpa_t address) {
    int i;
    for (i = 0; i < range_count; i++ ) {
        if (address >= ranges[i]->start && address < ranges[i]->end) return ranges[i];
    }
    return NULL;
}

int smc_add_range(smc_range_t* range)
{
    if (range_count >= MAX_RANGES -1) return -ENODEV;
    ranges[range_count++] = range;
    return ERR_SUCCESS;
}

smc_range_t* smc_assign_at(gpa_t address, size_t range_size)
{
    smc_range_t* range = malloc(sizeof(smc_range_t));
    if (range == NULL) return NULL;
    range->start = address;
    range->end = range->start + range_size;
    if (smc_add_range(range) < 0) {
        free(range);
        return NULL;
    }
    return range;
}

