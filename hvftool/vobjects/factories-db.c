/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */

#include <errno.h>
#include <string.h>

#include "vobjects.h"
#include "backends.h"

#define MAX_VOBJECT_TYPES 16
static vobject_factory_t* vobject_types_db[MAX_VOBJECT_TYPES] = { 0 };
static int types_count = 0;


vobject_factory_t* vobjtype_lookup(const char* key) {
    int i;
    for (i = 0; i < types_count; i++ ) {
        if (strcasecmp(key, vobject_types_db[i]->key) == 0) return vobject_types_db[i];
    }
    return NULL;
}

int vobjtype_register(vobject_factory_t* e)
{
    if (types_count >= MAX_VOBJECT_TYPES - 1) return -ENOMEM;
    vobject_types_db[types_count++] = e;
    return ERR_SUCCESS;
}

// lets not expose those functions.
extern int pl011_init(void);
extern int ram_init(void);
extern int sec_ram_init(void);
int cfi_init(void);
int psci_init(void);
int cpu_init(void);
int fixed_clock_init(void);
int gic_init(void);

int vobjtypes_init(void)
{
    int result=0;
    if ((result = pl011_init()) < 0) return result;
    if ((result = ram_init()) < 0) return result;
    if ((result = sec_ram_init()) < 0) return result;
    if ((result = cfi_init()) < 0) return result;
    if ((result = psci_init()) < 0) return result;
    if ((result = cpu_init()) < 0) return result;
    if ((result = fixed_clock_init()) < 0) return result;
    if ((result = gic_init()) < 0) return result;
    return result;
}
