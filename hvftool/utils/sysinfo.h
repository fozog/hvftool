/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */




#ifndef sysinfo_h
#define sysinfo_h

struct fdt_string;

struct cpu_node;
struct cpu_cluster;

typedef struct cpu_node {
    struct cpu_node* next;
    int id;
    char* name;
    struct fdt_string* compatible;
    struct cpu_cluster* cluster;
    bool used;
} cpu_node_t;

typedef struct cpu_cluster {
    struct cpu_cluster* next;
    int id;
    char type;
    cpu_node_t* sibblings;
} cpu_cluster_t;

cpu_node_t* cpu_find_bycluster(char type, int cpu_id);
bool is_hvf_supported(void);
int cpuinfo_prepare(void);

#endif /* sysinfo_h */
