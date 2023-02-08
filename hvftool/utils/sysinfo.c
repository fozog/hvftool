/*
 * Created by Francois-Frederic Ozog.
 *
 * SPDX-License-Identifier: Mozilla Public License 2.0
 *
 * Copyright © 2022 Shokubai.tech. All rights reserved.
 */



#include <errno.h>
#include <sys/sysctl.h>

#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>

#include "sysinfo.h"
#include "fdt.h"

#define DT_PLANE "IODeviceTree"

static cpu_cluster_t* clusters = {0};

bool is_hvf_supported(void)
{
    uint64_t hv_support;
    size_t hv_support_size = sizeof(hv_support);
    if (sysctlbyname("kern.hv_support", &hv_support, &hv_support_size, NULL, 0) != 0) {
        printf("Could not read Hypervisor Framework support: %s\n", strerror(errno));
        return false;
    };
    if (hv_support == 0) {
        printf("Hypervisor Framework not supported on this OS version\n");
        return false;
    };

    return true;
}

static cpu_cluster_t* add_cluster(int id, char type)
{
    cpu_cluster_t* cluster = malloc(sizeof(cpu_cluster_t));
    memset(cluster, 0, sizeof(cpu_cluster_t));
    cluster->id = id;
    cluster->type = type;
    // add tail
    if (clusters == NULL) {
        clusters=cluster;
        return cluster;
    }
    cpu_cluster_t* current = clusters;
    while (current->next != NULL) {
        current = current->next;
    }
    current->next = cluster;
    return cluster;
}

static cpu_cluster_t* find_add_cluster(int id, char type)
{
    if (clusters == NULL) return add_cluster(id, type);
    cpu_cluster_t* current = clusters;
    while (current != NULL) {
        if (current->id == id) return current;
        current = current->next;
    }
    return add_cluster(id, type);
}

cpu_node_t* cluster_add_cpu(cpu_cluster_t* cluster, int cpu_id, char* cpu_name, fdt_string_t* cpu_compatible)
{
    cpu_node_t* node = malloc(sizeof(cpu_node_t));
    if (node == NULL) return NULL;
    memset(node, 0, sizeof(cpu_node_t));
    node->id = cpu_id;
    node->name = cpu_name;
    node->compatible = cpu_compatible;
    // add tail
    if (cluster->sibblings == NULL) {
        cluster->sibblings = node;
        return node;
    }
    cpu_node_t* current = cluster->sibblings;
    while(current->next != NULL) {
        current = current->next;
    }
    current->next = node;
    return node;
}

cpu_node_t* cpu_find_bycluster(char type, int cpu_id)
{
    if (clusters == NULL) return NULL;
    cpu_cluster_t* current = clusters;
    while (current != NULL) {
        if (current->type == type || type == ' ') break;
        current = current->next;
    }
    if (current == NULL) return NULL;
    cpu_node_t* current_node = current->sibblings;
    for(;current_node != NULL; current_node = current_node->next) {
        if (current_node->id==cpu_id || cpu_id == -1) {
            if (current_node->used && cpu_id==-1) continue; // find the next free one
            if (current_node->used) return NULL;
            return current_node;
        }
    }
    return NULL;

}

int cpuinfo_prepare(void)
{
    io_registry_entry_t cpus_root;
    io_iterator_t cpus_iter;
    io_registry_entry_t cpus_child;
    kern_return_t kret;

    cpus_root = IORegistryEntryFromPath(kIOMainPortDefault, DT_PLANE ":/cpus");
    if (!cpus_root) return -ENOTSUP;

    kret = IORegistryEntryGetChildIterator(cpus_root, DT_PLANE, &cpus_iter);
    if (kret != KERN_SUCCESS) return -ENOTSUP;

    while ((cpus_child = IOIteratorNext(cpus_iter)) != 0)
    {
        io_name_t name;
        CFTypeRef ref;
        uint8_t buffer[64];
        
        kret = IORegistryEntryGetNameInPlane(cpus_child, DT_PLANE, name);
        if (kret != KERN_SUCCESS) continue;


        long long cluster_id;
        ref = IORegistryEntrySearchCFProperty(cpus_child, DT_PLANE, CFSTR("logical-cluster-id"), kCFAllocatorDefault, kNilOptions);
        if (!ref || CFGetTypeID(ref) != CFNumberGetTypeID()) return -ENOTSUP;
        if (!CFNumberGetValue(ref, kCFNumberLongLongType, &cluster_id)) return -ENOTSUP;
        //printf("got logical-cluster-id  %lld\n", value);
        CFRelease(ref);

        char cluster_type;
        ref = IORegistryEntrySearchCFProperty(cpus_child, DT_PLANE, CFSTR("cluster-type"), kCFAllocatorDefault, kNilOptions);
        if (!ref || CFGetTypeID(ref) != CFDataGetTypeID()) return -ENOTSUP;
        CFDataGetBytes(ref, CFRangeMake(0, CFDataGetLength(ref)), buffer);
        cluster_type = buffer[0];
        //printf("got cluster-type %c\n", buffer[0]);
        CFRelease(ref);

        cpu_cluster_t* cluster = find_add_cluster((int)cluster_id, cluster_type);
        if (cluster == NULL) return  -ENOMEM;
        
        long long cpu_id;
        ref = IORegistryEntrySearchCFProperty(cpus_child, DT_PLANE, CFSTR("logical-cpu-id"), kCFAllocatorDefault, kNilOptions);
        if (!ref || CFGetTypeID(ref) != CFNumberGetTypeID()) return -ENOTSUP;
        if (!CFNumberGetValue(ref, kCFNumberLongLongType, &cpu_id)) return -ENOTSUP;
        //printf("got logical-cpu-id %lld\n", cpu_id);
        CFRelease(ref);

        char* cpu_name;
        ref = IORegistryEntrySearchCFProperty(cpus_child, DT_PLANE, CFSTR("name"), kCFAllocatorDefault, kNilOptions);
        if (!ref || CFGetTypeID(ref) != CFDataGetTypeID()) return -ENOTSUP;
        CFDataGetBytes(ref, CFRangeMake(0, CFDataGetLength(ref)), buffer);
        cpu_name = strdup((char*)buffer);
        //printf("got name %s\n", buffer);
        CFRelease(ref);

        fdt_string_t* cpu_compatible;
        ref = IORegistryEntrySearchCFProperty(cpus_child, DT_PLANE, CFSTR("compatible"), kCFAllocatorDefault, kNilOptions);
        if (!ref || CFGetTypeID(ref) != CFDataGetTypeID()) return -ENOTSUP;
        CFDataGetBytes(ref, CFRangeMake(0, CFDataGetLength(ref)), buffer);
        cpu_compatible = fdt_wrap(buffer, (int)CFDataGetLength(ref));
        //printf("got compatible %s\n", buffer);
        CFRelease(ref);

        
        cpu_node_t* node = cluster_add_cpu(cluster, (int)cpu_id, cpu_name, cpu_compatible);
        if (node==NULL) return -ENOMEM;
        node->cluster = cluster;
        
        IOObjectRelease(cpus_child);
        
    }
    
    IOObjectRelease(cpus_iter);
    IOObjectRelease(cpus_root);

    return ERR_SUCCESS;;
}
