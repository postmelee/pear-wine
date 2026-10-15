/* Original Pear private native driver contract. SPDX-License-Identifier: MIT. */
#ifndef PEAR_MACDRV_METAL_V1_H
#define PEAR_MACDRV_METAL_V1_H
#include <stdint.h>
#include <stddef.h>
#define PEAR_METAL_VERSION 1u
#define PEAR_METAL_FEATURES UINT64_C(7)
#define PEAR_METAL_CAPACITY 64u
enum pear_metal_status {
    PEAR_METAL_OK=0, PEAR_METAL_ARGUMENT=1, PEAR_METAL_VERSION_ERROR=2,
    PEAR_METAL_SIZE=3, PEAR_METAL_FEATURE_ERROR=4, PEAR_METAL_WINDOW=5,
    PEAR_METAL_NO_CLIENT=6, PEAR_METAL_DEVICE=7, PEAR_METAL_VIEW=8,
    PEAR_METAL_LAYER=9, PEAR_METAL_STALE=10, PEAR_METAL_OWNER_CONFLICT=11,
    PEAR_METAL_CAPACITY_ERROR=12, PEAR_METAL_NATIVE_EXCEPTION=13
};
struct pear_metal_query_v1 {
    uint32_t bytes, state;
    uint64_t generation;
    double drawable_width, drawable_height;
};
typedef void (*pear_metal_layer_operation)(void *, uint64_t);
struct pear_macdrv_metal_v1 {
    uint32_t version, bytes;
    uint64_t features;
    int32_t (*acquire)(uint64_t, uint64_t, uint64_t *);
    int32_t (*query)(uint64_t, struct pear_metal_query_v1 *);
    int32_t (*release)(uint64_t);
    int32_t (*with_layer)(uint64_t, pear_metal_layer_operation, void *);
};
typedef int32_t (*pear_metal_get_interface)(uint32_t,uint32_t,uint64_t,const struct pear_macdrv_metal_v1 **);
_Static_assert(sizeof(void *)==8,"selected native Darwin ABI only");
_Static_assert(sizeof(struct pear_macdrv_metal_v1)==48,"native table size");
_Static_assert(offsetof(struct pear_macdrv_metal_v1,acquire)==16,"native table prefix");
_Static_assert(offsetof(struct pear_macdrv_metal_v1,with_layer)==40,"native table tail");
_Static_assert(sizeof(struct pear_metal_query_v1)==32,"native query size");
#endif
