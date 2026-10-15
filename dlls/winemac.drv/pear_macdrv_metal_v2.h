/* Original Pear private native driver contract. SPDX-License-Identifier: MIT. */
#ifndef PEAR_MACDRV_METAL_V2_H
#define PEAR_MACDRV_METAL_V2_H
#include "pear_macdrv_metal_v1.h"
#define PEAR_METAL_V2_VERSION 2u
#define PEAR_METAL_V2_FEATURES UINT64_C(15)
struct pear_macdrv_metal_v2 {
    uint32_t version, bytes;
    uint64_t features;
    int32_t (*acquire)(uint64_t, uint64_t, uint64_t *);
    int32_t (*query)(uint64_t, struct pear_metal_query_v1 *);
    int32_t (*release)(uint64_t);
    int32_t (*with_layer)(uint64_t, pear_metal_layer_operation, void *);
    int32_t (*acquire_window)(uint64_t, uint64_t, uint64_t *);
};
typedef int32_t (*pear_metal_v2_get_interface)(uint32_t,uint32_t,uint64_t,const struct pear_macdrv_metal_v2 **);
_Static_assert(sizeof(struct pear_macdrv_metal_v2)==56,"native v2 table size");
_Static_assert(offsetof(struct pear_macdrv_metal_v2,acquire_window)==48,"native v2 table tail");
#endif
