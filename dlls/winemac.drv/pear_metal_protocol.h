/* Original Pear finite pairing fixture. SPDX-License-Identifier: MIT. */
#ifndef PEAR_METAL_PROTOCOL_H
#define PEAR_METAL_PROTOCOL_H
#include <stdint.h>
#define PEAR_PAIRING_MAGIC UINT32_C(0x504d5431)
enum pear_pairing_operation { PEAR_PAIRING_INIT=1,PEAR_PAIRING_RUN=2,PEAR_PAIRING_RESIZE=3,PEAR_PAIRING_DETACH=4,PEAR_PAIRING_DESTROYED=5,PEAR_PAIRING_FINAL=6 };
struct pear_pairing_request {
    uint32_t magic,version,bytes,operation;
    uint64_t hwnd,cycle,guest_teb,guest_tid;
    int32_t status,expected_status;
    uint64_t native_tid,x18_entry,x18_exit,lease_count,attachment_count,case_count,width,height,flags;
};
_Static_assert(sizeof(struct pear_pairing_request)==128,"fixed finite fixture request");
#endif
