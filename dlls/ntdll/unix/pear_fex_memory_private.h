/* Original Pear bounded owner implementation interface. MIT-licensed.
 * Callback pointers never occur in the private PE wire record. */
#ifndef __PEAR_FEX_MEMORY_PRIVATE_H
#define __PEAR_FEX_MEMORY_PRIVATE_H
#include "wine/pear_fex_memory.h"

struct pear_fex_memory_error {
    uint32_t domain;
    int32_t code;
};
struct pear_fex_memory_backing {
    uint64_t owner_pid, private_base, shared_offset, dispatcher_offset;
    uint64_t capabilities;
};
struct pear_fex_memory_backend {
    int (*initialize)(struct pear_fex_memory_backing *, struct pear_fex_memory_error *);
    int (*query)(uint64_t, uint64_t, uint32_t, struct pear_fex_memory_error *);
    int (*protect)(uint64_t, uint64_t, uint32_t, struct pear_fex_memory_error *);
    int (*ec_register)(uint64_t, uint64_t, int, struct pear_fex_memory_error *);
    int (*view)(uint64_t extent_offset, uint64_t extent_size,
                uint64_t allocation_id, uint64_t generation,
                uint32_t allocation_class, uint32_t source_role, int reserve,
                struct pear_fex_memory_error *);
    int (*role)(uint32_t);
    /* The wire operation_size is independently fixed at4 by the core. */
    int (*entry)(uint64_t extent_offset, uint64_t usable_extent_size,
                 uint64_t entry_offset, uint32_t allocation_class, uint32_t source_role);
    int (*metadata)(struct pear_fex_memory_metadata *, struct pear_fex_memory_error *);
};

/* Initialization binds one immutable backend and real owner process. It does
 * not establish rights: the supervisor must admit this exact executable first.
 * Native core calls return the finite bridge status; backend callbacks return
 * zero only after their named operation and observation actually succeed. */
uint32_t pear_fex_memory_initialize(const struct pear_fex_memory_backend *,
                                    struct pear_fex_memory_error *);
uint32_t pear_fex_memory_dispatch(const struct pear_fex_memory_request *,
                                  struct pear_fex_memory_response *);
/* Call only from a compiled native gate outside the owner mapping. A managed
 * executor first performs HANDOFF, retaining a checked source continuation;
 * this function acknowledges native parking and waits for the closed writer.
 * It never releases an active lease merely because it was called. */
uint32_t pear_fex_memory_poll(uint64_t executor_id);

/* Actual source-bound backing functions supplied by pear_pe_arena.c. Offsets
 * are relative to its aligned interior, not caller-selected raw addresses. */
int pear_fex_backing_initialize(struct pear_fex_memory_backing *, struct pear_fex_memory_error *);
int pear_fex_backing_query(uint64_t, uint64_t, uint32_t, struct pear_fex_memory_error *);
int pear_fex_backing_protect(uint64_t, uint64_t, uint32_t, struct pear_fex_memory_error *);
int pear_fex_backing_metadata(struct pear_fex_memory_metadata *, uint64_t *mapping_base,
                              struct pear_fex_memory_error *);
#endif
