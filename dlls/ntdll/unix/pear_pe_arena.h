/* Original Pear native PE publication owner, MIT-licensed.
 * Internal to ntdll's Unix half; callers hold virtual_mutex. */
#ifndef __PEAR_PE_ARENA_H
#define __PEAR_PE_ARENA_H

/* Installed Stage 4 ARM64 fixture adds one measured 64 KiB image slot. */
#define PEAR_ARENA_INTERIOR_BYTES ((SIZE_T)1050345472)
#define PEAR_ARENA_ALIGNMENT ((SIZE_T)65536)
/* Dynamic allocations have a separate finite budget in the SAME MAP_JIT. */
#define PEAR_ARENA_DYNAMIC_SLOTS 8u
#define PEAR_ARENA_DYNAMIC_SLOT_BYTES ((SIZE_T)65536)
#define PEAR_ARENA_DYNAMIC_BYTES ((SIZE_T)524288)
#define PEAR_ARENA_TOTAL_BYTES (PEAR_ARENA_INTERIOR_BYTES + PEAR_ARENA_DYNAMIC_BYTES)
/* Keep TOTAL/PAGES as the immutable baseline PE + dynamic metadata bound. */
#include "wine/pear_fex_memory.h"
#define PEAR_ARENA_FEX_SHARED_OFFSET (PEAR_ARENA_TOTAL_BYTES + PEAR_FEX_MEMORY_SEPARATOR_BYTES)
#define PEAR_ARENA_FEX_DISPATCHER_OFFSET (PEAR_ARENA_FEX_SHARED_OFFSET + PEAR_FEX_MEMORY_SHARED_BYTES + PEAR_FEX_MEMORY_SEPARATOR_BYTES)
#define PEAR_ARENA_MAPPING_BYTES (PEAR_ARENA_FEX_DISPATCHER_OFFSET + PEAR_FEX_MEMORY_DISPATCHER_BYTES + PEAR_ARENA_ALIGNMENT)
_Static_assert(PEAR_ARENA_MAPPING_BYTES == UINT64_C(1588985856), "Approved single-MAP_JIT geometry");
#define PEAR_ARENA_MAX_IMAGE_BYTES ((SIZE_T)67108864)
#define PEAR_ARENA_MAX_SLOTS 756u
/* Two simultaneously owned copies of the original relocation fixture. */
#define PEAR_ARENA_RELOCATION_COPIES 2u
#define PEAR_ARENA_PAGE_BYTES ((SIZE_T)4096)

extern NTSTATUS pear_pe_diagnostic(int fd, const char *phase, NTSTATUS status);

struct pear_pe_plan;
struct pear_pe_slot;
struct pear_dynamic_slot;

enum pear_pe_role { PEAR_PE_ROLE_NATIVE = 1, PEAR_PE_ROLE_ARM64EC, PEAR_PE_ROLE_GUEST_X64 };

struct pear_pe_image
{
    SIZE_T size;
    ULONGLONG original_base;
    ULONG entry_rva;
    USHORT machine;
    enum pear_pe_role role;
    ULONG chpe_rva, native_entry_rva, original_entry_rva;
    USHORT original_machine;
};

extern BOOL pear_pe_arena_enabled(void);
extern BOOL pear_pe_arena_overlaps(const void *base, SIZE_T size);
extern NTSTATUS pear_pe_arena_initialize(void **base, SIZE_T *size);
extern NTSTATUS pear_pe_plan_read(int fd, struct pear_pe_plan **plan, struct pear_pe_image *image);
extern NTSTATUS pear_pe_plan_read_target(int fd, USHORT target, struct pear_pe_plan **plan, struct pear_pe_image *image);
extern void pear_pe_plan_free(struct pear_pe_plan *plan);
extern NTSTATUS pear_pe_slot_reserve(const struct pear_pe_plan *plan, ULONG_PTR low, ULONG_PTR high,
                                    struct pear_pe_slot **slot, void **base, SIZE_T *capacity);
extern ULONGLONG pear_pe_slot_generation(const struct pear_pe_slot *slot);
extern NTSTATUS pear_pe_slot_publish(struct pear_pe_slot *slot, ULONGLONG generation, struct pear_pe_plan *plan);
extern void pear_pe_slot_retire(struct pear_pe_slot *slot, ULONGLONG generation);
extern NTSTATUS pear_pe_slot_protect(struct pear_pe_slot *slot, ULONGLONG generation, const void *base, SIZE_T size, BYTE vprot);
extern BYTE pear_pe_slot_vprot(const struct pear_pe_slot *slot, ULONGLONG generation, SIZE_T offset);
extern BOOL pear_pe_arena_matches_protection(const void *base, SIZE_T size, int protection);
extern void DECLSPEC_NORETURN pear_pe_arena_fatal(const char *operation);

extern NTSTATUS pear_dynamic_reserve(SIZE_T size, struct pear_dynamic_slot **slot, void **base);
extern ULONGLONG pear_dynamic_generation(const struct pear_dynamic_slot *slot);
extern NTSTATUS pear_dynamic_protect(struct pear_dynamic_slot *slot, ULONGLONG generation,
                                    const void *base, SIZE_T size, BYTE vprot, BOOL commit);
extern NTSTATUS pear_dynamic_decommit(struct pear_dynamic_slot *slot, ULONGLONG generation,
                                     const void *base, SIZE_T size);
extern NTSTATUS pear_dynamic_release(struct pear_dynamic_slot *slot, ULONGLONG generation);
extern BOOL pear_dynamic_free_range(const void *base, void **start, void **end);

#endif
