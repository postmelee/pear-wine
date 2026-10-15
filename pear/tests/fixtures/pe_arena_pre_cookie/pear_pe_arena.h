/* Original Pear native PE publication owner, MIT-licensed.
 * Internal to ntdll's Unix half; callers hold virtual_mutex. */
#ifndef __PEAR_PE_ARENA_H
#define __PEAR_PE_ARENA_H

#define PEAR_ARENA_INTERIOR_BYTES ((SIZE_T)1049952256)
#define PEAR_ARENA_ALIGNMENT ((SIZE_T)65536)
#define PEAR_ARENA_MAPPING_BYTES (PEAR_ARENA_INTERIOR_BYTES + PEAR_ARENA_ALIGNMENT)
#define PEAR_ARENA_MAX_IMAGE_BYTES ((SIZE_T)38993920)
#define PEAR_ARENA_MAX_SLOTS 752u
#define PEAR_ARENA_PAGE_BYTES ((SIZE_T)4096)

struct pear_pe_plan;
struct pear_pe_slot;

struct pear_pe_image
{
    SIZE_T size;
    ULONGLONG original_base;
    ULONG entry_rva;
    USHORT machine;
};

extern BOOL pear_pe_arena_enabled(void);
extern BOOL pear_pe_arena_overlaps(const void *base, SIZE_T size);
extern NTSTATUS pear_pe_arena_initialize(void **base, SIZE_T *size);
extern NTSTATUS pear_pe_plan_read(int fd, struct pear_pe_plan **plan, struct pear_pe_image *image);
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

#endif
