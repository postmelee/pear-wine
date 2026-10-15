/* Original Pear native PE publication owner, MIT-licensed.
 * Reuses Wine's PE definitions, section mapping rules and unsigned DIR64
 * relocation arithmetic. The bounded ownership/page-W^X protocol follows the
 * original Pear native prerequisite; no Wine/FEX runtime qualification follows
 * from that separate experiment. All entry points run under virtual_mutex.
 *
 * One MAP_JIT allocation starts NONE and never becomes RWX. Ordinary holes are
 * one-way backing conversions. Code is prepared RW before publication as RX,
 * and retired NONE before compatible reuse. Generations protect owner handles,
 * not arbitrary guest pointers. There is no independent translator allocator.
 */
#if 0
#pragma makedep unix
#endif
#include "config.h"
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
#include "ntstatus.h"
#include "windef.h"
#include "winnt.h"
#include "winternl.h"
#include "wine/debug.h"
#include "pear_pe_arena.h"
#include "wine/pear_bootstrap.h"

WINE_DEFAULT_DEBUG_CHANNEL(virtual);

#define PAGE PEAR_ARENA_PAGE_BYTES
#define PAGES (PEAR_ARENA_TOTAL_BYTES / PAGE)
#define PV_READ 0x01
#define PV_WRITE 0x02
#define PV_EXEC 0x04
#define PV_COPY 0x08
#define PV_COMMITTED 0x20
#define PAGE_USED 0x80
#define MAX_SECTIONS 96u
/* A complete 8-byte destination cannot occur more than once per image. */
#define MAX_RELOCATIONS (PEAR_ARENA_MAX_IMAGE_BYTES / sizeof(ULONGLONG))
enum backing { VIRGIN, CODE, ORDINARY, DYNAMIC };
enum slot_state { SLOT_RESERVED, SLOT_PREPARING, SLOT_PUBLISHED, SLOT_FAILED, SLOT_RETIRED };
struct pear_pe_plan
{
    unsigned char *staging, *pages;
    ULONG *relocations;
    SIZE_T size, capacity, page_count, relocation_count, header_bytes;
    SIZE_T nt_offset;
    ULONGLONG original_base;
    BOOL relocated;
    enum pear_pe_role role;
};
struct pear_pe_slot
{
    SIZE_T offset, capacity, image_size;
    ULONGLONG generation, original_base;
    enum slot_state state;
    enum pear_pe_role role;
};
struct pear_dynamic_slot
{
    SIZE_T size;
    ULONGLONG generation;
    BOOL active;
};
static struct
{
    unsigned char *mapping, *interior;
    unsigned char *classes, *protection, *vprot;
    struct pear_pe_slot slots[PEAR_ARENA_MAX_SLOTS];
    struct pear_dynamic_slot dynamic[PEAR_ARENA_DYNAMIC_SLOTS];
    unsigned int count;
    SIZE_T used;
    BOOL attempted;
    pid_t owner_pid;
    unsigned long long sequence, dynamic_sequence;
} arena;

/* Events are opt-in owned diagnostics. They do not authorize execution. */
static void arena_event(const char *event, const char *format, ...)
{
    char fields[1536], detail[1664];
    int saved = errno, count;
    va_list args;
    if (!getenv("PEAR_STAGE3_CONTROL")) return;
    va_start(args, format);
    count = vsnprintf(fields, sizeof(fields), format, args);
    va_end(args);
    if (count < 0 || count >= sizeof(fields)) _exit(125);
    count = snprintf(detail, sizeof(detail), ",\"policy\":\"page-wx\",\"arena_sequence\":%llu%s",
                     ++arena.sequence, fields);
    if (count < 0 || count >= sizeof(detail)) _exit(125);
    pear_bootstrap_event("loader", event, detail);
    errno = saved;
}

/* Independent stream: Stage 3 image events keep their original sequence. */
static void dynamic_event(const char *event, const char *format, ...)
{
    char fields[1536], detail[1664];
    int saved = errno, count;
    va_list args;
    if (!getenv("PEAR_STAGE3_CONTROL")) return;
    va_start(args, format);
    count = vsnprintf(fields, sizeof(fields), format, args);
    va_end(args);
    if (count < 0 || count >= sizeof(fields)) _exit(125);
    count = snprintf(detail, sizeof(detail), ",\"policy\":\"page-wx\",\"dynamic_sequence\":%llu%s",
                     ++arena.dynamic_sequence, fields);
    if (count < 0 || count >= sizeof(detail)) _exit(125);
    pear_bootstrap_event("loader", event, detail);
    errno = saved;
}

static BOOL actual_protection(const void *pointer, SIZE_T bytes, int protection)
{
#ifdef __APPLE__
    mach_vm_address_t cursor = (mach_vm_address_t)pointer, end = cursor + bytes;
    if (end < cursor) return FALSE;
    while (cursor < end)
    {
        mach_vm_address_t address = cursor;
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info = {0};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t result = mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                                              (vm_region_info_t)&info, &count, &object);
        if (object != MACH_PORT_NULL && mach_port_deallocate(mach_task_self(), object) != KERN_SUCCESS)
            return FALSE;
        if (result != KERN_SUCCESS || address > cursor || !size || address > ~(mach_vm_address_t)0 - size ||
            address + size <= cursor || info.protection != protection ||
            (info.max_protection & protection) != protection) return FALSE;
        cursor = min(address + size, end);
    }
    return TRUE;
#else
    return FALSE;
#endif
}

static void require_owner(void)
{
    if (arena.mapping && arena.owner_pid != getpid()) pear_pe_arena_fatal("inherited_owner");
}

BOOL pear_pe_arena_enabled(void)
{
#if defined(PEAR_NATIVE_PE_PUBLICATION) && defined(__APPLE__) && defined(__aarch64__)
    return TRUE;
#else
    return FALSE;
#endif
}

void DECLSPEC_NORETURN pear_pe_arena_fatal(const char *operation)
{
    arena_event("arena_failure", ",\"operation\":\"%s\",\"status\":%u,\"errno\":%d,\"slot\":-1,\"slot_generation\":0",
                operation, (unsigned)STATUS_UNSUCCESSFUL, errno);
    ERR("Pear native PE arena cannot safely continue after %s (errno %d)\n", operation, errno);
    _exit(127);
}

static BOOL extent(SIZE_T start, SIZE_T size, SIZE_T limit)
{
    return start <= limit && size <= limit - start;
}

static BOOL rounded(SIZE_T value, SIZE_T alignment, SIZE_T *result)
{
    if (!alignment || (alignment & (alignment - 1)) || value > ~(SIZE_T)0 - (alignment - 1)) return FALSE;
    *result = (value + alignment - 1) & ~(alignment - 1);
    return TRUE;
}

BOOL pear_pe_arena_overlaps(const void *base, SIZE_T size)
{
    ULONG_PTR first = (ULONG_PTR)base, start = (ULONG_PTR)arena.mapping;
    if (!arena.mapping || !size) return FALSE;
    if (first > ~(ULONG_PTR)0 - size) return TRUE;
    return first < start + PEAR_ARENA_MAPPING_BYTES && start < first + size;
}

NTSTATUS pear_pe_arena_initialize(void **base, SIZE_T *size)
{
#if defined(PEAR_NATIVE_PE_PUBLICATION) && defined(__APPLE__) && defined(__aarch64__)
    SIZE_T prefix;
    void *mapping;
    if (!pear_pe_arena_enabled()) return STATUS_NOT_SUPPORTED;
    require_owner();
    if (arena.mapping) goto done;
    if (arena.attempted) return STATUS_NO_MEMORY;
    arena.attempted = TRUE;
    if (sysconf(_SC_PAGESIZE) != PAGE) return STATUS_NOT_SUPPORTED;
    if (!(arena.classes = calloc(PAGES, 1)) || !(arena.protection = calloc(PAGES, 1)) ||
        !(arena.vprot = calloc(PAGES, 1))) goto failed;
    mapping = mmap(NULL, PEAR_ARENA_MAPPING_BYTES, PROT_NONE, MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
    if (mapping == MAP_FAILED) goto failed;
    if ((ULONG_PTR)mapping > ~(ULONG_PTR)0 - PEAR_ARENA_MAPPING_BYTES)
    {
        if (munmap(mapping, PEAR_ARENA_MAPPING_BYTES)) pear_pe_arena_fatal("invalid reservation cleanup");
        goto failed;
    }
    prefix = (PEAR_ARENA_ALIGNMENT - ((ULONG_PTR)mapping & (PEAR_ARENA_ALIGNMENT - 1))) &
             (PEAR_ARENA_ALIGNMENT - 1);
    if (!actual_protection(mapping, PEAR_ARENA_MAPPING_BYTES, PROT_NONE))
    {
        if (munmap(mapping, PEAR_ARENA_MAPPING_BYTES)) pear_pe_arena_fatal("initial_protection_cleanup");
        goto failed;
    }
    arena.owner_pid = getpid();
    arena.mapping = mapping;
    arena.interior = (unsigned char *)mapping + prefix;
    arena_event("arena_reserve", ",\"mapping_base\":%llu,\"interior_base\":%llu,\"mapping_bytes\":%llu,"
                "\"interior_bytes\":%llu,\"page_bytes\":4096,\"max_slots\":%u",
                (unsigned long long)(ULONG_PTR)arena.mapping, (unsigned long long)(ULONG_PTR)arena.interior,
                (unsigned long long)PEAR_ARENA_MAPPING_BYTES, (unsigned long long)PEAR_ARENA_INTERIOR_BYTES,
                PEAR_ARENA_MAX_SLOTS);
    dynamic_event("dynamic_budget", ",\"policy_version\":1,\"base\":%llu,\"bytes\":%llu,\"slots\":%u,\"slot_bytes\":%llu",
                (unsigned long long)(ULONG_PTR)(arena.interior + PEAR_ARENA_INTERIOR_BYTES),
                (unsigned long long)PEAR_ARENA_DYNAMIC_BYTES, PEAR_ARENA_DYNAMIC_SLOTS,
                (unsigned long long)PEAR_ARENA_DYNAMIC_SLOT_BYTES);
    TRACE("Pear page-W^X arena reserved %lu bytes, %u slots, one MAP_JIT allocation\n",
          (unsigned long)PEAR_ARENA_MAPPING_BYTES, PEAR_ARENA_MAX_SLOTS);
done:
    *base = arena.mapping;
    *size = PEAR_ARENA_MAPPING_BYTES;
    return STATUS_SUCCESS;
failed:
    free(arena.classes); free(arena.protection); free(arena.vprot);
    arena.classes = arena.protection = arena.vprot = NULL;
    return STATUS_NO_MEMORY;
#else
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS read_exact(int fd, void *data, SIZE_T size, off_t offset)
{
    unsigned char *ptr = data;
    while (size)
    {
        ssize_t count = pread(fd, ptr, size, offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return STATUS_INVALID_IMAGE_FORMAT;
        size -= count; ptr += count; offset += count;
    }
    return STATUS_SUCCESS;
}

void pear_pe_plan_free(struct pear_pe_plan *plan)
{
    if (!plan) return;
    free(plan->staging); free(plan->pages); free(plan->relocations); free(plan);
}

static int compare_rva(const void *a, const void *b)
{
    ULONG x = *(const ULONG *)a, y = *(const ULONG *)b;
    return (x > y) - (x < y);
}

static BOOL directory(const IMAGE_NT_HEADERS64 *nt, unsigned int index, SIZE_T size,
                      const IMAGE_DATA_DIRECTORY **out)
{
    const IMAGE_DATA_DIRECTORY *dir;
    *out = NULL;
    if (index >= nt->OptionalHeader.NumberOfRvaAndSizes) return TRUE;
    dir = &nt->OptionalHeader.DataDirectory[index];
    if (!dir->Size && !dir->VirtualAddress) return TRUE;
    if (!dir->Size || !dir->VirtualAddress || !extent(dir->VirtualAddress, dir->Size, size)) return FALSE;
    *out = dir;
    return TRUE;
}

static BOOL used_range(const struct pear_pe_plan *plan, SIZE_T offset, SIZE_T size, BOOL ordinary)
{
    SIZE_T last, page;
    if (!size || !extent(offset, size, plan->size)) return FALSE;
    last = (offset + size - 1) / PAGE;
    for (page = offset / PAGE; page <= last; ++page)
        if (!(plan->pages[page] & PAGE_USED) || (ordinary && (plan->pages[page] & PV_EXEC))) return FALSE;
    return TRUE;
}

static NTSTATUS parse_relocations(struct pear_pe_plan *plan, const IMAGE_DATA_DIRECTORY *dir)
{
    SIZE_T cursor, end, maximum, count = 0;
    if (!dir) return STATUS_SUCCESS; /* PIC images may legitimately have none. */
    if (!used_range(plan, dir->VirtualAddress, dir->Size, FALSE)) return STATUS_INVALID_IMAGE_FORMAT;
    maximum = dir->Size / sizeof(USHORT);
    if (maximum > MAX_RELOCATIONS || maximum > ~(SIZE_T)0 / sizeof(ULONG)) return STATUS_NOT_SUPPORTED;
    if (!(plan->relocations = malloc(maximum * sizeof(ULONG)))) return STATUS_NO_MEMORY;
    cursor = dir->VirtualAddress;
    end = cursor + dir->Size;
    while (cursor < end)
    {
        IMAGE_BASE_RELOCATION block;
        SIZE_T pos;
        if (!extent(cursor, sizeof(block), end)) return STATUS_INVALID_IMAGE_FORMAT;
        memcpy(&block, plan->staging + cursor, sizeof(block));
        if (block.SizeOfBlock < sizeof(block) || (block.SizeOfBlock & 1) ||
            !extent(cursor, block.SizeOfBlock, end) || (block.VirtualAddress & (PAGE - 1)))
            return STATUS_INVALID_IMAGE_FORMAT;
        for (pos = sizeof(block); pos < block.SizeOfBlock; pos += sizeof(USHORT))
        {
            USHORT item;
            SIZE_T target;
            memcpy(&item, plan->staging + cursor + pos, sizeof(item));
            if ((item >> 12) == IMAGE_REL_BASED_ABSOLUTE) continue;
            if ((item >> 12) != IMAGE_REL_BASED_DIR64) return STATUS_NOT_SUPPORTED;
            target = (SIZE_T)block.VirtualAddress + (item & 0xfff);
            if (!used_range(plan, target, sizeof(ULONGLONG), FALSE) || target < plan->header_bytes ||
                (target < end && dir->VirtualAddress < target + sizeof(ULONGLONG)))
                return STATUS_INVALID_IMAGE_FORMAT;
            plan->relocations[count++] = target;
        }
        cursor += block.SizeOfBlock;
    }
    qsort(plan->relocations, count, sizeof(ULONG), compare_rva);
    for (cursor = 1; cursor < count; ++cursor)
        if ((SIZE_T)plan->relocations[cursor] < (SIZE_T)plan->relocations[cursor - 1] + sizeof(ULONGLONG))
            return STATUS_INVALID_IMAGE_FORMAT;
    plan->relocation_count = count;
    return STATUS_SUCCESS;
}

static BOOL ordinary_va(const struct pear_pe_plan *plan, ULONGLONG address, SIZE_T size)
{
    return address >= plan->original_base && address - plan->original_base <= plan->size &&
           used_range(plan, (SIZE_T)(address - plan->original_base), size, TRUE);
}

/* These loader-written destinations must never retain executable backing.
 * Wine keeps responsibility for resolving imports and initializing TLS/cookies. */
static NTSTATUS check_loader_data(const struct pear_pe_plan *plan, const IMAGE_NT_HEADERS64 *nt)
{
    const IMAGE_DATA_DIRECTORY *dir;
    IMAGE_TLS_DIRECTORY64 tls;
    if (!directory(nt, IMAGE_DIRECTORY_ENTRY_IAT, plan->size, &dir) ||
        (dir && !used_range(plan, dir->VirtualAddress, dir->Size, TRUE))) return STATUS_INVALID_IMAGE_FORMAT;
    if (!directory(nt, IMAGE_DIRECTORY_ENTRY_TLS, plan->size, &dir)) return STATUS_INVALID_IMAGE_FORMAT;
    if (dir)
    {
        SIZE_T offset;
        if (dir->Size < sizeof(tls)) return STATUS_INVALID_IMAGE_FORMAT;
        memcpy(&tls, plan->staging + dir->VirtualAddress, sizeof(tls));
        if (tls.EndAddressOfRawData < tls.StartAddressOfRawData ||
            (tls.EndAddressOfRawData != tls.StartAddressOfRawData &&
             !ordinary_va(plan, tls.StartAddressOfRawData, tls.EndAddressOfRawData - tls.StartAddressOfRawData)) ||
            !ordinary_va(plan, tls.AddressOfIndex, sizeof(ULONG))) return STATUS_INVALID_IMAGE_FORMAT;
        if (tls.AddressOfCallBacks)
        {
            if (!ordinary_va(plan, tls.AddressOfCallBacks, sizeof(ULONGLONG))) return STATUS_INVALID_IMAGE_FORMAT;
            offset = tls.AddressOfCallBacks - plan->original_base;
            for (;; offset += sizeof(ULONGLONG))
            {
                ULONGLONG callback;
                if (!used_range(plan, offset, sizeof(callback), TRUE)) return STATUS_INVALID_IMAGE_FORMAT;
                memcpy(&callback, plan->staging + offset, sizeof(callback));
                if (!callback) break;
                if (callback < plan->original_base || callback - plan->original_base >= plan->size ||
                    !(plan->pages[(callback - plan->original_base) / PAGE] & PV_EXEC))
                    return STATUS_INVALID_IMAGE_FORMAT;
            }
        }
    }
    if (!directory(nt, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, plan->size, &dir)) return STATUS_INVALID_IMAGE_FORMAT;
    if (dir)
    {
        ULONG length;
        ULONGLONG cookie;
        SIZE_T available, field = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie);
        memcpy(&length, plan->staging + dir->VirtualAddress, sizeof(length));
        available = min((SIZE_T)length, (SIZE_T)dir->Size);
        /* Wine reads the complete pointer whenever Size extends past its first
         * byte. Reject partial fields before publishing executable pages. */
        if (available > field)
        {
            if (!extent(field, sizeof(cookie), available)) return STATUS_INVALID_IMAGE_FORMAT;
            memcpy(&cookie, plan->staging + dir->VirtualAddress + field, sizeof(cookie));
            if (cookie && !ordinary_va(plan, cookie, sizeof(cookie))) return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    return STATUS_SUCCESS;
}

/* Original Pear role validation around Wine's IMAGE_ARM64EC_METADATA layout.
 * The loader retains relocation/import/dispatch ownership. No allocation or
 * executable publication occurs while validating this staged image. */
/* Reuses Wine's ARM64X zero/value/delta relocation semantics on NX staging.
 * Validate the entire selected stream before mutation; no native code executes. */
static BOOL hybrid_header_write(const struct pear_pe_plan *plan, SIZE_T at, SIZE_T size)
{
    SIZE_T nt = plan->nt_offset, opt = nt + offsetof(IMAGE_NT_HEADERS64, OptionalHeader);
    SIZE_T machine = nt + offsetof(IMAGE_NT_HEADERS64, FileHeader.Machine);
    SIZE_T entry = opt + offsetof(IMAGE_OPTIONAL_HEADER64, AddressOfEntryPoint);
    SIZE_T dirs = opt + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
    if (at >= plan->header_bytes) return TRUE;
    return (at >= machine && extent(at - machine, size, sizeof(USHORT))) ||
           (at >= entry && extent(at - entry, size, sizeof(ULONG))) ||
           (at >= dirs && extent(at - dirs, size, sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
}

static NTSTATUS arm64x_fixups(struct pear_pe_plan *plan, SIZE_T begin, SIZE_T bytes,
                             SIZE_T table_begin, SIZE_T table_bytes, BOOL apply)
{
    SIZE_T cursor = begin, end = begin + bytes;
    while (cursor < end)
    {
        IMAGE_BASE_RELOCATION block;
        SIZE_T stop, item;
        if (!extent(cursor, sizeof(block), end)) return STATUS_INVALID_IMAGE_FORMAT;
        memcpy(&block, plan->staging + cursor, sizeof(block));
        if (block.SizeOfBlock < sizeof(block) || (block.SizeOfBlock & 1) ||
            !extent(cursor, block.SizeOfBlock, end) || (block.VirtualAddress & (PAGE - 1)))
            return STATUS_INVALID_IMAGE_FORMAT;
        stop = cursor + block.SizeOfBlock; item = cursor + sizeof(block);
        while (item < stop)
        {
            USHORT word;
            unsigned int type, arg;
            SIZE_T offset, width;
            memcpy(&word, plan->staging + item, sizeof(word)); item += sizeof(word);
            if (!word)
            {
                /* Only zero padding may follow the terminator. */
                while (item < stop)
                {
                    memcpy(&word, plan->staging + item, sizeof(word)); item += sizeof(word);
                    if (word) return STATUS_INVALID_IMAGE_FORMAT;
                }
                break;
            }
            type = (word >> 12) & 3; arg = word >> 14;
            offset = (SIZE_T)block.VirtualAddress + (word & 0xfff);
            width = type == IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA ? sizeof(ULONG) : (SIZE_T)1 << arg;
            if (type > IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA ||
                !used_range(plan, offset, width, FALSE) || !hybrid_header_write(plan, offset, width) ||
                (offset < table_begin + table_bytes && table_begin < offset + width))
                return STATUS_INVALID_IMAGE_FORMAT;
            switch (type)
            {
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL:
                if (apply) memset(plan->staging + offset, 0, width);
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE:
                if (width < sizeof(USHORT) || !extent(item, width, stop)) return STATUS_INVALID_IMAGE_FORMAT;
                if (apply) memcpy(plan->staging + offset, plan->staging + item, width);
                item += width;
                break;
            case IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA:
                if (!extent(item, sizeof(USHORT), stop)) return STATUS_INVALID_IMAGE_FORMAT;
                if (apply)
                {
                    USHORT encoded;
                    ULONG value, delta;
                    memcpy(&encoded, plan->staging + item, sizeof(encoded));
                    memcpy(&value, plan->staging + offset, sizeof(value));
                    delta = (ULONG)encoded * ((arg & 2) ? 8 : 4);
                    value = (arg & 1) ? value - delta : value + delta;
                    memcpy(plan->staging + offset, &value, sizeof(value));
                }
                item += sizeof(USHORT);
                break;
            }
        }
        cursor = stop;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS select_arm64x(struct pear_pe_plan *plan, IMAGE_NT_HEADERS64 *nt,
                              const IMAGE_SECTION_HEADER *sections, const IMAGE_DATA_DIRECTORY *cfg)
{
    ULONG length, offset;
    USHORT section;
    IMAGE_DYNAMIC_RELOCATION_TABLE table;
    SIZE_T start, cursor, end, selected = 0, selected_size = 0;
    SIZE_T offset_field = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableOffset);
    SIZE_T section_field = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, DynamicValueRelocTableSection);
    NTSTATUS status;
    if (!cfg || cfg->Size < sizeof(length)) return STATUS_NOT_SUPPORTED;
    memcpy(&length, plan->staging + cfg->VirtualAddress, sizeof(length));
    if (length > cfg->Size || !extent(section_field, sizeof(section), length)) return STATUS_INVALID_IMAGE_FORMAT;
    memcpy(&offset, plan->staging + cfg->VirtualAddress + offset_field, sizeof(offset));
    memcpy(&section, plan->staging + cfg->VirtualAddress + section_field, sizeof(section));
    if (!section || section > nt->FileHeader.NumberOfSections) return STATUS_NOT_SUPPORTED;
    if (!extent(offset, sizeof(table), sections[section - 1].Misc.VirtualSize)) return STATUS_INVALID_IMAGE_FORMAT;
    start = (SIZE_T)sections[section - 1].VirtualAddress + offset;
    if (!used_range(plan, start, sizeof(table), FALSE)) return STATUS_INVALID_IMAGE_FORMAT;
    memcpy(&table, plan->staging + start, sizeof(table));
    if (table.Version != 1 && table.Version != 2) return STATUS_NOT_SUPPORTED;
    cursor = start + sizeof(table);
    if (!used_range(plan, cursor, table.Size, FALSE) ||
        !extent(offset + sizeof(table), table.Size, sections[section - 1].Misc.VirtualSize))
        return STATUS_INVALID_IMAGE_FORMAT;
    end = cursor + table.Size;
    while (cursor < end)
    {
        ULONGLONG symbol;
        SIZE_T header_size, fixup_size;
        if (table.Version == 1)
        {
            IMAGE_DYNAMIC_RELOCATION64 entry;
            if (!extent(cursor, sizeof(entry), end)) return STATUS_INVALID_IMAGE_FORMAT;
            memcpy(&entry, plan->staging + cursor, sizeof(entry));
            symbol = entry.Symbol; header_size = sizeof(entry); fixup_size = entry.BaseRelocSize;
        }
        else
        {
            IMAGE_DYNAMIC_RELOCATION64_V2 entry;
            if (!extent(cursor, sizeof(entry), end)) return STATUS_INVALID_IMAGE_FORMAT;
            memcpy(&entry, plan->staging + cursor, sizeof(entry));
            if (entry.HeaderSize < sizeof(entry)) return STATUS_INVALID_IMAGE_FORMAT;
            symbol = entry.Symbol; header_size = entry.HeaderSize; fixup_size = entry.FixupInfoSize;
        }
        if (!extent(cursor, header_size, end) || !extent(cursor + header_size, fixup_size, end))
            return STATUS_INVALID_IMAGE_FORMAT;
        if (symbol == IMAGE_DYNAMIC_RELOCATION_ARM64X)
        {
            if (selected || !fixup_size) return STATUS_INVALID_IMAGE_FORMAT;
            selected = cursor + header_size; selected_size = fixup_size;
        }
        cursor += header_size + fixup_size;
    }
    if (!selected) return STATUS_NOT_SUPPORTED;
    status = arm64x_fixups(plan, selected, selected_size, start, end - start, FALSE);
    if (!status) status = arm64x_fixups(plan, selected, selected_size, start, end - start, TRUE);
    if (!status && nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) status = STATUS_INVALID_IMAGE_FORMAT;
    return status;
}

static BOOL executable_range(const struct pear_pe_plan *plan, ULONG rva, SIZE_T size)
{
    SIZE_T page;
    if (!size || !used_range(plan, rva, size, FALSE)) return FALSE;
    for (page = rva / PAGE; page <= ((SIZE_T)rva + size - 1) / PAGE; ++page)
        if (!(plan->pages[page] & PV_EXEC)) return FALSE;
    return TRUE;
}

static BOOL chpe_table(const struct pear_pe_plan *plan, ULONG rva, ULONG count, SIZE_T item_size)
{
    return !count ? !rva : rva && count <= plan->size / item_size &&
           used_range(plan, rva, (SIZE_T)count * item_size, FALSE);
}

static BOOL chpe_native_range(const struct pear_pe_plan *plan,
                              const IMAGE_ARM64EC_METADATA *metadata, ULONG rva, SIZE_T size, ULONG code_kind)
{
    ULONG i;
    for (i = 0; i < metadata->CodeMapCount; ++i)
    {
        IMAGE_CHPE_RANGE_ENTRY range;
        ULONG start;
        memcpy(&range, plan->staging + metadata->CodeMap + i * sizeof(range), sizeof(range));
        start = range.StartOffset & ~3u;
        if ((range.StartOffset & 3) == code_kind && rva >= start &&
            (SIZE_T)rva - start <= range.Length && size <= range.Length - ((SIZE_T)rva - start)) return TRUE;
    }
    return FALSE;
}

static NTSTATUS check_chpe_role(struct pear_pe_plan *plan, const IMAGE_NT_HEADERS64 *nt,
                                const IMAGE_DATA_DIRECTORY *cfg, USHORT target, struct pear_pe_image *image)
{
    IMAGE_ARM64EC_METADATA metadata = {0};
    ULONGLONG pointer = 0;
    ULONG length = 0, i, previous_end = 0, ec_ranges = 0;
    SIZE_T metadata_rva, minimum = offsetof(IMAGE_ARM64EC_METADATA, AuxiliaryIATCopy) + sizeof(ULONG);
    ULONG native_entry = nt->OptionalHeader.AddressOfEntryPoint;
    image->role = PEAR_PE_ROLE_NATIVE;
    if (cfg)
    {
        SIZE_T field = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer);
        memcpy(&length, plan->staging + cfg->VirtualAddress, sizeof(length));
        if (length > field && !extent(field, sizeof(pointer), length)) return STATUS_INVALID_IMAGE_FORMAT;
        if (extent(field, sizeof(pointer), length))
            memcpy(&pointer, plan->staging + cfg->VirtualAddress + field, sizeof(pointer));
    }
    if (!pointer)
    {
        if (nt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) image->role = PEAR_PE_ROLE_GUEST_X64;
        return target == nt->FileHeader.Machine ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    }
    /* ARM64X needs the original Wine dynamic-relocation selection before role
     * validation. Never grant native execution simply because metadata exists. */
    if (target != nt->FileHeader.Machine || pointer < plan->original_base ||
        pointer - plan->original_base > plan->size) return STATUS_INVALID_IMAGE_FORMAT;
    metadata_rva = pointer - plan->original_base;
    if (!used_range(plan, metadata_rva, minimum, FALSE)) return STATUS_INVALID_IMAGE_FORMAT;
    memcpy(&metadata, plan->staging + metadata_rva, minimum);
    if ((metadata.Version != 1 && metadata.Version != 2) || !metadata.CodeMapCount ||
        !chpe_table(plan, metadata.CodeMap, metadata.CodeMapCount, sizeof(IMAGE_CHPE_RANGE_ENTRY)) ||
        !chpe_table(plan, metadata.RedirectionMetadata, metadata.RedirectionMetadataCount,
                    sizeof(IMAGE_ARM64EC_REDIRECTION_ENTRY)) ||
        !chpe_table(plan, metadata.CodeRangesToEntryPoints, metadata.CodeRangesToEntryPointsCount,
                    sizeof(IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT))) return STATUS_INVALID_IMAGE_FORMAT;
    for (i = 0; i < metadata.CodeMapCount; ++i)
    {
        IMAGE_CHPE_RANGE_ENTRY range;
        ULONG start, kind;
        memcpy(&range, plan->staging + metadata.CodeMap + i * sizeof(range), sizeof(range));
        start = range.StartOffset & ~3u; kind = range.StartOffset & 3;
        if ((kind > 2) || start < previous_end ||
            !executable_range(plan, start, range.Length) ||
            (kind == 1 && (range.Length & 3))) return STATUS_INVALID_IMAGE_FORMAT;
        previous_end = start + range.Length;
        ec_ranges += kind == 1;
    }
    if (!ec_ranges) return STATUS_INVALID_IMAGE_FORMAT;
    previous_end = 0;
    for (i = 0; i < metadata.RedirectionMetadataCount; ++i)
    {
        IMAGE_ARM64EC_REDIRECTION_ENTRY entry;
        memcpy(&entry, plan->staging + metadata.RedirectionMetadata + i * sizeof(entry), sizeof(entry));
        if ((i && entry.Source <= previous_end) || !executable_range(plan, entry.Source, 1) ||
            (entry.Destination & 3) || !chpe_native_range(plan, &metadata, entry.Destination, 4, 1))
            return STATUS_INVALID_IMAGE_FORMAT;
        if (target == IMAGE_FILE_MACHINE_AMD64 && entry.Source == native_entry) image->native_entry_rva = entry.Destination;
        previous_end = entry.Source;
    }
    if (native_entry && !image->native_entry_rva)
    {
        if (!chpe_native_range(plan, &metadata, native_entry, 4, target == IMAGE_FILE_MACHINE_ARM64 ? 0 : 1)) return STATUS_INVALID_IMAGE_FORMAT;
        image->native_entry_rva = native_entry;
    }
    previous_end = 0;
    for (i = 0; i < metadata.CodeRangesToEntryPointsCount; ++i)
    {
        IMAGE_ARM64EC_CODE_RANGE_ENTRY_POINT entry;
        memcpy(&entry, plan->staging + metadata.CodeRangesToEntryPoints + i * sizeof(entry), sizeof(entry));
        if (entry.EndRva <= entry.StartRva || entry.StartRva < previous_end ||
            !executable_range(plan, entry.StartRva, (SIZE_T)entry.EndRva - entry.StartRva) ||
            !executable_range(plan, entry.EntryPoint, 1)) return STATUS_INVALID_IMAGE_FORMAT;
        previous_end = entry.EndRva;
    }
    /* Wine/FEX write dispatch slots and auxiliary import pointers after mapping;
     * their storage must remain ordinary NX, as do existing IAT/TLS fields. */
    {
        ULONG slots[] = {metadata.__os_arm64x_dispatch_call_no_redirect, metadata.__os_arm64x_dispatch_ret,
            metadata.__os_arm64x_dispatch_call, metadata.__os_arm64x_dispatch_icall,
            metadata.__os_arm64x_dispatch_icall_cfg, metadata.GetX64InformationFunctionPointer,
            metadata.SetX64InformationFunctionPointer, metadata.__os_arm64x_dispatch_fptr,
            metadata.AuxiliaryIAT, metadata.AuxiliaryIATCopy};
        for (i = 0; i < sizeof(slots) / sizeof(slots[0]); ++i)
            if (slots[i] && ((slots[i] & 7) || !used_range(plan, slots[i], sizeof(ULONGLONG), TRUE)))
                return STATUS_INVALID_IMAGE_FORMAT;
    }
    image->role = target == IMAGE_FILE_MACHINE_ARM64 ? PEAR_PE_ROLE_NATIVE : PEAR_PE_ROLE_ARM64EC;
    image->chpe_rva = metadata_rva;
    return STATUS_SUCCESS;
}

/* Opt-in Task #40 diagnostics; preserve errno and the original status.
 * The caller holds virtual_mutex. File identity disambiguates mapping attempts;
 * this observer neither authorizes nor modifies image admission. */
NTSTATUS pear_pe_diagnostic(int fd, const char *phase, NTSTATUS status)
{
    int saved = errno, count;
    struct stat info;
    char line[384];
    if (getenv("PEAR_IMAGE_ADMISSION_DIAGNOSTIC") && !fstat(fd, &info))
    {
        count = snprintf(line, sizeof(line),
                         "PEAR_IMAGE_ADMISSION pid=%u fd=%d dev=%llu ino=%llu bytes=%llu phase=%s status=%08x\n",
                         (unsigned)getpid(), fd, (unsigned long long)info.st_dev,
                         (unsigned long long)info.st_ino, (unsigned long long)info.st_size,
                         phase, (unsigned)status);
        if (count > 0 && count < sizeof(line)) (void)write(2, line, count);
    }
    errno = saved;
    return status;
}

NTSTATUS pear_pe_plan_read_target(int fd, USHORT target, struct pear_pe_plan **ret, struct pear_pe_image *image)
{
    struct stat stat;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 header, *nt;
    IMAGE_SECTION_HEADER *sections;
    const IMAGE_DATA_DIRECTORY *relocs, *cfg, *dir;
    struct pear_pe_plan *plan = NULL;
    NTSTATUS status = STATUS_INVALID_IMAGE_FORMAT;
    SIZE_T section_offset, section_bytes, header_end, i, j;
    pear_pe_diagnostic(fd, "parser.begin", STATUS_SUCCESS);
    *ret = NULL;
    memset(image, 0, sizeof(*image));
    if (target != IMAGE_FILE_MACHINE_ARM64 && target != IMAGE_FILE_MACHINE_AMD64) return pear_pe_diagnostic(fd, "parser.return01", STATUS_NOT_SUPPORTED);
    if (fstat(fd, &stat) || stat.st_size < 0 || !S_ISREG(stat.st_mode)) return pear_pe_diagnostic(fd, "parser.return02", status);
    if (!extent(0, sizeof(dos), stat.st_size) ||
        read_exact(fd, &dos, sizeof(dos), 0) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < (LONG)sizeof(dos) || dos.e_lfanew % _Alignof(IMAGE_NT_HEADERS64) ||
        !extent(dos.e_lfanew, sizeof(header), stat.st_size) ||
        read_exact(fd, &header, sizeof(header), dos.e_lfanew)) return pear_pe_diagnostic(fd, "parser.return03", status);
    if (header.Signature != IMAGE_NT_SIGNATURE || (header.FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64 && header.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) ||
        header.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        header.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
        !header.FileHeader.NumberOfSections || header.FileHeader.NumberOfSections > MAX_SECTIONS ||
        header.OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return pear_pe_diagnostic(fd, "parser.return04", status);
    if (header.OptionalHeader.ImageBase & (PEAR_ARENA_ALIGNMENT - 1)) return pear_pe_diagnostic(fd, "parser.return05", status);
    if (!(header.FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ||
        header.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED ||
        !(header.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return pear_pe_diagnostic(fd, "parser.return06", STATUS_NOT_SUPPORTED);
    if ((header.OptionalHeader.SectionAlignment != PAGE && header.OptionalHeader.SectionAlignment != PEAR_ARENA_ALIGNMENT) ||
        header.OptionalHeader.FileAlignment < 512 || header.OptionalHeader.FileAlignment > header.OptionalHeader.SectionAlignment ||
        (header.OptionalHeader.FileAlignment & (header.OptionalHeader.FileAlignment - 1))) return pear_pe_diagnostic(fd, "parser.return07", STATUS_NOT_SUPPORTED);
    if (!header.OptionalHeader.SizeOfImage || header.OptionalHeader.SizeOfImage % header.OptionalHeader.SectionAlignment ||
        header.OptionalHeader.SizeOfImage > PEAR_ARENA_MAX_IMAGE_BYTES) return pear_pe_diagnostic(fd, "parser.return08", STATUS_NOT_SUPPORTED);
    section_offset = (SIZE_T)dos.e_lfanew + sizeof(header);
    section_bytes = (SIZE_T)header.FileHeader.NumberOfSections * sizeof(*sections);
    if (header.OptionalHeader.SizeOfHeaders % header.OptionalHeader.FileAlignment ||
        !extent(section_offset, section_bytes, header.OptionalHeader.SizeOfHeaders) ||
        !extent(0, header.OptionalHeader.SizeOfHeaders, stat.st_size) ||
        !rounded(header.OptionalHeader.SizeOfHeaders, header.OptionalHeader.SectionAlignment, &header_end) ||
        !extent(0, header_end, header.OptionalHeader.SizeOfImage)) return pear_pe_diagnostic(fd, "parser.return09", status);
    if (!(plan = calloc(1, sizeof(*plan)))) return pear_pe_diagnostic(fd, "parser.return10", STATUS_NO_MEMORY);
    plan->size = header.OptionalHeader.SizeOfImage;
    plan->page_count = plan->size / PAGE;
    plan->header_bytes = header_end;
    plan->nt_offset = dos.e_lfanew;
    plan->original_base = header.OptionalHeader.ImageBase;
    if (!rounded(plan->size, PEAR_ARENA_ALIGNMENT, &plan->capacity) ||
        !(plan->staging = calloc(1, plan->size)) || !(plan->pages = calloc(1, plan->page_count)))
    { status = STATUS_NO_MEMORY; goto done; }
    if ((status = read_exact(fd, plan->staging, header.OptionalHeader.SizeOfHeaders, 0))) goto done;
    /* A source changed between initial header read and staging cannot alter the
     * checked structure. All later parsing and writes use this private copy. */
    nt = (IMAGE_NT_HEADERS64 *)(plan->staging + plan->nt_offset);
    if (memcmp(nt, &header, sizeof(header))) { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
    sections = (IMAGE_SECTION_HEADER *)(plan->staging + section_offset);
    for (i = 0; i < header_end / PAGE; ++i) plan->pages[i] = PAGE_USED | PV_READ;
    for (i = 0; i < header.FileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER *sec = &sections[i];
        SIZE_T size, raw;
        unsigned int previous;
        BYTE protection = PAGE_USED;
        if (sec->Characteristics & IMAGE_SCN_MEM_SHARED) { status = STATUS_NOT_SUPPORTED; goto done; }
        if ((sec->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) ==
            (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE)) { status = STATUS_NOT_SUPPORTED; goto done; }
        if (sec->Characteristics & IMAGE_SCN_MEM_READ) protection |= PV_READ;
        if (sec->Characteristics & IMAGE_SCN_MEM_WRITE) protection |= PV_COPY;
        if (sec->Characteristics & IMAGE_SCN_MEM_EXECUTE) protection |= PV_EXEC | PV_READ;
        if (sec->VirtualAddress % header.OptionalHeader.SectionAlignment ||
            !rounded(sec->Misc.VirtualSize ? sec->Misc.VirtualSize : sec->SizeOfRawData,
                     header.OptionalHeader.SectionAlignment, &size) || !extent(sec->VirtualAddress, size, plan->size))
        { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
        for (j = sec->VirtualAddress / PAGE; j < (sec->VirtualAddress + size) / PAGE; ++j)
        {
            if (plan->pages[j] & PAGE_USED) { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
            plan->pages[j] = protection;
        }
        /* Raw file intervals are fully bounded even when only VirtualSize is
         * materialized. Reject header aliasing and ambiguous section aliases. */
        if (sec->SizeOfRawData && (sec->PointerToRawData < header.OptionalHeader.SizeOfHeaders ||
            !extent(sec->PointerToRawData, sec->SizeOfRawData, stat.st_size)))
        { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
        for (previous = 0; previous < i; ++previous)
        {
            const IMAGE_SECTION_HEADER *other = &sections[previous];
            if (sec->SizeOfRawData && other->SizeOfRawData &&
                (SIZE_T)sec->PointerToRawData < (SIZE_T)other->PointerToRawData + other->SizeOfRawData &&
                (SIZE_T)other->PointerToRawData < (SIZE_T)sec->PointerToRawData + sec->SizeOfRawData)
            { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
        }
        raw = min((SIZE_T)sec->SizeOfRawData, size);
        if (raw && (!sec->PointerToRawData || sec->PointerToRawData % header.OptionalHeader.FileAlignment ||
                    !extent(sec->PointerToRawData, raw, stat.st_size)))
        { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
        if (raw && (status = read_exact(fd, plan->staging + sec->VirtualAddress, raw, sec->PointerToRawData))) goto done;
    }
    if (header.OptionalHeader.AddressOfEntryPoint &&
        (header.OptionalHeader.AddressOfEntryPoint >= plan->size ||
         !(plan->pages[header.OptionalHeader.AddressOfEntryPoint / PAGE] & PV_EXEC)))
    { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
    for (i = 0; i < header.OptionalHeader.NumberOfRvaAndSizes; ++i)
    {
        if (i == IMAGE_DIRECTORY_ENTRY_SECURITY) /* file offset, not an RVA */
        {
            const IMAGE_DATA_DIRECTORY *security = &nt->OptionalHeader.DataDirectory[i];
            if ((security->Size || security->VirtualAddress) &&
                (!security->Size || !security->VirtualAddress ||
                 !extent(security->VirtualAddress, security->Size, stat.st_size)))
            { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
            continue;
        }
        if (!directory(nt, i, plan->size, &dir) || (dir && !used_range(plan, dir->VirtualAddress, dir->Size, FALSE)))
        { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
    }
    if (!directory(nt, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, plan->size, &cfg) ||
        !directory(nt, IMAGE_DIRECTORY_ENTRY_BASERELOC, plan->size, &relocs))
    { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
    if (header.FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64 && target == IMAGE_FILE_MACHINE_AMD64)
    {
        if ((status = select_arm64x(plan, nt, sections, cfg))) goto done;
        /* Wine selects the x64 view before base relocations and EC registration.
         * Re-read changed data directories; geometry/section headers were not writable. */
        for (i = 0; i < nt->OptionalHeader.NumberOfRvaAndSizes; ++i)
        {
            if (i == IMAGE_DIRECTORY_ENTRY_SECURITY)
            {
                const IMAGE_DATA_DIRECTORY *security = &nt->OptionalHeader.DataDirectory[i];
                if ((security->Size || security->VirtualAddress) &&
                    (!security->Size || !security->VirtualAddress ||
                     !extent(security->VirtualAddress, security->Size, stat.st_size)))
                { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
                continue;
            }
            if (!directory(nt, i, plan->size, &dir) || (dir && !used_range(plan, dir->VirtualAddress, dir->Size, FALSE)))
            { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
        }
        if (!directory(nt, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, plan->size, &cfg) ||
            !directory(nt, IMAGE_DIRECTORY_ENTRY_BASERELOC, plan->size, &relocs))
        { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
    }
    if (cfg)
    {
        SIZE_T field = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer);
        ULONG cfg_size;
        ULONGLONG chpe = 0;
        if (cfg->Size < sizeof(cfg_size)) { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
        memcpy(&cfg_size, plan->staging + cfg->VirtualAddress, sizeof(cfg_size));
        if (cfg_size < sizeof(cfg_size) || cfg_size > cfg->Size) { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
        if (extent(field, sizeof(chpe), cfg_size)) memcpy(&chpe, plan->staging + cfg->VirtualAddress + field, sizeof(chpe));
        (void)chpe; /* Role-specific validation below retains native-only rejection. */
    }
    if ((status = check_chpe_role(plan, nt, cfg, target, image))) goto done;
    plan->role = image->role;
    if ((status = check_loader_data(plan, nt)) || (status = parse_relocations(plan, relocs))) goto done;
    image->size = plan->size;
    image->original_base = plan->original_base;
    image->entry_rva = nt->OptionalHeader.AddressOfEntryPoint;
    image->machine = nt->FileHeader.Machine;
    image->original_machine = header.FileHeader.Machine;
    image->original_entry_rva = header.OptionalHeader.AddressOfEntryPoint;
    *ret = plan;
    return pear_pe_diagnostic(fd, "parser.return11", STATUS_SUCCESS);
done:
    pear_pe_plan_free(plan);
    return pear_pe_diagnostic(fd, "parser.return12", status);
}

NTSTATUS pear_pe_plan_read(int fd, struct pear_pe_plan **ret, struct pear_pe_image *image)
{
    return pear_pe_plan_read_target(fd, IMAGE_FILE_MACHINE_ARM64, ret, image);
}

static BOOL compatible(const struct pear_pe_slot *slot, const struct pear_pe_plan *plan)
{
    SIZE_T i, first = slot->offset / PAGE;
    if (plan->capacity > slot->capacity) return FALSE;
    for (i = 0; i < plan->page_count; ++i)
    {
        if (!(plan->pages[i] & PAGE_USED)) continue;
        if (plan->role != PEAR_PE_ROLE_GUEST_X64 && (plan->pages[i] & PV_EXEC))
        { if (arena.classes[first + i] == ORDINARY) return FALSE; }
        else if (arena.classes[first + i] == CODE) return FALSE;
    }
    return TRUE;
}

NTSTATUS pear_pe_slot_reserve(const struct pear_pe_plan *plan, ULONG_PTR low, ULONG_PTR high,
                             struct pear_pe_slot **ret, void **base, SIZE_T *capacity)
{
    struct pear_pe_slot *slot = NULL;
    unsigned int i;
    ULONG_PTR address;
    require_owner();
    if (!arena.mapping) return STATUS_NOT_SUPPORTED;
    if (!high) high = ~(ULONG_PTR)0;
    for (i = 0; i < arena.count; ++i)
    {
        struct pear_pe_slot *candidate = &arena.slots[i];
        address = (ULONG_PTR)arena.interior + candidate->offset;
        if (candidate->state != SLOT_RETIRED || candidate->generation == ~(ULONGLONG)0 ||
            address < low || address > high || plan->size - 1 > high - address || !compatible(candidate, plan)) continue;
        slot = candidate;
        break;
    }
    if (!slot)
    {
        if (arena.count == PEAR_ARENA_MAX_SLOTS || !extent(arena.used, plan->capacity, PEAR_ARENA_INTERIOR_BYTES))
            return STATUS_NO_MEMORY;
        address = (ULONG_PTR)arena.interior + arena.used;
        if (address < low || address > high || plan->size - 1 > high - address) return STATUS_CONFLICTING_ADDRESSES;
        slot = &arena.slots[arena.count++];
        slot->offset = arena.used;
        slot->capacity = plan->capacity;
        arena.used += plan->capacity;
    }
    slot->state = SLOT_PREPARING;
    ++slot->generation;
    slot->image_size = plan->size;
    slot->original_base = plan->original_base;
    slot->role = plan->role;
    *ret = slot;
    *base = arena.interior + slot->offset;
    *capacity = slot->capacity;
    return STATUS_SUCCESS;
}

static int unix_protection(BYTE value)
{
    int result = 0;
    if (value & PV_READ) result |= PROT_READ;
    if (value & (PV_WRITE | PV_COPY)) result |= PROT_READ | PROT_WRITE;
    if (value & PV_EXEC) result |= PROT_EXEC;
    return result;
}

ULONGLONG pear_pe_slot_generation(const struct pear_pe_slot *slot)
{
    return slot->generation;
}

void pear_pe_slot_retire(struct pear_pe_slot *slot, ULONGLONG generation)
{
    SIZE_T i, first = slot->offset / PAGE;
    require_owner();
    if (slot->generation != generation || (slot->state != SLOT_PREPARING &&
        slot->state != SLOT_PUBLISHED && slot->state != SLOT_FAILED))
        pear_pe_arena_fatal("invalid retirement state");
    /* Never return a failed retirement to Wine's free_modref, which has already
     * consumed loader ownership. A partial OS failure is terminal for this
     * owned launch; no corrupted live process or reusable slot is reported. */
    for (i = 0; i < slot->capacity / PAGE; ++i)
    {
        if (arena.classes[first + i] == ORDINARY)
        {
            if (mprotect(arena.interior + slot->offset + i * PAGE, PAGE, PROT_READ | PROT_WRITE))
                pear_pe_arena_fatal("retirement_data_write");
            memset(arena.interior + slot->offset + i * PAGE, 0, PAGE);
        }
        if (mprotect(arena.interior + slot->offset + i * PAGE, PAGE, PROT_NONE))
            pear_pe_arena_fatal("retirement protection");
        arena.protection[first + i] = PROT_NONE;
        arena.vprot[first + i] = 0;
    }
    if (!actual_protection(arena.interior + slot->offset, slot->capacity, PROT_NONE))
        pear_pe_arena_fatal("retirement_verification");
    slot->state = SLOT_RETIRED;
    arena_event("arena_retire", ",\"slot\":%u,\"slot_generation\":%llu,\"base\":%llu,\"size\":%llu,\"capacity\":%llu",
                (unsigned)(slot - arena.slots), (unsigned long long)slot->generation,
                (unsigned long long)(ULONG_PTR)(arena.interior + slot->offset),
                (unsigned long long)slot->image_size, (unsigned long long)slot->capacity);
}

static NTSTATUS relocate_staging(struct pear_pe_plan *plan, ULONG_PTR address)
{
    SIZE_T i;
    ULONGLONG delta = (ULONGLONG)address - plan->original_base;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(plan->staging + plan->nt_offset);
    if (plan->relocated) return STATUS_INVALID_PARAMETER;
    for (i = 0; i < plan->relocation_count; ++i)
    {
        ULONGLONG value;
        memcpy(&value, plan->staging + plan->relocations[i], sizeof(value));
        value += delta;
        memcpy(plan->staging + plan->relocations[i], &value, sizeof(value));
    }
    nt->OptionalHeader.ImageBase = (ULONGLONG)address;
    plan->relocated = TRUE;
    return STATUS_SUCCESS;
}

NTSTATUS pear_pe_slot_publish(struct pear_pe_slot *slot, ULONGLONG generation, struct pear_pe_plan *plan)
{
    SIZE_T i, first = slot->offset / PAGE, code_pages = 0, data_pages = 0;
    unsigned char *base = arena.interior + slot->offset;
    require_owner();
    if (slot->generation != generation || slot->state != SLOT_PREPARING || slot->image_size != plan->size || !compatible(slot, plan))
        return STATUS_INVALID_PARAMETER;
    /* The loader completes EC registration before returning an entry. Pure
     * guest image bytes retain logical PE execution flags but native NX pages. */
    if (plan->role < PEAR_PE_ROLE_NATIVE || plan->role > PEAR_PE_ROLE_GUEST_X64) return STATUS_NOT_SUPPORTED;
    if (relocate_staging(plan, (ULONG_PTR)base)) return STATUS_INVALID_PARAMETER;
    for (i = 0; i < plan->page_count; ++i)
    {
        BYTE value = plan->pages[i];
        if (!(value & PAGE_USED)) continue;
        if ((plan->role == PEAR_PE_ROLE_GUEST_X64 || !(value & PV_EXEC)) && arena.classes[first + i] == VIRGIN)
        {
            void *actual = mmap(base + i * PAGE, PAGE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
            if (actual != base + i * PAGE) goto failed;
            arena.classes[first + i] = ORDINARY;
        }
        else
        {
            if (mprotect(base + i * PAGE, PAGE, PROT_READ | PROT_WRITE)) goto failed;
            if (plan->role != PEAR_PE_ROLE_GUEST_X64 && (value & PV_EXEC)) arena.classes[first + i] = CODE;
        }
        arena.protection[first + i] = PROT_READ | PROT_WRITE;
        memcpy(base + i * PAGE, plan->staging + i * PAGE, PAGE);
    }
    /* No entry is visible to PE until every page has its final protection. */
    for (i = 0; i < plan->page_count; ++i)
    {
        BYTE value = plan->pages[i];
        int protection = (value & PAGE_USED) ? unix_protection(plan->role == PEAR_PE_ROLE_GUEST_X64 ? value & ~PV_EXEC : value) : PROT_NONE;
        if ((protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
            pear_pe_arena_fatal("invalid writable executable plan");
        if (mprotect(base + i * PAGE, PAGE, protection)) goto failed;
        arena.protection[first + i] = protection;
        arena.vprot[first + i] = (value & ~PAGE_USED) | ((value & PAGE_USED) ? PV_COMMITTED : 0);
#ifdef __APPLE__
        if (plan->role != PEAR_PE_ROLE_GUEST_X64 && (value & PV_EXEC)) sys_icache_invalidate(base + i * PAGE, PAGE);
#endif
    }
    for (i = 0; i < plan->page_count; ++i)
    {
        if (!actual_protection(base + i * PAGE, PAGE, arena.protection[first + i])) goto failed;
        if (plan->role != PEAR_PE_ROLE_GUEST_X64 && (plan->pages[i] & PV_EXEC)) ++code_pages;
        else if (plan->pages[i] & PAGE_USED) ++data_pages;
    }
    slot->state = SLOT_PUBLISHED;
    arena_event("arena_publish", ",\"slot\":%u,\"slot_generation\":%llu,\"base\":%llu,\"size\":%llu,\"capacity\":%llu,"
                "\"code_pages\":%llu,\"data_pages\":%llu,\"relocations\":%llu,\"reused\":%s,\"original_base\":%llu",
                (unsigned)(slot - arena.slots), (unsigned long long)slot->generation,
                (unsigned long long)(ULONG_PTR)base, (unsigned long long)slot->image_size,
                (unsigned long long)slot->capacity, (unsigned long long)code_pages, (unsigned long long)data_pages,
                (unsigned long long)plan->relocation_count, slot->generation > 1 ? "true" : "false",
                (unsigned long long)slot->original_base);
    return STATUS_SUCCESS;
failed:
    arena_event("arena_failure", ",\"operation\":\"publish\",\"status\":%u,\"errno\":%d,\"slot\":%u,\"slot_generation\":%llu",
                (unsigned)STATUS_ACCESS_DENIED, errno, (unsigned)(slot - arena.slots),
                (unsigned long long)slot->generation);
    slot->state = SLOT_FAILED;
    return STATUS_ACCESS_DENIED;
}

NTSTATUS pear_pe_slot_protect(struct pear_pe_slot *slot, ULONGLONG generation, const void *pointer, SIZE_T size, BYTE vprot)
{
    SIZE_T offset = (ULONG_PTR)pointer - ((ULONG_PTR)arena.interior + slot->offset), i, first;
    int protection = unix_protection(slot->role == PEAR_PE_ROLE_GUEST_X64 ? vprot & ~PV_EXEC : vprot);
    require_owner();
    if (slot->generation != generation || slot->state != SLOT_PUBLISHED || (offset | size) & (PAGE - 1) || !size ||
        !extent(offset, size, slot->image_size) || vprot & ~(PV_READ | PV_WRITE | PV_COPY | PV_EXEC | PV_COMMITTED))
        return STATUS_INVALID_PAGE_PROTECTION;
    first = (slot->offset + offset) / PAGE;
    for (i = 0; i < size / PAGE; ++i)
    {
        if (!(arena.vprot[first + i] & PV_COMMITTED)) return STATUS_NOT_COMMITTED;
        if (arena.classes[first + i] == CODE)
        {
            /* Immutable published code cannot be changed or re-enabled by PE. */
            if (protection != (PROT_READ | PROT_EXEC) || arena.protection[first + i] != protection)
                return STATUS_INVALID_PAGE_PROTECTION;
        }
        else if (arena.classes[first + i] != ORDINARY || (protection & PROT_EXEC))
            return STATUS_INVALID_PAGE_PROTECTION;
    }
    for (i = 0; i < size / PAGE; ++i)
        if (mprotect((unsigned char *)pointer + i * PAGE, PAGE, protection))
        {
            SIZE_T restore;
            int saved = errno;
            for (restore = 0; restore < i; ++restore)
                if (mprotect((unsigned char *)pointer + restore * PAGE, PAGE, arena.protection[first + restore]))
                    pear_pe_arena_fatal("ordinary_protection_rollback");
            for (restore = 0; restore < size / PAGE; ++restore)
                if (!actual_protection((unsigned char *)pointer + restore * PAGE, PAGE, arena.protection[first + restore]))
                    pear_pe_arena_fatal("ordinary_rollback_verification");
            errno = saved;
            return STATUS_ACCESS_DENIED;
        }
    if (!actual_protection(pointer, size, protection)) pear_pe_arena_fatal("ordinary_protection_verification");
    for (i = 0; i < size / PAGE; ++i)
    {
        arena.protection[first + i] = protection;
        arena.vprot[first + i] = vprot;
    }
    return STATUS_SUCCESS;
}

BYTE pear_pe_slot_vprot(const struct pear_pe_slot *slot, ULONGLONG generation, SIZE_T offset)
{
    if (slot->generation != generation || offset >= slot->image_size || offset % PAGE || slot->state != SLOT_PUBLISHED)
        pear_pe_arena_fatal("invalid published page query");
    return arena.vprot[(slot->offset + offset) / PAGE];
}

BOOL pear_pe_arena_matches_protection(const void *base, SIZE_T size, int protection)
{
    ULONG_PTR address = (ULONG_PTR)base, start = (ULONG_PTR)arena.interior;
    SIZE_T i, first;
    if (!arena.mapping || address < start || (address | size) & (PAGE - 1) ||
        !extent(address - start, size, PEAR_ARENA_TOTAL_BYTES)) return FALSE;
    first = (address - start) / PAGE;
    for (i = 0; i < size / PAGE; ++i) if (arena.protection[first + i] != protection) return FALSE;
    return TRUE;
}

/* Original Pear Stage 4 dynamic-code owner. The caller holds virtual_mutex
 * and supplies quiescence before changing/freeing code. A Windows allocation
 * declared executable at reserve time gets a fixed private slot; ordinary
 * anonymous memory is never remapped into this authorization domain.
 * Immutable PE CODE and converted ORDINARY backing retain their old rules. */
static BOOL dynamic_index(const struct pear_dynamic_slot *slot, SIZE_T *index)
{
    ULONG_PTR value = (ULONG_PTR)slot, first = (ULONG_PTR)arena.dynamic;
    if (value < first || value - first >= sizeof(arena.dynamic) ||
        (value - first) % sizeof(*slot)) return FALSE;
    *index = (value - first) / sizeof(*slot);
    return TRUE;
}

static unsigned char *dynamic_base(SIZE_T index)
{
    return arena.interior + PEAR_ARENA_INTERIOR_BYTES + index * PEAR_ARENA_DYNAMIC_SLOT_BYTES;
}

static NTSTATUS dynamic_range(struct pear_dynamic_slot *slot, ULONGLONG generation,
                              const void *pointer, SIZE_T size, SIZE_T *index, SIZE_T *first)
{
    ULONG_PTR address = (ULONG_PTR)pointer, start;
    require_owner();
    if (!arena.mapping || !dynamic_index(slot, index) || !slot->active ||
        !generation || slot->generation != generation || !size || (address | size) & (PAGE - 1))
        return STATUS_INVALID_PARAMETER;
    start = (ULONG_PTR)dynamic_base(*index);
    if (address < start || !extent(address - start, size, slot->size)) return STATUS_INVALID_PARAMETER;
    *first = (address - (ULONG_PTR)arena.interior) / PAGE;
    return STATUS_SUCCESS;
}

NTSTATUS pear_dynamic_reserve(SIZE_T size, struct pear_dynamic_slot **ret, void **base)
{
    SIZE_T i, page, first;
    struct pear_dynamic_slot *slot;
    require_owner();
    if (!arena.mapping) return STATUS_NOT_SUPPORTED;
    if (!size || size > PEAR_ARENA_DYNAMIC_SLOT_BYTES || size & (PAGE - 1)) return STATUS_INVALID_PARAMETER;
    for (i = 0; i < PEAR_ARENA_DYNAMIC_SLOTS; ++i)
    {
        slot = &arena.dynamic[i];
        if (slot->active || slot->generation == ~(ULONGLONG)0) continue;
        if (!actual_protection(dynamic_base(i), PEAR_ARENA_DYNAMIC_SLOT_BYTES, PROT_NONE))
            pear_pe_arena_fatal("dynamic_reservation_protection");
        first = (PEAR_ARENA_INTERIOR_BYTES + i * PEAR_ARENA_DYNAMIC_SLOT_BYTES) / PAGE;
        for (page = 0; page < PEAR_ARENA_DYNAMIC_SLOT_BYTES / PAGE; ++page)
        {
            if (arena.classes[first + page] != VIRGIN && arena.classes[first + page] != DYNAMIC)
                pear_pe_arena_fatal("dynamic_backing_class");
            arena.classes[first + page] = DYNAMIC;
            arena.protection[first + page] = PROT_NONE;
            arena.vprot[first + page] = 0;
        }
        slot->size = size;
        ++slot->generation;
        slot->active = TRUE;
        *ret = slot;
        *base = dynamic_base(i);
        dynamic_event("dynamic_reserve", ",\"slot\":%u,\"slot_generation\":%llu,\"base\":%llu,\"size\":%llu,\"capacity\":65536",
                    (unsigned)i, (unsigned long long)slot->generation, (unsigned long long)(ULONG_PTR)*base,
                    (unsigned long long)size);
        return STATUS_SUCCESS;
    }
    return STATUS_NO_MEMORY;
}

ULONGLONG pear_dynamic_generation(const struct pear_dynamic_slot *slot)
{
    return slot->generation;
}

static NTSTATUS dynamic_rollback(const char *operation, struct pear_dynamic_slot *slot, SIZE_T index,
                                 const void *pointer, SIZE_T size, SIZE_T first, int saved)
{
    SIZE_T i;
    for (i = 0; i < size / PAGE; ++i)
        if (mprotect((unsigned char *)pointer + i * PAGE, PAGE, arena.protection[first + i]))
            pear_pe_arena_fatal("dynamic_protection_rollback");
    for (i = 0; i < size / PAGE; ++i)
        if (!actual_protection((unsigned char *)pointer + i * PAGE, PAGE, arena.protection[first + i]))
            pear_pe_arena_fatal("dynamic_rollback_verification");
    errno = saved;
    dynamic_event("dynamic_failure", ",\"operation\":\"%s\",\"status\":%u,\"errno\":%d,\"slot\":%u,\"slot_generation\":%llu",
                operation, (unsigned)STATUS_ACCESS_DENIED, saved, (unsigned)index,
                (unsigned long long)slot->generation);
    return STATUS_ACCESS_DENIED;
}

NTSTATUS pear_dynamic_protect(struct pear_dynamic_slot *slot, ULONGLONG generation,
                              const void *pointer, SIZE_T size, BYTE vprot, BOOL commit)
{
    SIZE_T index, first, i;
    NTSTATUS status = dynamic_range(slot, generation, pointer, size, &index, &first);
    int protection = unix_protection(vprot);
    if (status) return status;
    if (vprot != PV_COMMITTED && vprot != (PV_COMMITTED | PV_READ) &&
        vprot != (PV_COMMITTED | PV_READ | PV_WRITE) && vprot != (PV_COMMITTED | PV_READ | PV_EXEC))
        return STATUS_INVALID_PAGE_PROTECTION;
    for (i = 0; i < size / PAGE; ++i)
    {
        if (arena.classes[first + i] != DYNAMIC) return STATUS_INVALID_PAGE_PROTECTION;
        if (!commit && !(arena.vprot[first + i] & PV_COMMITTED)) return STATUS_NOT_COMMITTED;
    }
    for (i = 0; i < size / PAGE; ++i)
    {
        unsigned char *page = (unsigned char *)pointer + i * PAGE;
        /* Recommit of an already committed page preserves all existing data. */
        if (commit && !(arena.vprot[first + i] & PV_COMMITTED))
        {
            if (mprotect(page, PAGE, PROT_READ | PROT_WRITE))
                return dynamic_rollback("commit_prepare", slot, index, pointer, size, first, errno);
            if (!actual_protection(page, PAGE, PROT_READ | PROT_WRITE))
                pear_pe_arena_fatal("dynamic_commit_prepare_verification");
            memset(page, 0, PAGE);
        }
        if (mprotect(page, PAGE, protection))
            return dynamic_rollback(commit ? "commit" : "protect", slot, index, pointer, size, first, errno);
        if (!actual_protection(page, PAGE, protection)) pear_pe_arena_fatal("dynamic_protection_verification");
    }
    for (i = 0; i < size / PAGE; ++i)
    {
        arena.protection[first + i] = protection;
        arena.vprot[first + i] = vprot;
    }
    dynamic_event("dynamic_protect", ",\"operation\":\"%s\",\"slot\":%u,\"slot_generation\":%llu,\"offset\":%llu,"
                "\"size\":%llu,\"vprot\":%u,\"unix_protection\":%u,\"committed_pages\":%llu,\"protection_verified\":true",
                commit ? "commit" : "protect", (unsigned)index, (unsigned long long)generation,
                (unsigned long long)((ULONG_PTR)pointer - (ULONG_PTR)dynamic_base(index)),
                (unsigned long long)size, (unsigned)vprot, (unsigned)protection, (unsigned long long)(size / PAGE));
    return STATUS_SUCCESS;
}

NTSTATUS pear_dynamic_decommit(struct pear_dynamic_slot *slot, ULONGLONG generation,
                               const void *pointer, SIZE_T size)
{
    SIZE_T index, first, i;
    NTSTATUS status = dynamic_range(slot, generation, pointer, size, &index, &first);
    if (status) return status;
    for (i = 0; i < size / PAGE; ++i)
        if (arena.classes[first + i] != DYNAMIC) return STATUS_INVALID_PAGE_PROTECTION;
    /* Acquire all write permissions before destroying any old contents. */
    for (i = 0; i < size / PAGE; ++i)
    {
        unsigned char *page = (unsigned char *)pointer + i * PAGE;
        if (mprotect(page, PAGE, PROT_READ | PROT_WRITE))
            return dynamic_rollback("decommit_prepare", slot, index, pointer, size, first, errno);
        if (!actual_protection(page, PAGE, PROT_READ | PROT_WRITE))
            pear_pe_arena_fatal("dynamic_decommit_prepare_verification");
    }
    for (i = 0; i < size / PAGE; ++i)
    {
        unsigned char *page = (unsigned char *)pointer + i * PAGE;
        memset(page, 0, PAGE);
        /* Once bytes are scrubbed, an incomplete revoke cannot be rolled back
         * to the original executable contents. End the owned process instead. */
        if (mprotect(page, PAGE, PROT_NONE)) pear_pe_arena_fatal("dynamic_decommit_revoke");
        if (!actual_protection(page, PAGE, PROT_NONE)) pear_pe_arena_fatal("dynamic_decommit_verification");
    }
    for (i = 0; i < size / PAGE; ++i)
    {
        arena.protection[first + i] = PROT_NONE;
        arena.vprot[first + i] = 0;
    }
    dynamic_event("dynamic_decommit", ",\"slot\":%u,\"slot_generation\":%llu,\"offset\":%llu,\"size\":%llu,"
                "\"zeroed_pages\":%llu,\"protection_verified\":true", (unsigned)index,
                (unsigned long long)generation, (unsigned long long)((ULONG_PTR)pointer - (ULONG_PTR)dynamic_base(index)),
                (unsigned long long)size, (unsigned long long)(size / PAGE));
    return STATUS_SUCCESS;
}

NTSTATUS pear_dynamic_release(struct pear_dynamic_slot *slot, ULONGLONG generation)
{
    SIZE_T index;
    NTSTATUS status;
    require_owner();
    if (!dynamic_index(slot, &index) || !slot->active || generation != slot->generation)
        return STATUS_INVALID_PARAMETER;
    if ((status = pear_dynamic_decommit(slot, generation, dynamic_base(index), slot->size))) return status;
    if (!actual_protection(dynamic_base(index), PEAR_ARENA_DYNAMIC_SLOT_BYTES, PROT_NONE))
        pear_pe_arena_fatal("dynamic_release_verification");
    slot->active = FALSE;
    dynamic_event("dynamic_release", ",\"slot\":%u,\"slot_generation\":%llu,\"base\":%llu,\"size\":%llu,"
                "\"capacity\":65536,\"protection_verified\":true", (unsigned)index, (unsigned long long)generation,
                (unsigned long long)(ULONG_PTR)dynamic_base(index), (unsigned long long)slot->size);
    return STATUS_SUCCESS;
}

/* VirtualQuery may expose logically free dynamic slots while Wine's internal
 * reservation view continues to protect the one MAP_JIT allocation from mmap. */
BOOL pear_dynamic_free_range(const void *pointer, void **start, void **end)
{
    ULONG_PTR address = (ULONG_PTR)pointer, first = (ULONG_PTR)arena.interior + PEAR_ARENA_INTERIOR_BYTES;
    SIZE_T index, offset;
    require_owner();
    if (!arena.mapping || address < first || address - first >= PEAR_ARENA_DYNAMIC_BYTES) return FALSE;
    index = (address - first) / PEAR_ARENA_DYNAMIC_SLOT_BYTES;
    offset = (address - first) % PEAR_ARENA_DYNAMIC_SLOT_BYTES;
    if (arena.dynamic[index].active && offset < arena.dynamic[index].size) return FALSE;
    *start = dynamic_base(index) + (arena.dynamic[index].active ? arena.dynamic[index].size : 0);
    *end = dynamic_base(index) + PEAR_ARENA_DYNAMIC_SLOT_BYTES;
    return TRUE;
}

/* Original Pear FEX backing extension, MIT-licensed. The baseline PE/dynamic
 * arrays retain their original PAGES bound. New class identity/protection is
 * stored in the separately bounded owner, not expanded three-byte arrays. */
#include "pear_fex_memory_private.h"

static int fex_backing_range(uint64_t offset, uint64_t size)
{
    uint64_t shared = PEAR_ARENA_TOTAL_BYTES + PEAR_FEX_MEMORY_SEPARATOR_BYTES;
    uint64_t dispatcher = shared + PEAR_FEX_MEMORY_SHARED_BYTES + PEAR_FEX_MEMORY_SEPARATOR_BYTES;
    if (!size || (offset | size) & (PAGE - 1)) return 0;
    if (offset >= shared && offset - shared <= PEAR_FEX_MEMORY_SHARED_BYTES &&
        size <= PEAR_FEX_MEMORY_SHARED_BYTES - (offset-shared)) return 1;
    return offset >= dispatcher && offset-dispatcher <= PEAR_FEX_MEMORY_DISPATCHER_BYTES &&
           size <= PEAR_FEX_MEMORY_DISPATCHER_BYTES - (offset-dispatcher);
}

int pear_fex_backing_query(uint64_t offset, uint64_t size, uint32_t protection,
                           struct pear_fex_memory_error *error)
{
#if defined(PEAR_NATIVE_PE_PUBLICATION) && defined(__APPLE__) && defined(__aarch64__)
    mach_vm_address_t cursor, end;
    vm_prot_t expected;
    memset(error, 0, sizeof(*error));
    if (!arena.mapping || arena.owner_pid != getpid() || !fex_backing_range(offset, size) ||
        protection > PEAR_FEX_PROTECTION_RX) return 1;
    expected = protection == PEAR_FEX_PROTECTION_NONE ? PROT_NONE :
               protection == PEAR_FEX_PROTECTION_RW_NX ? PROT_READ|PROT_WRITE : PROT_READ|PROT_EXEC;
    cursor = (mach_vm_address_t)(uintptr_t)arena.interior + offset;
    end = cursor + size;
    while (cursor < end)
    {
        mach_vm_address_t address = cursor;
        mach_vm_size_t length = 0;
        vm_region_basic_info_data_64_t info = {0};
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;
        kern_return_t code = mach_vm_region(mach_task_self(), &address, &length, VM_REGION_BASIC_INFO_64,
                                            (vm_region_info_t)&info, &count, &object);
        if (object != MACH_PORT_NULL)
        {
            kern_return_t released = mach_port_deallocate(mach_task_self(), object);
            if (code == KERN_SUCCESS && released != KERN_SUCCESS) code = released;
        }
        if (code != KERN_SUCCESS)
        { error->domain = PEAR_FEX_ERROR_MACH; error->code = (int32_t)code; return 1; }
        if (count != VM_REGION_BASIC_INFO_COUNT_64 || address > cursor || !length || address > UINT64_MAX-length || address+length <= cursor ||
            info.protection != expected || (info.max_protection & expected) != expected) return 1;
        cursor = min(address+length, end);
    }
    return 0;
#else
    (void)offset; (void)size; (void)protection; memset(error, 0, sizeof(*error));
    return 1;
#endif
}

int pear_fex_backing_protect(uint64_t offset, uint64_t size, uint32_t protection,
                             struct pear_fex_memory_error *error)
{
#if defined(PEAR_NATIVE_PE_PUBLICATION) && defined(__APPLE__) && defined(__aarch64__)
    int flags;
    memset(error, 0, sizeof(*error));
    if (!arena.mapping || arena.owner_pid != getpid() || !fex_backing_range(offset, size) ||
        protection > PEAR_FEX_PROTECTION_RX) return 1;
    flags = protection == PEAR_FEX_PROTECTION_NONE ? PROT_NONE :
            protection == PEAR_FEX_PROTECTION_RW_NX ? PROT_READ|PROT_WRITE : PROT_READ|PROT_EXEC;
    if (mprotect(arena.interior+offset, size, flags))
    { error->domain = PEAR_FEX_ERROR_ERRNO; error->code = errno; return 1; }
    return pear_fex_backing_query(offset, size, protection, error);
#else
    (void)offset; (void)size; (void)protection; memset(error, 0, sizeof(*error));
    return 1;
#endif
}

int pear_fex_backing_initialize(struct pear_fex_memory_backing *backing,
                                struct pear_fex_memory_error *error)
{
    void *base;
    SIZE_T size;
    NTSTATUS status;
    memset(backing, 0, sizeof(*backing)); memset(error, 0, sizeof(*error));
    status = pear_pe_arena_initialize(&base, &size);
    if (status)
    { error->domain = PEAR_FEX_ERROR_NTSTATUS; error->code = (int32_t)status; return 1; }
    if (size != PEAR_ARENA_MAPPING_BYTES || !arena.interior || arena.owner_pid != getpid() ||
        sysconf(_SC_PAGESIZE) != PAGE) return 1;
    backing->owner_pid = getpid(); backing->private_base = (uintptr_t)arena.interior;
    backing->shared_offset = PEAR_ARENA_TOTAL_BYTES + PEAR_FEX_MEMORY_SEPARATOR_BYTES;
    backing->dispatcher_offset = backing->shared_offset + PEAR_FEX_MEMORY_SHARED_BYTES + PEAR_FEX_MEMORY_SEPARATOR_BYTES;
    if (pear_fex_backing_query(backing->shared_offset, PEAR_FEX_MEMORY_SHARED_BYTES, PEAR_FEX_PROTECTION_NONE, error) ||
        pear_fex_backing_query(backing->dispatcher_offset, PEAR_FEX_MEMORY_DISPATCHER_BYTES, PEAR_FEX_PROTECTION_NONE, error))
    { memset(backing, 0, sizeof(*backing)); return 1; }
    backing->capabilities = PEAR_FEX_SINGLE_MAP_JIT | PEAR_FEX_OBSERVED_4K;
    return 0;
}

/* Observe existing backing only; unlike initialize this cannot construct MAP_JIT. */
int pear_fex_backing_metadata(struct pear_fex_memory_metadata *out, uint64_t *mapping_base,
                              struct pear_fex_memory_error *error)
{
    if (!arena.mapping || !arena.interior || arena.owner_pid != getpid())
    { error->domain = PEAR_FEX_ERROR_ERRNO; error->code = EINVAL; return 1; }
    *mapping_base = (uintptr_t)arena.mapping;
    out->mapping_bytes = PEAR_ARENA_MAPPING_BYTES;
    out->baseline_mapping_bytes = PEAR_ARENA_TOTAL_BYTES + PEAR_ARENA_ALIGNMENT;
    out->page_bytes = PEAR_ARENA_PAGE_BYTES;
    return 0;
}
