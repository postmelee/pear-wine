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
#define PAGES (PEAR_ARENA_INTERIOR_BYTES / PAGE)
#define PV_READ 0x01
#define PV_WRITE 0x02
#define PV_EXEC 0x04
#define PV_COPY 0x08
#define PV_COMMITTED 0x20
#define PAGE_USED 0x80
#define MAX_SECTIONS 96u
/* A complete 8-byte destination cannot occur more than once per image. */
#define MAX_RELOCATIONS (PEAR_ARENA_MAX_IMAGE_BYTES / sizeof(ULONGLONG))
enum backing { VIRGIN, CODE, ORDINARY };
enum slot_state { SLOT_RESERVED, SLOT_PREPARING, SLOT_PUBLISHED, SLOT_FAILED, SLOT_RETIRED };
struct pear_pe_plan
{
    unsigned char *staging, *pages;
    ULONG *relocations;
    SIZE_T size, capacity, page_count, relocation_count, header_bytes;
    SIZE_T nt_offset;
    ULONGLONG original_base;
    BOOL relocated;
};
struct pear_pe_slot
{
    SIZE_T offset, capacity, image_size;
    ULONGLONG generation, original_base;
    enum slot_state state;
};
static struct
{
    unsigned char *mapping, *interior;
    unsigned char *classes, *protection, *vprot;
    struct pear_pe_slot slots[PEAR_ARENA_MAX_SLOTS];
    unsigned int count;
    SIZE_T used;
    BOOL attempted;
    pid_t owner_pid;
    unsigned long long sequence;
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
        SIZE_T field = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, SecurityCookie);
        memcpy(&length, plan->staging + dir->VirtualAddress, sizeof(length));
        if (extent(field, sizeof(cookie), min((SIZE_T)length, (SIZE_T)dir->Size)))
        {
            memcpy(&cookie, plan->staging + dir->VirtualAddress + field, sizeof(cookie));
            if (cookie && !ordinary_va(plan, cookie, sizeof(cookie))) return STATUS_INVALID_IMAGE_FORMAT;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS pear_pe_plan_read(int fd, struct pear_pe_plan **ret, struct pear_pe_image *image)
{
    struct stat stat;
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS64 header, *nt;
    IMAGE_SECTION_HEADER *sections;
    const IMAGE_DATA_DIRECTORY *relocs, *cfg, *dir;
    struct pear_pe_plan *plan = NULL;
    NTSTATUS status = STATUS_INVALID_IMAGE_FORMAT;
    SIZE_T section_offset, section_bytes, header_end, i, j;
    *ret = NULL;
    if (fstat(fd, &stat) || stat.st_size < 0 || !S_ISREG(stat.st_mode)) return status;
    if (!extent(0, sizeof(dos), stat.st_size) ||
        read_exact(fd, &dos, sizeof(dos), 0) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < (LONG)sizeof(dos) || dos.e_lfanew % _Alignof(IMAGE_NT_HEADERS64) ||
        !extent(dos.e_lfanew, sizeof(header), stat.st_size) ||
        read_exact(fd, &header, sizeof(header), dos.e_lfanew)) return status;
    if (header.Signature != IMAGE_NT_SIGNATURE || header.FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64 ||
        header.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        header.FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64) ||
        !header.FileHeader.NumberOfSections || header.FileHeader.NumberOfSections > MAX_SECTIONS ||
        header.OptionalHeader.NumberOfRvaAndSizes > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return status;
    if (header.OptionalHeader.ImageBase & (PEAR_ARENA_ALIGNMENT - 1)) return status;
    if (!(header.FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) ||
        header.FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED ||
        !(header.OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return STATUS_NOT_SUPPORTED;
    if ((header.OptionalHeader.SectionAlignment != PAGE && header.OptionalHeader.SectionAlignment != PEAR_ARENA_ALIGNMENT) ||
        header.OptionalHeader.FileAlignment < 512 || header.OptionalHeader.FileAlignment > header.OptionalHeader.SectionAlignment ||
        (header.OptionalHeader.FileAlignment & (header.OptionalHeader.FileAlignment - 1))) return STATUS_NOT_SUPPORTED;
    if (!header.OptionalHeader.SizeOfImage || header.OptionalHeader.SizeOfImage % header.OptionalHeader.SectionAlignment ||
        header.OptionalHeader.SizeOfImage > PEAR_ARENA_MAX_IMAGE_BYTES) return STATUS_NOT_SUPPORTED;
    section_offset = (SIZE_T)dos.e_lfanew + sizeof(header);
    section_bytes = (SIZE_T)header.FileHeader.NumberOfSections * sizeof(*sections);
    if (header.OptionalHeader.SizeOfHeaders % header.OptionalHeader.FileAlignment ||
        !extent(section_offset, section_bytes, header.OptionalHeader.SizeOfHeaders) ||
        !extent(0, header.OptionalHeader.SizeOfHeaders, stat.st_size) ||
        !rounded(header.OptionalHeader.SizeOfHeaders, header.OptionalHeader.SectionAlignment, &header_end) ||
        !extent(0, header_end, header.OptionalHeader.SizeOfImage)) return status;
    if (!(plan = calloc(1, sizeof(*plan)))) return STATUS_NO_MEMORY;
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
    if (cfg)
    {
        SIZE_T field = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY64, CHPEMetadataPointer);
        ULONG cfg_size;
        ULONGLONG chpe = 0;
        if (cfg->Size < sizeof(cfg_size)) { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
        memcpy(&cfg_size, plan->staging + cfg->VirtualAddress, sizeof(cfg_size));
        if (cfg_size < sizeof(cfg_size) || cfg_size > cfg->Size) { status = STATUS_INVALID_IMAGE_FORMAT; goto done; }
        if (extent(field, sizeof(chpe), cfg_size)) memcpy(&chpe, plan->staging + cfg->VirtualAddress + field, sizeof(chpe));
        if (chpe) { status = STATUS_NOT_SUPPORTED; goto done; }
    }
    if ((status = check_loader_data(plan, nt)) || (status = parse_relocations(plan, relocs))) goto done;
    image->size = plan->size;
    image->original_base = plan->original_base;
    image->entry_rva = header.OptionalHeader.AddressOfEntryPoint;
    image->machine = header.FileHeader.Machine;
    *ret = plan;
    return STATUS_SUCCESS;
done:
    pear_pe_plan_free(plan);
    return status;
}

static BOOL compatible(const struct pear_pe_slot *slot, const struct pear_pe_plan *plan)
{
    SIZE_T i, first = slot->offset / PAGE;
    if (plan->capacity > slot->capacity) return FALSE;
    for (i = 0; i < plan->page_count; ++i)
    {
        if (!(plan->pages[i] & PAGE_USED)) continue;
        if (plan->pages[i] & PV_EXEC)
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
    if (relocate_staging(plan, (ULONG_PTR)base)) return STATUS_INVALID_PARAMETER;
    for (i = 0; i < plan->page_count; ++i)
    {
        BYTE value = plan->pages[i];
        if (!(value & PAGE_USED)) continue;
        if (!(value & PV_EXEC) && arena.classes[first + i] == VIRGIN)
        {
            void *actual = mmap(base + i * PAGE, PAGE, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
            if (actual != base + i * PAGE) goto failed;
            arena.classes[first + i] = ORDINARY;
        }
        else
        {
            if (mprotect(base + i * PAGE, PAGE, PROT_READ | PROT_WRITE)) goto failed;
            if (value & PV_EXEC) arena.classes[first + i] = CODE;
        }
        arena.protection[first + i] = PROT_READ | PROT_WRITE;
        memcpy(base + i * PAGE, plan->staging + i * PAGE, PAGE);
    }
    /* No entry is visible to PE until every page has its final protection. */
    for (i = 0; i < plan->page_count; ++i)
    {
        BYTE value = plan->pages[i];
        int protection = (value & PAGE_USED) ? unix_protection(value) : PROT_NONE;
        if ((protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC))
            pear_pe_arena_fatal("invalid writable executable plan");
        if (mprotect(base + i * PAGE, PAGE, protection)) goto failed;
        arena.protection[first + i] = protection;
        arena.vprot[first + i] = (value & ~PAGE_USED) | ((value & PAGE_USED) ? PV_COMMITTED : 0);
#ifdef __APPLE__
        if (value & PV_EXEC) sys_icache_invalidate(base + i * PAGE, PAGE);
#endif
    }
    for (i = 0; i < plan->page_count; ++i)
    {
        if (!actual_protection(base + i * PAGE, PAGE, arena.protection[first + i])) goto failed;
        if (plan->pages[i] & PV_EXEC) ++code_pages;
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
    int protection = unix_protection(vprot);
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
        !extent(address - start, size, PEAR_ARENA_INTERIOR_BYTES)) return FALSE;
    first = (address - start) / PAGE;
    for (i = 0; i < size / PAGE; ++i) if (arena.protection[first + i] != protection) return FALSE;
    return TRUE;
}
