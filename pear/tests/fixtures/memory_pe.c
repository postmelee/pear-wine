/* Original Pear Stage 4 Windows memory fixture. SPDX-License-Identifier: MIT.
 * Real Wine APIs exercise ordinary 4 KiB pages and a separate declared dynamic
 * code protocol. No CRT, proprietary bytes or substitute native memory helper.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "stage4_protocol.h"

#define PAGE_BYTES 4096u
#define ST_GUARD UINT32_C(0x80000001)
#define ST_ACCESS UINT32_C(0xc0000005)
static unsigned error_step;
static DWORD error_code;
static uint64_t queries, sentinel_checks, zero_bytes, access_faults, guard_faults;
static uint64_t ordinary_commits, ordinary_protects, ordinary_decommits, ordinary_releases;
static uint64_t dynamic_reserves, dynamic_commits, dynamic_protects, dynamic_decommits, dynamic_releases;
static uint64_t flushes, code_calls, negatives, first_value, second_value, reuse_checks;
static volatile unsigned char *ordinary, *dynamic;
static ULONG_PTR first_dynamic_base;
static const uint32_t first_code[2] = { UINT32_C(0x52800540), UINT32_C(0xd65f03c0) }; /* mov w0,#42; ret */
static const uint32_t second_code[2] = { UINT32_C(0x52800a80), UINT32_C(0xd65f03c0) }; /* mov w0,#84; ret */

static int fail(unsigned step, DWORD code)
{
    if (!error_step) { error_step = step; error_code = code; }
    return 0;
}
static int api_fail(unsigned step) { return fail(step, GetLastError()); }
static int require(int condition, unsigned step) { return condition || fail(step, ERROR_INVALID_DATA); }

static int query(volatile unsigned char *address, ULONG_PTR allocation, DWORD state, DWORD protect,
                 DWORD allocation_protect, unsigned step)
{
    MEMORY_BASIC_INFORMATION info;
    SIZE_T bytes = VirtualQuery((void *)address, &info, sizeof(info));
    if (bytes != sizeof(info)) return bytes ? fail(step, ERROR_INVALID_DATA) : api_fail(step);
    if (!require(info.BaseAddress == (void *)address && info.RegionSize >= PAGE_BYTES &&
                 (ULONG_PTR)info.AllocationBase == allocation && info.State == state &&
                 info.Protect == protect && info.AllocationProtect == allocation_protect &&
                 info.Type == (state == MEM_FREE ? 0 : MEM_PRIVATE), step)) return 0;
    ++queries;
    return 1;
}

static unsigned char pattern(unsigned index, unsigned page)
{
    return (unsigned char)(index * 17u + page * 53u + 7u);
}
static int sentinels(unsigned step)
{
    for (unsigned i = 0; i < PAGE_BYTES; ++i)
        if (ordinary[i] != pattern(i, 0) || ordinary[2 * PAGE_BYTES + i] != pattern(i, 2))
            return fail(step, ERROR_INVALID_DATA);
    ++sentinel_checks;
    return 1;
}
static int zeros(volatile unsigned char *base, unsigned count, unsigned step)
{
    for (unsigned i = 0; i < count; ++i) if (base[i]) return fail(step, ERROR_INVALID_DATA);
    zero_bytes += count;
    return 1;
}
static int expect_fault(volatile unsigned char *address, unsigned access, unsigned code, unsigned step)
{
    int result = pear_expect_memory_fault(address, access, code);
    if (result) return fail(step, (DWORD)result);
    if (code == ST_GUARD) ++guard_faults;
    else ++access_faults;
    return 1;
}
static int protect_dynamic(DWORD protection, DWORD expected_old, unsigned step)
{
    DWORD old = 0;
    if (!VirtualProtect((void *)dynamic, PAGE_BYTES, protection, &old)) return api_fail(step);
    if (!require(old == expected_old, step)) return 0;
    ++dynamic_protects;
    return query(dynamic, (ULONG_PTR)dynamic, MEM_COMMIT, protection, PAGE_EXECUTE_READ, step);
}
static int rejected_protection(volatile unsigned char *address, DWORD protection, DWORD expected_error, unsigned step)
{
    DWORD old = 0;
    SetLastError(ERROR_SUCCESS);
    if (VirtualProtect((void *)address, PAGE_BYTES, protection, &old)) return fail(step, ERROR_INVALID_DATA);
    DWORD observed = GetLastError();
    if (observed != expected_error) return fail(step, observed ? observed : ERROR_INVALID_DATA);
    ++negatives;
    return 1;
}
static uint64_t code_hash(volatile const unsigned char *bytes)
{
    uint64_t value = UINT64_C(14695981039346656037);
    for (unsigned i = 0; i < 8; ++i) { value ^= bytes[i]; value *= UINT64_C(1099511628211); }
    return value;
}

/* The loaded argument is the actual Windows allocation. This non-inlined
 * exported boundary prevents a known expected result replacing the code call. */
__declspec(dllexport) __declspec(noinline) unsigned WINAPI PearDynamicCall(volatile unsigned char *address)
{
    unsigned (WINAPI *function)(void) = (void *)address;
    volatile unsigned result = function();
    return result;
}

static int publish_call(const uint32_t *code, unsigned expected, unsigned ordinal, unsigned step)
{
    volatile uint32_t *words = (volatile uint32_t *)dynamic;
    uint64_t hash;
    unsigned observed;
    words[0] = code[0];
    words[1] = code[1];
    if (!require(words[0] == code[0] && words[1] == code[1], step)) return 0;
    hash = code_hash(dynamic);
    if (!protect_dynamic(PAGE_EXECUTE_READ, PAGE_READWRITE, step)) return 0;
    if (!FlushInstructionCache(GetCurrentProcess(), (void *)dynamic, 8)) return api_fail(step);
    ++flushes;
    observed = PearDynamicCall(dynamic);
    ++code_calls;
    if (ordinal == 1) first_value = observed;
    else second_value = observed;
    {
        const char *const names[] = {"ordinal", "base", "bytes", "word0", "word1", "hash", "value"};
        const uint64_t values[] = {ordinal, (ULONG_PTR)dynamic, 8, words[0], words[1], hash, observed};
        if (!pear_emit("pear_dynamic_call", names, values, 7)) return fail(step, ERROR_WRITE_FAULT);
    }
    return require(observed == expected, step);
}

static int ordinary_checks(void)
{
    DWORD old;
    ordinary = VirtualAlloc(NULL, 3 * PAGE_BYTES, MEM_RESERVE, PAGE_NOACCESS);
    if (!ordinary) return api_fail(1);
    if (!require(!((ULONG_PTR)ordinary & 65535u), 1)) return 0;
    {
        const char *const names[] = {"base", "size", "page_bytes", "middle_offset", "allocation_protect"};
        const uint64_t values[] = {(ULONG_PTR)ordinary, 3 * PAGE_BYTES, PAGE_BYTES, PAGE_BYTES, PAGE_NOACCESS};
        if (!pear_emit("pear_memory_region", names, values, 5)) return fail(1, ERROR_WRITE_FAULT);
    }
    for (unsigned page = 0; page < 3; ++page)
        if (!query(ordinary + page * PAGE_BYTES, (ULONG_PTR)ordinary, MEM_RESERVE, 0, PAGE_NOACCESS, 2)) return 0;
    if (VirtualAlloc((void *)ordinary, 3 * PAGE_BYTES, MEM_COMMIT, PAGE_READWRITE) != ordinary) return api_fail(3);
    ++ordinary_commits;
    if (!zeros(ordinary, 3 * PAGE_BYTES, 4)) return 0;
    for (unsigned page = 0; page < 3; ++page)
    {
        for (unsigned i = 0; i < PAGE_BYTES; ++i) ordinary[page * PAGE_BYTES + i] = pattern(i, page);
        if (!query(ordinary + page * PAGE_BYTES, (ULONG_PTR)ordinary, MEM_COMMIT, PAGE_READWRITE, PAGE_NOACCESS, 5)) return 0;
    }
    if (!rejected_protection(ordinary + PAGE_BYTES, PAGE_EXECUTE_READ, ERROR_NOT_SUPPORTED, 6) ||
        !query(ordinary + PAGE_BYTES, (ULONG_PTR)ordinary, MEM_COMMIT, PAGE_READWRITE, PAGE_NOACCESS, 6)) return 0;
    if (!VirtualProtect((void *)(ordinary + PAGE_BYTES), PAGE_BYTES, PAGE_READONLY, &old)) return api_fail(7);
    ++ordinary_protects;
    if (!require(old == PAGE_READWRITE, 7) ||
        !query(ordinary + PAGE_BYTES, (ULONG_PTR)ordinary, MEM_COMMIT, PAGE_READONLY, PAGE_NOACCESS, 7) ||
        !expect_fault(ordinary + PAGE_BYTES, 1, ST_ACCESS, 8) || !sentinels(9)) return 0;
    if (!VirtualProtect((void *)(ordinary + PAGE_BYTES), PAGE_BYTES, PAGE_READWRITE, &old)) return api_fail(10);
    ++ordinary_protects;
    if (!require(old == PAGE_READONLY, 10)) return 0;
    if (!VirtualProtect((void *)(ordinary + PAGE_BYTES), PAGE_BYTES, PAGE_READWRITE | PAGE_GUARD, &old)) return api_fail(11);
    ++ordinary_protects;
    if (!require(old == PAGE_READWRITE, 11) ||
        !query(ordinary + PAGE_BYTES, (ULONG_PTR)ordinary, MEM_COMMIT, PAGE_READWRITE | PAGE_GUARD, PAGE_NOACCESS, 11) ||
        !expect_fault(ordinary + PAGE_BYTES, 0, ST_GUARD, 12)) return 0;
    /* The helper retried the exact instruction. A second ordinary access must
     * succeed without another guard exception; the helper is disarmed here. */
    if (!require(ordinary[PAGE_BYTES] == pattern(0, 1), 13) ||
        !query(ordinary + PAGE_BYTES, (ULONG_PTR)ordinary, MEM_COMMIT, PAGE_READWRITE, PAGE_NOACCESS, 13) ||
        !sentinels(13)) return 0;
    if (!VirtualFree((void *)(ordinary + PAGE_BYTES), PAGE_BYTES, MEM_DECOMMIT)) return api_fail(14);
    ++ordinary_decommits;
    if (!query(ordinary + PAGE_BYTES, (ULONG_PTR)ordinary, MEM_RESERVE, 0, PAGE_NOACCESS, 14) ||
        !expect_fault(ordinary + PAGE_BYTES, 0, ST_ACCESS, 15) || !sentinels(15)) return 0;
    if (VirtualAlloc((void *)(ordinary + PAGE_BYTES), PAGE_BYTES, MEM_COMMIT, PAGE_READWRITE) != ordinary + PAGE_BYTES)
        return api_fail(16);
    ++ordinary_commits;
    if (!zeros(ordinary + PAGE_BYTES, PAGE_BYTES, 17)) return 0;
    ordinary[PAGE_BYTES] = 0xa7;
    if (!require(ordinary[PAGE_BYTES] == 0xa7, 17) || !sentinels(17) ||
        !query(ordinary + PAGE_BYTES, (ULONG_PTR)ordinary, MEM_COMMIT, PAGE_READWRITE, PAGE_NOACCESS, 17)) return 0;
    return 1;
}

static int dynamic_checks(void)
{
    dynamic = VirtualAlloc(NULL, PAGE_BYTES, MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!dynamic) return api_fail(21);
    ++dynamic_reserves;
    first_dynamic_base = (ULONG_PTR)dynamic;
    if (!require(!(first_dynamic_base & 65535u), 21) ||
        !query(dynamic, first_dynamic_base, MEM_RESERVE, 0, PAGE_EXECUTE_READ, 21)) return 0;
    if (VirtualAlloc((void *)dynamic, PAGE_BYTES, MEM_COMMIT, PAGE_READWRITE) != dynamic) return api_fail(22);
    ++dynamic_commits;
    if (!query(dynamic, first_dynamic_base, MEM_COMMIT, PAGE_READWRITE, PAGE_EXECUTE_READ, 22) ||
        !zeros(dynamic, PAGE_BYTES, 22)) return 0;
    if (!rejected_protection(dynamic, PAGE_EXECUTE_READWRITE, ERROR_INVALID_PARAMETER, 23) ||
        !rejected_protection(dynamic, PAGE_READWRITE | PAGE_GUARD, ERROR_INVALID_PARAMETER, 23) ||
        !query(dynamic, first_dynamic_base, MEM_COMMIT, PAGE_READWRITE, PAGE_EXECUTE_READ, 23)) return 0;
    if (!publish_call(first_code, 42, 1, 24)) return 0;
    if (!protect_dynamic(PAGE_READWRITE, PAGE_EXECUTE_READ, 25) ||
        !publish_call(second_code, 84, 2, 26)) return 0;
    if (!VirtualFree((void *)dynamic, PAGE_BYTES, MEM_DECOMMIT)) return api_fail(27);
    ++dynamic_decommits;
    if (!query(dynamic, first_dynamic_base, MEM_RESERVE, 0, PAGE_EXECUTE_READ, 27)) return 0;
    if (VirtualAlloc((void *)dynamic, PAGE_BYTES, MEM_COMMIT, PAGE_READWRITE) != dynamic) return api_fail(28);
    ++dynamic_commits;
    if (!query(dynamic, first_dynamic_base, MEM_COMMIT, PAGE_READWRITE, PAGE_EXECUTE_READ, 28) ||
        !zeros(dynamic, PAGE_BYTES, 28)) return 0;
    dynamic[0] = 0x93;
    if (!VirtualFree((void *)dynamic, 0, MEM_RELEASE)) return api_fail(29);
    dynamic = NULL;
    ++dynamic_releases;
    if (!query((void *)first_dynamic_base, 0, MEM_FREE, PAGE_NOACCESS, 0, 29)) return 0;
    dynamic = VirtualAlloc(NULL, PAGE_BYTES, MEM_RESERVE, PAGE_EXECUTE_READ);
    if (!dynamic) return api_fail(30);
    ++dynamic_reserves;
    if (!require((ULONG_PTR)dynamic == first_dynamic_base, 30)) return 0;
    ++reuse_checks;
    if (VirtualAlloc((void *)dynamic, PAGE_BYTES, MEM_COMMIT, PAGE_READWRITE) != dynamic) return api_fail(31);
    ++dynamic_commits;
    if (!query(dynamic, first_dynamic_base, MEM_COMMIT, PAGE_READWRITE, PAGE_EXECUTE_READ, 31) ||
        !zeros(dynamic, PAGE_BYTES, 31)) return 0;
    return 1;
}

int pear_memory_checks(void)
{
    SYSTEM_INFO info;
    int valid;
    GetSystemInfo(&info);
    valid = require(info.dwPageSize == PAGE_BYTES && info.dwAllocationGranularity == 65536, 40);
    if (valid) valid = ordinary_checks();
    if (valid) valid = dynamic_checks();
    if (dynamic)
    {
        if (!VirtualFree((void *)dynamic, 0, MEM_RELEASE)) { api_fail(41); valid = 0; }
        else { dynamic = NULL; ++dynamic_releases; }
    }
    if (ordinary)
    {
        if (!VirtualFree((void *)ordinary, 0, MEM_RELEASE)) { api_fail(42); valid = 0; }
        else { ordinary = NULL; ++ordinary_releases; }
    }
    {
        const char *const names[] = {"error_step", "error_code", "queries", "sentinel_checks", "zero_bytes",
            "access_faults", "guard_faults", "ordinary_commits", "ordinary_protects", "ordinary_decommits", "ordinary_releases",
            "dynamic_reserves", "dynamic_commits", "dynamic_protects", "dynamic_decommits", "dynamic_releases",
            "flushes", "code_calls", "first_value", "second_value", "reuse_checks", "negative_controls"};
        const uint64_t values[] = {error_step, error_code, queries, sentinel_checks, zero_bytes,
            access_faults, guard_faults, ordinary_commits, ordinary_protects, ordinary_decommits, ordinary_releases,
            dynamic_reserves, dynamic_commits, dynamic_protects, dynamic_decommits, dynamic_releases,
            flushes, code_calls, first_value, second_value, reuse_checks, negatives};
        if (!pear_emit("pear_memory_result", names, values, 22)) return ERROR_WRITE_FAULT;
    }
    return valid && !error_step ? 0 : (int)(error_code ? error_code : ERROR_INVALID_DATA);
}
