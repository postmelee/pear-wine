# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise candidate owner C under UBSan with explicit simulated OS permissions.
No MAP_JIT initialization, Wine, signing or generated-code execution occurs.
Only mprotect and Mach protection observation are replaced by finite test shims.
The complete production owner handles ranges, generations, rollback and zeroing.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

from pear.tests.source_inputs import materialize, configured_headers

PRELUDE = r'''
#include <sys/mman.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
static unsigned char *test_base, *test_permissions;
static size_t test_bytes;
static unsigned calls, failure_call;
static int test_mprotect(void *pointer, size_t bytes, int protection)
{
    uintptr_t off = (uintptr_t)pointer - (uintptr_t)test_base;
    ++calls;
    if (failure_call == calls) { errno = EACCES; return -1; }
    if ((off | bytes) & 4095 || off > test_bytes || bytes > test_bytes - off) abort();
    if ((protection & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) abort();
    memset(test_permissions + off / 4096, protection, bytes / 4096);
    return 0;
}
static int test_actual_protection(const void *pointer, size_t bytes, int protection)
{
    uintptr_t off = (uintptr_t)pointer - (uintptr_t)test_base;
    if ((off | bytes) & 4095 || off > test_bytes || bytes > test_bytes - off) return 0;
    for (size_t i = 0; i < bytes / 4096; ++i)
        if (test_permissions[off / 4096 + i] != protection) return 0;
    return 1;
}
#define mprotect test_mprotect
'''
TAIL = r'''
unsigned char __wine_dbg_get_channel_flags(struct __wine_debug_channel *channel) { return 0; }
const char *__wine_dbg_strdup(const char *text) { return text; }
int __wine_dbg_output(const char *text) { return 0; }
int __wine_dbg_header(enum __wine_debug_class cls, struct __wine_debug_channel *channel, const char *function) { return 0; }
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "check line %d failed\n", __LINE__); return 1; } } while (0)
static int setup(void)
{
    test_bytes = PEAR_ARENA_TOTAL_BYTES;
    test_base = mmap(NULL, test_bytes + 65536, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    CHECK(test_base != MAP_FAILED);
    test_base = (void *)(((uintptr_t)test_base + 65535) & ~(uintptr_t)65535);
    arena.mapping = arena.interior = test_base;
    arena.owner_pid = getpid();
    arena.classes = calloc(PAGES, 1);
    arena.protection = calloc(PAGES, 1);
    arena.vprot = calloc(PAGES, 1);
    test_permissions = calloc(PAGES, 1);
    CHECK(arena.classes && arena.protection && arena.vprot && test_permissions);
    return 0;
}
int main(int argc, char **argv)
{
    struct pear_dynamic_slot *slot, *again, *all[PEAR_ARENA_DYNAMIC_SLOTS];
    void *base, *next, *start, *end;
    SIZE_T first, index;
    ULONGLONG generation;
    unsigned scenario = argc > 1 ? atoi(argv[1]) : 0;
    CHECK(!setup());
    if (scenario == 1)
    {
        CHECK(pear_dynamic_reserve(0, &slot, &base) == STATUS_INVALID_PARAMETER);
        CHECK(pear_dynamic_reserve(4095, &slot, &base) == STATUS_INVALID_PARAMETER);
        CHECK(pear_dynamic_reserve(65537, &slot, &base) == STATUS_INVALID_PARAMETER);
        for (unsigned i = 0; i < PEAR_ARENA_DYNAMIC_SLOTS; ++i)
            CHECK(!pear_dynamic_reserve(PAGE, &all[i], &base) && all[i]->generation == 1);
        CHECK(pear_dynamic_reserve(PAGE, &slot, &base) == STATUS_NO_MEMORY);
        for (unsigned i = 0; i < PEAR_ARENA_DYNAMIC_SLOTS; ++i) CHECK(!pear_dynamic_release(all[i], 1));
        CHECK(!pear_dynamic_reserve(PAGE, &slot, &base) && slot == all[0] && slot->generation == 2);
        CHECK(!arena.count && !arena.used);
        return 0;
    }
    CHECK(!pear_dynamic_reserve(3 * PAGE, &slot, &base));
    generation = slot->generation;
    first = ((uintptr_t)base - (uintptr_t)arena.interior) / PAGE;
    if (scenario == 2)
    {
        CHECK(pear_dynamic_protect(slot, generation, base, PAGE, PV_READ | PV_COMMITTED, FALSE) == STATUS_NOT_COMMITTED);
        CHECK(pear_dynamic_protect(slot, generation + 1, base, PAGE, PV_READ | PV_COMMITTED, TRUE) == STATUS_INVALID_PARAMETER);
        CHECK(pear_dynamic_protect(slot, generation, (char *)base + 1, PAGE, PV_READ | PV_COMMITTED, TRUE) == STATUS_INVALID_PARAMETER);
        CHECK(pear_dynamic_protect(slot, generation, (char *)base + 3 * PAGE, PAGE, PV_READ | PV_COMMITTED, TRUE) == STATUS_INVALID_PARAMETER);
        CHECK(pear_dynamic_protect((void *)((char *)slot + 1), generation, base, PAGE, PV_READ | PV_COMMITTED, TRUE) == STATUS_INVALID_PARAMETER);
        CHECK(pear_dynamic_protect(slot, generation, base, PAGE, PV_READ | PV_COMMITTED | PV_EXEC | PV_WRITE, TRUE) == STATUS_INVALID_PAGE_PROTECTION);
        CHECK(pear_dynamic_protect(slot, generation, base, PAGE, PV_READ | PV_COMMITTED | PV_COPY, TRUE) == STATUS_INVALID_PAGE_PROTECTION);
        CHECK(pear_dynamic_protect(slot, generation, base, PAGE, PV_READ | PV_COMMITTED | 0x10, TRUE) == STATUS_INVALID_PAGE_PROTECTION);
        CHECK(!calls && !arena.vprot[first] && !arena.protection[first]);
        return 0;
    }
    CHECK(!pear_dynamic_protect(slot, generation, base, 3 * PAGE, PV_READ | PV_WRITE | PV_COMMITTED, TRUE));
    memset(base, 0x5a, 3 * PAGE);
    if (scenario == 3)
    {
        CHECK(!pear_dynamic_protect(slot, generation, base, 3 * PAGE, PV_READ | PV_WRITE | PV_COMMITTED, TRUE));
        for (unsigned i = 0; i < 3 * PAGE; ++i) CHECK(((unsigned char *)base)[i] == 0x5a);
        CHECK(!pear_dynamic_protect(slot, generation, (char *)base + PAGE, PAGE, PV_READ | PV_EXEC | PV_COMMITTED, FALSE));
        CHECK(arena.protection[first] == (PROT_READ | PROT_WRITE));
        CHECK(arena.protection[first + 1] == (PROT_READ | PROT_EXEC));
        CHECK(arena.protection[first + 2] == (PROT_READ | PROT_WRITE));
        CHECK(!pear_dynamic_protect(slot, generation, (char *)base + PAGE, PAGE, PV_READ | PV_WRITE | PV_COMMITTED, FALSE));
        CHECK(!pear_dynamic_decommit(slot, generation, (char *)base + PAGE, PAGE));
        CHECK(!arena.vprot[first + 1] && !arena.protection[first + 1]);
        CHECK(!pear_dynamic_protect(slot, generation, (char *)base + PAGE, PAGE, PV_READ | PV_WRITE | PV_COMMITTED, TRUE));
        for (unsigned i = 0; i < 3 * PAGE; ++i) CHECK(((unsigned char *)base)[i] == (i >= PAGE && i < 2 * PAGE ? 0 : 0x5a));
        return 0;
    }
    if (scenario == 4)
    {
        CHECK(!pear_dynamic_release(slot, generation));
        CHECK(!slot->active && !arena.vprot[first]);
        CHECK(pear_dynamic_free_range(base, &start, &end) && start == base && (char *)end - (char *)start == 65536);
        CHECK(!pear_dynamic_reserve(PAGE, &again, &next) && next == base && again == slot && again->generation == generation + 1);
        CHECK(pear_dynamic_protect(slot, generation, base, PAGE, PV_READ | PV_COMMITTED, TRUE) == STATUS_INVALID_PARAMETER);
        CHECK(!pear_dynamic_protect(again, again->generation, base, PAGE, PV_READ | PV_WRITE | PV_COMMITTED, TRUE));
        for (unsigned i = 0; i < PAGE; ++i) CHECK(!((unsigned char *)base)[i]);
        CHECK(!pear_dynamic_free_range(base, &start, &end));
        CHECK(pear_dynamic_free_range((char *)base + PAGE, &start, &end) && start == (char *)base + PAGE);
        return 0;
    }
    if (scenario >= 10 && scenario <= 12)
    {
        calls = 0; failure_call = scenario - 9;
        CHECK(pear_dynamic_protect(slot, generation, base, 3 * PAGE, PV_READ | PV_EXEC | PV_COMMITTED, FALSE) == STATUS_ACCESS_DENIED);
        CHECK(errno == EACCES);
        for (unsigned i = 0; i < 3; ++i)
            CHECK(arena.vprot[first + i] == (PV_READ | PV_WRITE | PV_COMMITTED) &&
                  arena.protection[first + i] == (PROT_READ | PROT_WRITE) &&
                  test_permissions[first + i] == (PROT_READ | PROT_WRITE));
        for (unsigned i = 0; i < 3 * PAGE; ++i) CHECK(((unsigned char *)base)[i] == 0x5a);
        return 0;
    }
    if (scenario >= 20 && scenario <= 22)
    {
        calls = 0; failure_call = scenario - 19;
        CHECK(pear_dynamic_decommit(slot, generation, base, 3 * PAGE) == STATUS_ACCESS_DENIED);
        CHECK(errno == EACCES);
        for (unsigned i = 0; i < 3; ++i)
            CHECK(arena.vprot[first + i] == (PV_READ | PV_WRITE | PV_COMMITTED) &&
                  test_permissions[first + i] == (PROT_READ | PROT_WRITE));
        for (unsigned i = 0; i < 3 * PAGE; ++i) CHECK(((unsigned char *)base)[i] == 0x5a);
        return 0;
    }
    if (scenario == 30)
    {
        calls = 0; failure_call = 4;
        pear_dynamic_decommit(slot, generation, base, 3 * PAGE);
        return 9; /* First irreversible revoke failure must terminate 127. */
    }
    if (scenario == 31)
    {
        arena.owner_pid = getpid() + 1;
        pear_dynamic_protect(slot, generation, base, PAGE, PV_READ | PV_COMMITTED, FALSE);
        return 9;
    }
    if (scenario == 32)
    {
        arena.classes[first] = CODE;
        CHECK(pear_dynamic_protect(slot, generation, base, PAGE, PV_READ | PV_COMMITTED, FALSE) == STATUS_INVALID_PAGE_PROTECTION);
        CHECK(pear_dynamic_decommit(slot, generation, base, PAGE) == STATUS_INVALID_PAGE_PROTECTION);
        return 0;
    }
    if (scenario >= 40 && scenario <= 45)
    {
        CHECK(!pear_dynamic_decommit(slot, generation, base, 3 * PAGE));
        calls = 0; failure_call = scenario - 39;
        CHECK(pear_dynamic_protect(slot, generation, base, 3 * PAGE, PV_READ | PV_COMMITTED, TRUE) == STATUS_ACCESS_DENIED);
        CHECK(errno == EACCES);
        for (unsigned i = 0; i < 3; ++i) CHECK(!arena.vprot[first + i] && !arena.protection[first + i] && !test_permissions[first + i]);
        return 0;
    }
    return 8;
}
'''

class DynamicOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='pear-dynamic-owner-')
        cls.addClassCleanup(cls.tmp.cleanup)
        folder = Path(cls.tmp.name)
        objects, source_headers = configured_headers()
        source = materialize('dlls/ntdll/unix/pear_pe_arena.c')
        begin = source.index('static BOOL actual_protection(')
        end = source.index('\nstatic void require_owner', begin)
        source = source[:begin] + '''static BOOL actual_protection(const void *pointer, SIZE_T size, int prot)
{ return test_actual_protection(pointer, size, prot); }
''' + source[end:]
        (folder / 'pear_pe_arena.h').write_text(materialize('dlls/ntdll/unix/pear_pe_arena.h'))
        (folder / 'pear_fex_memory_private.h').write_text(materialize('dlls/ntdll/unix/pear_fex_memory_private.h'))
        (folder / 'main.c').write_text(PRELUDE + source + TAIL)
        cls.exe = folder / 'owner'
        result = subprocess.run(['/usr/bin/clang', '-std=gnu23', '-fsanitize=undefined',
            '-fno-sanitize-recover=all', '-D__WINESRC__', '-DWINE_UNIX_LIB',
            '-I' + str(objects), '-I' + str(source_headers),
            str(folder / 'main.c'), '-o', str(cls.exe)], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    def test_owner_cases(self):
        for number in [1,2,3,4,10,11,12,20,21,22,30,31,32,40,41,42,43,44,45]:
            with self.subTest(scenario=number):
                result = subprocess.run([str(self.exe), str(number)], text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 127 if number in (30,31) else 0, result.stdout + result.stderr)

if __name__ == '__main__':
    unittest.main()
