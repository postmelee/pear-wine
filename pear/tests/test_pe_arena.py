# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the actual native PE parser and finite admission logic under UBSan.

These checks never initialize MAP_JIT, publish executable memory or run Wine.
They use independently encoded original PE fixtures and the pinned Wine build
headers when available. Missing prepared headers are an explicit test skip.
"""
from pathlib import Path
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from pear.tests.source_inputs import ROOT, materialize, configured_headers, historical_arena


def candidate_file(relative, *, cookie_guard=True):
    if cookie_guard:
        return materialize(relative)
    return historical_arena(Path(relative).name)


def fixture():
    """Four 4 KiB pages, one DIR64 relocation, and 512-byte file alignment."""
    data = bytearray(0x800)
    struct.pack_into('<H', data, 0, 0x5A4D)
    struct.pack_into('<I', data, 60, 0x80)
    struct.pack_into('<IHHIIIHH', data, 0x80, 0x4550, 0xAA64, 3, 0, 0, 0, 240, 0x2022)
    optional = 0x98
    struct.pack_into('<H', data, optional, 0x20B)
    struct.pack_into('<I', data, optional + 16, 0x1000)
    struct.pack_into('<Q', data, optional + 24, 0x180000000)
    struct.pack_into('<II', data, optional + 32, 0x1000, 0x200)
    struct.pack_into('<II', data, optional + 56, 0x4000, 0x200)
    struct.pack_into('<H', data, optional + 70, 0x40)
    struct.pack_into('<I', data, optional + 108, 16)
    struct.pack_into('<II', data, optional + 112 + 5 * 8, 0x3000, 12)
    for index, (name, protection) in enumerate(((b'.text', 0x60000020),
                                               (b'.data', 0xC0000040),
                                               (b'.reloc', 0x42000040))):
        offset = optional + 240 + index * 40
        struct.pack_into('<8sIIIIIIHHI', data, offset, name, 0x200,
                         (index + 1) * 0x1000, 0x200, (index + 1) * 0x200,
                         0, 0, 0, 0, protection)
    struct.pack_into('<Q', data, 0x400, 0x180001234)
    struct.pack_into('<IIHH', data, 0x600, 0x2000, 12, 0xA000, 0)
    return data


BASE = 0x180000000
CONFIG_RVA = 0x2080
CONFIG_FILE = 0x480
COOKIE_OFFSET = 88


def cookie_fixture(length=96, directory_size=96, destination=BASE + 0x2040):
    data = fixture()
    struct.pack_into('<II', data, 0x98 + 112 + 10 * 8, CONFIG_RVA, directory_size)
    struct.pack_into('<I', data, CONFIG_FILE, length)
    struct.pack_into('<Q', data, CONFIG_FILE + COOKIE_OFFSET, destination)
    struct.pack_into('<Q', data, 0x440, 0x00002b992ddfa232)
    # Relocate the actual load-config pointer, not an unrelated test value.
    struct.pack_into('<H', data, 0x608, 0xA0D8)
    return data


HARNESS = r'''
#include <fcntl.h>
#include "pear_pe_arena.c"
unsigned char __wine_dbg_get_channel_flags(struct __wine_debug_channel *channel) { return 0; }
const char *__wine_dbg_strdup(const char *text) { return text; }
int __wine_dbg_output(const char *text) { return 0; }
int __wine_dbg_header(enum __wine_debug_class cls, struct __wine_debug_channel *channel, const char *function) { return 0; }
static int admission(struct pear_pe_plan *plan)
{
    struct pear_pe_slot *first, *next;
    void *base, *again;
    SIZE_T capacity;
    ULONGLONG generation;
    if (posix_memalign((void **)&arena.interior, PEAR_ARENA_ALIGNMENT, 2 * PEAR_ARENA_ALIGNMENT)) return 1;
    arena.mapping = arena.interior;
    arena.owner_pid = getpid();
    arena.classes = calloc(PAGES, 1);
    arena.protection = calloc(PAGES, 1);
    arena.vprot = calloc(PAGES, 1);
    if (!arena.classes || !arena.protection || !arena.vprot) return 2;
    if (pear_pe_slot_reserve(plan, 0, 0, &first, &base, &capacity)) return 3;
    if (capacity != 65536 || (ULONG_PTR)base % 65536 || first->generation != 1) return 4;
    generation = first->generation;
    first->state = SLOT_RETIRED;
    for (SIZE_T i = 0; i < plan->page_count; ++i)
        if (plan->pages[i] & PAGE_USED) arena.classes[i] = plan->pages[i] & PV_EXEC ? CODE : ORDINARY;
    if (pear_pe_slot_reserve(plan, 0, 0, &next, &again, &capacity)) return 5;
    if (first != next || base != again || next->generation != 2 || arena.count != 1) return 6;
    if (pear_pe_slot_protect(first, generation, base, PAGE, PV_READ | PV_COMMITTED) != STATUS_INVALID_PAGE_PROTECTION) return 7;
    first->state = SLOT_RETIRED;
    /* Different compatible ordinary permissions may share this backing. */
    plan->pages[2] = PAGE_USED | PV_READ;
    if (pear_pe_slot_reserve(plan, 0, 0, &next, &again, &capacity) || first != next || next->generation != 3) return 8;
    first->state = SLOT_RETIRED;
    /* Previously ordinary page 2 must never be reclassified as code. */
    plan->pages[2] = PAGE_USED | PV_READ | PV_EXEC;
    arena.used = PEAR_ARENA_INTERIOR_BYTES;
    if (pear_pe_slot_reserve(plan, 0, 0, &next, &again, &capacity) != STATUS_NO_MEMORY || arena.count != 1) return 9;
    if (pear_pe_slot_reserve(plan, 0, 0, &next, &again, &capacity) != STATUS_NO_MEMORY || arena.count != 1) return 10;
    plan->pages[2] = PAGE_USED | PV_READ;
    if (pear_pe_slot_reserve(plan, 0, (ULONG_PTR)base - 1, &next, &again, &capacity) != STATUS_NO_MEMORY) return 11;
    first->generation = ~(ULONGLONG)0;
    if (pear_pe_slot_reserve(plan, 0, 0, &next, &again, &capacity) != STATUS_NO_MEMORY) return 12;
    free(arena.mapping); free(arena.classes); free(arena.protection); free(arena.vprot);
    return 0;
}
int main(int argc, char **argv)
{
    struct pear_pe_plan *plan = NULL;
    struct pear_pe_image image;
    int fd = open(argv[1], O_RDONLY);
    NTSTATUS status = fd < 0 ? STATUS_OBJECT_NAME_NOT_FOUND : pear_pe_plan_read(fd, &plan, &image);
    if (fd >= 0) close(fd);
    printf("%08x", (unsigned)status);
    if (!status)
    {
        printf(" %llu %llu %llu", (unsigned long long)plan->size,
               (unsigned long long)plan->relocation_count, (unsigned long long)plan->original_base);
        if (argc > 2 && !strcmp(argv[2], "admission")) printf(" %d", admission(plan));
        else if (argc > 2)
        {
            ULONGLONG target = strtoull(argv[2], NULL, 10), value = 0;
            NTSTATUS moved = relocate_staging(plan, target);
            if (plan->relocation_count) memcpy(&value, plan->staging + plan->relocations[0], sizeof(value));
            printf(" %08x %llu %llu %08x", (unsigned)moved, (unsigned long long)value,
                (unsigned long long)((IMAGE_NT_HEADERS64 *)(plan->staging + plan->nt_offset))->OptionalHeader.ImageBase,
                (unsigned)relocate_staging(plan, target));
        }
    }
    puts("");
    pear_pe_plan_free(plan);
    return 0;
}
'''


class NativePEParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        objects, source_headers = configured_headers()
        if not shutil.which('clang'):
            raise unittest.SkipTest('native clang unavailable')
        cls.temporary = tempfile.TemporaryDirectory(prefix='pear-pe-parser-')
        cls.folder = Path(cls.temporary.name)
        cls.addClassCleanup(cls.temporary.cleanup)
        for name in ('pear_pe_arena.c', 'pear_pe_arena.h'):
            (cls.folder / name).write_text(candidate_file('dlls/ntdll/unix/' + name))
        (cls.folder / 'pear_fex_memory_private.h').write_text(materialize('dlls/ntdll/unix/pear_fex_memory_private.h'))
        (cls.folder / 'main.c').write_text(HARNESS)
        command = [shutil.which('clang'), '-std=gnu23', '-fsanitize=undefined',
                   '-fno-sanitize-recover=all', '-D__WINESRC__', '-DWINE_UNIX_LIB',
                   '-I' + str(objects), '-I' + str(source_headers),
                   str(cls.folder / 'main.c'), '-o', str(cls.folder / 'parser')]
        result = subprocess.run(command, text=True, capture_output=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stderr)

        # Compile the exact prior owner only for observable regression controls.
        folder = cls.folder / 'before'
        folder.mkdir()
        for name in ('pear_pe_arena.c', 'pear_pe_arena.h'):
            (folder / name).write_text(candidate_file('dlls/ntdll/unix/' + name, cookie_guard=False))
        (folder / 'main.c').write_text(HARNESS)
        command = [shutil.which('clang'), '-std=gnu23', '-fsanitize=undefined',
                   '-fno-sanitize-recover=all', '-D__WINESRC__', '-DWINE_UNIX_LIB',
                   '-I' + str(objects), '-I' + str(source_headers),
                   str(folder / 'main.c'), '-o', str(folder / 'parser')]
        compiled = subprocess.run(command, text=True, capture_output=True, timeout=60)
        if compiled.returncode:
            raise AssertionError(compiled.stderr)
        cls.before_folder = folder


    def parse(self, data, admission=False, target=None):
        path = self.folder / 'input.pe'
        path.write_bytes(data)
        command = [str(self.folder / 'parser'), str(path)] + (['admission'] if admission else [])
        if target is not None:
            command.append(str(target))
        result = subprocess.run(command, text=True, capture_output=True, timeout=15,
                                env={k: v for k, v in os.environ.items() if not k.startswith('PEAR_')})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        return result.stdout.strip().split()

    def test_original_fixture_and_relocation(self):
        self.assertEqual(self.parse(fixture()), ['00000000', '16384', '1', str(0x180000000)])

    def test_compatible_reuse_stale_generation_and_bounded_exhaustion(self):
        self.assertEqual(self.parse(fixture(), True)[-1], '0')

    def test_native_relocation_updates_code_and_data_at_two_bases(self):
        for destination in (0x190000000, 0x170000000):
            for code in (False, True):
                data = fixture()
                if code:
                    struct.pack_into('<I', data, 0x600, 0x1000)
                    struct.pack_into('<H', data, 0x608, 0xA008)
                    struct.pack_into('<Q', data, 0x208, 0x180001234)
                with self.subTest(destination=destination, code=code):
                    self.assertEqual(self.parse(data, target=destination)[4:],
                                     ['00000000', str(destination + 0x1234), str(destination), 'c000000d'])

    def test_truncated_file_extents(self):
        source = fixture()
        for length in (0, 63, 0x80, 0x180, 0x1ff, 0x600, 0x7ff):
            with self.subTest(length=length):
                self.assertNotEqual(self.parse(source[:length])[0], '00000000')

    def test_misaligned_negative_and_outside_nt_header(self):
        for offset in (0x81, 0xffffffff, 0x7fffffff, 0x10):
            data = fixture(); struct.pack_into('<I', data, 60, offset)
            with self.subTest(offset=offset):
                self.assertNotEqual(self.parse(data)[0], '00000000')

    def test_wrong_machine_optional_header_and_image_bound(self):
        for offset, fmt, value in ((0x84, 'H', 0x8664), (0x98, 'H', 0x10b),
                                   (0x94, 'H', 0xffff), (0xd0, 'I', 0xffffffff),
                                   (0xba, 'H', 3), (0xb0, 'Q', 0x180000001)):
            data = fixture(); struct.pack_into('<' + fmt, data, offset, value)
            with self.subTest(offset=offset):
                self.assertNotEqual(self.parse(data)[0], '00000000')

    def test_section_and_raw_overlap_and_declared_extent(self):
        section = 0x98 + 240
        for offset, value in ((section + 40 + 12, 0x1000), (section + 40 + 20, 0x200),
                               (section + 20, 0), (section + 16, 0x1000),
                               (section + 12, 0xfffff000), (section + 36, 0xE0000020),
                               (section + 36, 0x70000020)):
            data = fixture(); struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset, value=value):
                self.assertNotEqual(self.parse(data)[0], '00000000')

    def test_unsupported_and_overlapping_relocations(self):
        for first, second in ((0x3000, 0), (0xA000, 0xA000), (0xA000, 0xA004),
                              (0xAfff, 0), (0xA000, 0xAfff)):
            data = fixture(); struct.pack_into('<HH', data, 0x608, first, second)
            with self.subTest(first=first, second=second):
                # Crossing from .data into .reloc is valid unless the target
                # overlaps relocation bytes; use last-image page for overflow.
                if first == 0xAfff or second == 0xAfff:
                    struct.pack_into('<I', data, 0x600, 0x3000)
                self.assertNotEqual(self.parse(data)[0], '00000000')

    def test_invalid_relocation_blocks_cannot_loop_or_escape(self):
        for size in (0, 2, 6, 9, 14, 0xfffffffc):
            data = fixture(); struct.pack_into('<I', data, 0x604, size)
            with self.subTest(size=size):
                self.assertNotEqual(self.parse(data)[0], '00000000')

    def test_zero_fill_and_absolute_padding_are_allowed(self):
        data = fixture(); struct.pack_into('<HH', data, 0x608, 0, 0)
        self.assertEqual(self.parse(data)[0:3], ['00000000', '16384', '0'])

    def test_iat_cannot_alias_executable_page(self):
        data = fixture(); struct.pack_into('<II', data, 0x98 + 112 + 12 * 8, 0x1000, 8)
        self.assertEqual(self.parse(data)[0], 'c000007b')

    def test_security_directory_is_checked_as_file_extent(self):
        data = fixture(); struct.pack_into('<II', data, 0x98 + 112 + 4 * 8, 0x7f0, 64)
        self.assertEqual(self.parse(data)[0], 'c000007b')

    def test_unsafe_fixed_base_and_dynamic_hybrid_are_rejected(self):
        data = fixture(); struct.pack_into('<H', data, 0x98 + 70, 0)
        self.assertEqual(self.parse(data)[0], 'c00000bb')
        data = fixture(); struct.pack_into('<H', data, 0x96, 0x2023)
        self.assertEqual(self.parse(data)[0], 'c00000bb')


    def parse_before(self, data):
        target = self.before_folder / 'input.pe'
        target.write_bytes(data)
        result = subprocess.run([str(self.before_folder / 'parser'), str(target)],
                                capture_output=True, text=True, timeout=15,
                                env={k: v for k, v in os.environ.items() if not k.startswith('PEAR_')})
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        return result.stdout.strip().split()

    def test_partial_pointer_reproduces_before_and_rejects_after(self):
        for length in range(89, 96):
            for directory_size in (length, 96):
                data = cookie_fixture(length, directory_size, BASE + 0x1000)
                with self.subTest(length=length, directory_size=directory_size):
                    self.assertEqual(self.parse_before(data)[0], '00000000')
                    self.assertEqual(self.parse(data)[0], 'c000007b')

    def test_absent_field_boundary_preserves_upstream_consumption(self):
        # Size==offsetof means Wine never consumes the pointer, even if the
        # larger directory contains bytes that would be an invalid destination.
        for length, directory_size in ((4, 4), (4, 96), (88, 88), (88, 89), (88, 95), (88, 96)):
            data = cookie_fixture(length, directory_size, BASE + 0x1000)
            with self.subTest(length=length, directory_size=directory_size):
                self.assertEqual(self.parse_before(data)[0], '00000000')
                self.assertEqual(self.parse(data)[0], '00000000')

    def test_complete_field_boundary_and_larger_directory_allow_valid_cookie(self):
        for length, directory_size in ((96, 96), (96, 104), (104, 104)):
            data = cookie_fixture(length, directory_size)
            with self.subTest(length=length, directory_size=directory_size):
                self.assertEqual(self.parse_before(data)[0], '00000000')
                self.assertEqual(self.parse(data)[0], '00000000')

    def test_internal_size_cannot_exceed_directory_or_omit_size_word(self):
        for length, directory_size in ((96, 95), (96, 88), (97, 96), (89, 88), (0, 96), (3, 96), (88, 3)):
            data = cookie_fixture(length, directory_size)
            with self.subTest(length=length, directory_size=directory_size):
                self.assertEqual(self.parse_before(data)[0], 'c000007b')
                self.assertEqual(self.parse(data)[0], 'c000007b')

    def test_complete_pointer_must_fit_used_ordinary_image_storage(self):
        for destination in (BASE - 1, BASE + 0x4000, BASE + 0x3ff9, 2**64 - 1,
                            BASE + 0x1000, BASE + 0x1008, BASE + 0xffc):
            data = cookie_fixture(destination=destination)
            with self.subTest(destination=destination):
                self.assertEqual(self.parse_before(data)[0], 'c000007b')
                self.assertEqual(self.parse(data)[0], 'c000007b')

    def test_full_pointer_to_unused_image_hole_is_rejected(self):
        data = cookie_fixture(destination=BASE + 0x4000)
        struct.pack_into('<I', data, 0x98 + 56, 0x5000)
        self.assertEqual(self.parse_before(data)[0], 'c000007b')
        self.assertEqual(self.parse(data)[0], 'c000007b')

    def test_zero_and_complete_last_eight_bytes_and_readonly_data_stay_valid(self):
        for destination in (0, BASE + 0x3ff8, BASE + 0x2ffc):
            data = cookie_fixture(destination=destination)
            with self.subTest(destination=destination):
                self.assertEqual(self.parse_before(data)[0], '00000000')
                self.assertEqual(self.parse(data)[0], '00000000')
        data = cookie_fixture()
        # Wine temporarily protects ordinary read-only cookie storage RW and
        # restores it. The publisher's destination guard must not require W.
        struct.pack_into('<I', data, 0x98 + 240 + 40 + 36, 0x40000040)
        self.assertEqual(self.parse(data)[0], '00000000')

    def test_valid_pointer_itself_relocates_to_the_owned_target(self):
        for target in (0x190000000, 0x170000000):
            with self.subTest(target=target):
                self.assertEqual(self.parse(cookie_fixture(), target=target)[4:],
                    ['00000000', str(target + 0x2040), str(target), 'c000000d'])


if __name__ == '__main__':
    unittest.main()
