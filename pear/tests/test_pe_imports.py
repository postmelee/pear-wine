# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run actual patched Wine import control flow against synthetic host boundaries.

The tested function is extracted from the attributable ordered patch, not a
second implementation of the loader. Mock NT protection/export/module services
exercise success, typed failure, IAT restoration and fatal rollback handling.
This is not real Wine execution or proof of dependency-graph/lifetime cleanup;
those require the original PE DLL fixtures in the owned signed runtime.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from source_inputs import materialize


def import_function():
    source = materialize('dlls/ntdll/loader.c')
    marker = 'static NTSTATUS import_dll('
    if source.count(marker) != 1:
        raise ValueError('selected loader must have exactly one import function')
    start = source.index(marker)
    end = source.index('\n}\n', start) + 3
    return source[start:end]


PREAMBLE = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <setjmp.h>
typedef uint32_t NTSTATUS, DWORD;
typedef uintptr_t ULONG_PTR;
typedef size_t SIZE_T;
typedef wchar_t WCHAR;
typedef const WCHAR *LPCWSTR;
typedef void *HMODULE, *PVOID;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0u
#define STATUS_DLL_NOT_FOUND 0xc0000135u
#define STATUS_ENTRYPOINT_NOT_FOUND 0xc0000139u
#define STATUS_ORDINAL_NOT_FOUND 0xc0000138u
#define STATUS_ACCESS_DENIED 0xc0000022u
#define LDR_WINE_INTERNAL 0x80000000u
#define PAGE_READONLY 2u
#define PAGE_READWRITE 4u
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_SNAP_BY_ORDINAL(n) ((n) >> 63)
#define IMAGE_ORDINAL(n) ((n) & 0xffff)
#define IntToPtr(n) ((void *)(uintptr_t)(n))
#define NtCurrentProcess() ((void *)(intptr_t)-1)
typedef struct { uintptr_t OriginalFirstThunk, FirstThunk, Name; } IMAGE_IMPORT_DESCRIPTOR;
typedef struct { union { uintptr_t Ordinal, AddressOfData, Function; } u1; } IMAGE_THUNK_DATA;
typedef struct { unsigned short Hint; char Name[32]; } IMAGE_IMPORT_BY_NAME;
typedef struct { uint32_t Base; } IMAGE_EXPORT_DIRECTORY;
typedef struct { struct { HMODULE DllBase; DWORD Flags; struct { WCHAR *Buffer; } FullDllName; } ldr; int system; } WINE_MODREF;
static WINE_MODREF provider;
static IMAGE_EXPORT_DIRECTORY exports_value = {1};
static int export_present, export_table, provider_error, protection_failure;
static unsigned protection_calls, stub_calls, lookup_calls, protection_state, fatal_calls;
static NTSTATUS fatal_status;
static jmp_buf fatal_jump;
static void *get_rva(void *base, uintptr_t rva) { return (char *)base + rva; }
static const char *debugstr_w(const WCHAR *value) { (void)value; return "fixture"; }
static void quiet(const char *format, ...) { (void)format; }
#define WARN quiet
#define ERR quiet
#define TRACE_(channel) quiet
static NTSTATUS build_import_name(WINE_MODREF *wm, WCHAR *buffer, const char *name, DWORD length)
{ (void)wm; (void)buffer; (void)name; (void)length; return 0; }
static NTSTATUS load_dll(LPCWSTR path, WCHAR *name, DWORD flags, WINE_MODREF **wm, BOOL system)
{
    (void)path; (void)name; (void)flags; (void)system;
    if (provider_error) return STATUS_DLL_NOT_FOUND;
    *wm = &provider;
    return 0;
}
static NTSTATUS NtProtectVirtualMemory(void *process, PVOID *base, SIZE_T *size, DWORD protection, DWORD *old)
{
    (void)process;
    if (!base || !*base || !size || *size != sizeof(IMAGE_THUNK_DATA)) abort();
    ++protection_calls;
    if (protection_failure == (int)protection_calls) return STATUS_ACCESS_DENIED;
    *old = protection_state;
    protection_state = protection;
    return 0;
}
static void *RtlImageDirectoryEntryToData(HMODULE module, BOOL mapped, DWORD directory, DWORD *size)
{
    (void)module; (void)mapped; (void)directory;
    *size = sizeof(exports_value);
    return export_table ? &exports_value : NULL;
}
static ULONG_PTR allocate_stub(const char *dll, const char *name)
{ (void)dll; (void)name; ++stub_calls; return 0xdeadbeef; }
static void *find_ordinal_export(HMODULE module, const IMAGE_EXPORT_DIRECTORY *exports,
                                 DWORD size, int ordinal, LPCWSTR path, WINE_MODREF *wm, BOOL dynamic)
{
    (void)module; (void)exports; (void)size; (void)ordinal; (void)path; (void)wm; (void)dynamic;
    ++lookup_calls;
    return export_present ? (void *)(uintptr_t)0x445500 : NULL;
}
static void *find_named_export(HMODULE module, const IMAGE_EXPORT_DIRECTORY *exports,
                               DWORD size, const char *name, unsigned hint, LPCWSTR path,
                               WINE_MODREF *wm, BOOL dynamic)
{
    (void)module; (void)exports; (void)size; (void)name; (void)hint; (void)path; (void)wm; (void)dynamic;
    ++lookup_calls;
    return export_present ? (void *)(uintptr_t)0x445500 : NULL;
}
static NTSTATUS NtTerminateProcess(void *process, NTSTATUS status)
{
    (void)process;
    ++fatal_calls;
    fatal_status = status;
    longjmp(fatal_jump, 1);
}
'''
MAIN = r'''
int main(int argc, char **argv)
{
    union { uint64_t alignment; unsigned char bytes[512]; } memory = {0};
    IMAGE_IMPORT_DESCRIPTOR descriptor = {128, 256, 32};
    IMAGE_THUNK_DATA *imports = (void *)(memory.bytes + 128);
    IMAGE_THUNK_DATA *iat = (void *)(memory.bytes + 256);
    IMAGE_IMPORT_BY_NAME *name = (void *)(memory.bytes + 192);
    WINE_MODREF wm = {{memory.bytes, 0, {L"subject.dll"}}, 0}, *imported = NULL;
    NTSTATUS status = 0;
    if (argc != 2) return 2;
    strcpy((char *)memory.bytes + 32, "provider.dll");
    strcpy(name->Name, "Missing");
    imports[0].u1.AddressOfData = 192;
    iat[0].u1.Function = UINT64_C(0x12345678);
    export_table = 1;
    protection_state = PAGE_READONLY;
    if (strstr(argv[1], "ordinal")) imports[0].u1.Ordinal = UINT64_C(0x8000000000007fff);
    if (strstr(argv[1], "noexports")) export_table = 0;
    if (strstr(argv[1], "resolved")) export_present = 1;
    if (!strcmp(argv[1], "empty")) imports[0].u1.Ordinal = 0;
    if (!strcmp(argv[1], "provider-failure")) provider_error = 1;
    if (!strcmp(argv[1], "protect-denied")) protection_failure = 1;
    if (strstr(argv[1], "restore-denied")) protection_failure = 2;
    if (!setjmp(fatal_jump)) status = import_dll(&wm, &descriptor, NULL, &imported);
    else status = fatal_status;
    printf("%08x %u %u %u %u %u %u\n", status, protection_calls, protection_state,
           stub_calls, lookup_calls, fatal_calls, imported == &provider);
    return 0;
}
'''


class PEImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which('clang')
        if not compiler:
            raise unittest.SkipTest('Clang unavailable; import control flow execution unperformed')
        function = import_function()
        cls.directory = tempfile.TemporaryDirectory(prefix='pear-pe-import-')
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        for policy in (0, 1):
            source = cls.root / f'policy{policy}.c'
            source.write_text(f'#define PEAR_NATIVE_PE_LOADER {policy}\n' + PREAMBLE + function + MAIN)
            result = subprocess.run([compiler, '-O0', '-Wall', '-Wextra', '-Werror',
                                     '-fsanitize=undefined', '-fno-sanitize-recover=all',
                                     str(source), '-o', str(cls.root / f'policy{policy}')],
                                    capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError(result.stderr)

    def run_case(self, scenario, policy=1):
        result = subprocess.run([str(self.root / f'policy{policy}'), scenario],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        fields = result.stdout.split()
        self.assertEqual(len(fields), 7, result.stdout)
        return int(fields[0], 16), *map(int, fields[1:])

    def test_named_missing_export_is_typed_without_stub_and_restores_iat(self):
        self.assertEqual(self.run_case('missing-name'), (0xc0000139, 2, 2, 0, 1, 0, 1))

    def test_ordinal_missing_export_is_typed_without_stub_and_restores_iat(self):
        self.assertEqual(self.run_case('missing-ordinal'), (0xc0000138, 2, 2, 0, 1, 0, 1))

    def test_missing_export_directory_preserves_name_and_ordinal_errors(self):
        self.assertEqual(self.run_case('noexports-name'), (0xc0000139, 2, 2, 0, 0, 0, 1))
        self.assertEqual(self.run_case('noexports-ordinal'), (0xc0000138, 2, 2, 0, 0, 0, 1))

    def test_normal_resolved_export_restores_iat_without_stub(self):
        for policy in (0, 1):
            self.assertEqual(self.run_case('resolved', policy), (0, 2, 2, 0, 1, 0, 1))

    def test_other_platform_preserves_existing_stub_fallback(self):
        for scenario in ('missing-name', 'missing-ordinal'):
            self.assertEqual(self.run_case(scenario, 0), (0, 2, 2, 1, 1, 0, 1))
        self.assertEqual(self.run_case('noexports-name', 0), (0, 2, 2, 1, 0, 0, 1))

    def test_failed_protection_prevents_lookup_and_preserves_provider_ownership(self):
        self.assertEqual(self.run_case('protect-denied'), (0xc0000022, 1, 2, 0, 0, 0, 1))

    def test_restore_failure_terminates_instead_of_returning_a_writable_iat(self):
        self.assertEqual(self.run_case('restore-denied-name'), (0xc0000139, 2, 4, 0, 1, 1, 1))
        self.assertEqual(self.run_case('restore-denied-resolved'), (0xc0000022, 2, 4, 0, 1, 1, 1))

    def test_provider_failure_and_unused_import_never_open_writer(self):
        self.assertEqual(self.run_case('provider-failure'), (0xc0000135, 0, 2, 0, 0, 0, 0))
        self.assertEqual(self.run_case('empty'), (0, 0, 2, 0, 0, 0, 0))


if __name__ == '__main__':
    unittest.main()
