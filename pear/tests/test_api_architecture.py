"""Injected architecture-query checks against the actual original PE fixture.

The ordinary native harness replaces module lookup, the NT query and stdout.
It neither executes Wine/PE nor establishes native-only runtime qualification.
Original harness code: SPDX-License-Identifier: MIT.
"""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parent / 'fixtures/api_pe.c'

HARNESS = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#define NTAPI
#define ERROR_INVALID_DATA 13
#define STD_OUTPUT_HANDLE 1
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef uint32_t DWORD;
typedef void *HANDLE;
typedef void *HMODULE;
static unsigned scenario, query_calls, arguments_valid, error_step;
static DWORD error_code, last_error;
static DWORD GetLastError(void) { return last_error; }
static HMODULE GetModuleHandleW(const wchar_t *name)
{
    if (wcscmp(name, L"ntdll.dll")) abort();
    if (scenario == 1) { last_error = 126; return NULL; }
    return (HMODULE)1;
}
static LONG query(ULONG kind, void *input, ULONG input_size, void *output, ULONG output_size, ULONG *returned)
{
    DWORD *words = output;
    ++query_calls;
    arguments_valid = kind == 181 && input && input_size == sizeof(HANDLE) &&
                      *(HANDLE *)input == NULL && output && output_size == 32 && returned;
    if (!arguments_valid) abort();
    words[0] = 0x7AA64u; words[1] = 0; *returned = 8;
    switch (scenario) {
    case 4: case 14: return (LONG)0xc000000du;
    case 5: *returned = 36; break;
    case 6: *returned = 9; break;
    case 7: *returned = 4; break;
    case 8: words[0] = 0x3014cu; break;
    case 9: words[1] = 0x13014cu; words[2] = 0; *returned = 12; break;
    case 10: words[1] = 0x7AA64u; break;
    case 11: words[0] = 0x3AA64u; break;
    case 12: words[0] |= 0x80000000u; break;
    case 13: return 1;
    case 15: words[0] = 0; break;
    case 16: words[0] = words[1] = UINT32_MAX; break;
    case 17: words[1] = 0x10000u; break;
    }
    return 0;
}
static ULONG convert(LONG status)
{
    if ((uint32_t)status != 0xc000000du) abort();
    last_error = 999;
    return 87;
}
static uintptr_t GetProcAddress(HMODULE module, const char *name)
{
    if (module != (HMODULE)1) abort();
    if (!strcmp(name, "NtQuerySystemInformationEx")) {
        if (scenario == 2) { last_error = 127; return 0; }
        return (uintptr_t)query;
    }
    if (!strcmp(name, "RtlNtStatusToDosError")) {
        if (scenario == 3) { last_error = 127; return 0; }
        return (uintptr_t)convert;
    }
    abort();
}
static HANDLE GetStdHandle(DWORD which) { if (which != STD_OUTPUT_HANDLE) abort(); return (HANDLE)2; }
static int WriteFile(HANDLE handle, const void *buffer, DWORD size, DWORD *written, void *overlapped)
{
    if (handle != (HANDLE)2 || overlapped) abort();
    if (scenario == 18) { last_error = 112; return 0; }
    *written = (DWORD)fwrite(buffer, 1, size, stdout);
    if (scenario == 19) --*written;
    return 1;
}
'''

MAIN = r'''
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    scenario = (unsigned)strtoul(argv[1], NULL, 10);
    if (scenario == 14) { error_step = 6; error_code = 31; }
    int valid = architecture_check();
    printf("{\"valid\":%d,\"step\":%u,\"code\":%u,\"query_calls\":%u,\"arguments_valid\":%u}\n",
           valid, error_step, error_code, query_calls, arguments_valid);
    int reported = architecture_report();
    printf("{\"reported\":%d,\"buffer_length\":%u}\n", reported, output_length);
    return 0;
}
'''


def actual_source():
    source = SOURCE.read_text()
    declarations = source[source.index('typedef LONG (NTAPI *query_architectures_fn)'):
                          source.index('static const WCHAR arg_space[]')]
    errors = source[source.index('static int fail_code('):source.index('static uint64_t hash_bytes(')]
    formatter = source[source.index('static char output[512]'):source.index('static int report(int child)')]
    functions = source[source.index('static int architecture_check(void)'):
                       source.index('void WINAPI mainCRTStartup(void)')]
    return HARNESS + declarations + errors + formatter + functions + MAIN


class ArchitectureQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='pear-api-architecture-')
        cls.root = Path(cls.directory.name)
        source = cls.root / 'query.c'
        source.write_text(actual_source())
        cls.binary = cls.root / 'query'
        result = subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1',
                                 '-fsanitize=undefined', '-fno-sanitize-recover=all',
                                 str(source), '-o', str(cls.binary)], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def run_case(self, scenario):
        result = subprocess.run([str(self.binary), str(scenario)], capture_output=True,
                                text=True, timeout=10, check=True)
        self.assertEqual(result.stderr, '')
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_real_query_contract_and_observed_output(self):
        observation, row, output = self.run_case(0)
        self.assertEqual(observation, {'valid': 1, 'step': 0, 'code': 0,
                                       'query_calls': 1, 'arguments_valid': 1})
        self.assertEqual(row, {'version': 1, 'record_kind': 'pear_architecture_result', 'status': 0,
                              'returned_bytes': 8, 'machines': [43620], 'flags': [7], 'terminator': 0})
        self.assertEqual(output, {'reported': 1, 'buffer_length': 0})

    def test_missing_real_exports_preserve_win32_errors(self):
        for scenario, code in ((1, 126), (2, 127), (3, 127)):
            with self.subTest(scenario=scenario):
                observation, output = self.run_case(scenario)
                self.assertEqual(observation, {'valid': 0, 'step': 9, 'code': code,
                                               'query_calls': 0, 'arguments_valid': 0})
                self.assertEqual(output['reported'], 1)

    def test_failed_query_preserves_ntstatus_and_converted_error(self):
        observation, row, _ = self.run_case(4)
        self.assertEqual((observation['valid'], observation['step'], observation['code']), (0, 9, 87))
        self.assertEqual(row['status'], 0xc000000d)
        self.assertEqual(row['machines'], [])
        self.assertEqual(row['terminator'], 0xffffffff)

    def test_bad_lengths_architectures_flags_and_terminators_fail(self):
        for scenario in range(5, 18):
            if scenario == 14:
                continue
            with self.subTest(scenario=scenario):
                observation, row, _ = self.run_case(scenario)
                self.assertEqual((observation['valid'], observation['step'], observation['code']), (0, 9, 13))
                self.assertEqual(observation['arguments_valid'], 1)
                self.assertNotEqual(row, self.run_case(0)[1])

    def test_prior_error_survives_query_failure(self):
        observation, row, _ = self.run_case(14)
        self.assertEqual((observation['valid'], observation['step'], observation['code']), (0, 6, 31))
        self.assertEqual(row['status'], 0xc000000d)

    def test_report_errors_and_short_writes_are_not_success(self):
        for scenario in (18, 19):
            with self.subTest(scenario=scenario):
                rows = self.run_case(scenario)
                self.assertEqual(rows[0]['valid'], 1)
                self.assertEqual(rows[-1], {'reported': 0, 'buffer_length': 0})
