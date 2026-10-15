# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic native-bridge contract tests using the actual original C fixture.

The C harness stubs Wine callbacks and the mode getter. It contains no x18
writes, setters, PE execution or Wine runtime. Passing these tests is only
input/result rejection coverage; it cannot authorize or qualify a boundary.
"""
import json
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest

FIXTURE = Path(__file__).resolve().parents[2] / 'dlls/ntdll/unix/pear_abi_fixture.c'

HARNESS = r'''
#include <stdio.h>
#include <stdlib.h>
#include "pear_abi_fixture.c"
static unsigned mode, getter_calls, callbacks, scenario;
static struct thread_data thread = {(void *)(uintptr_t)0x12340000};
static pear_abi_reply reply;
static unsigned char fake_frame[0x330], fake_parent[0x330];
static void *frame_pointer = fake_frame;
static unsigned char fake_getter(void) { ++getter_calls; return mode; }
unsigned char (*pear_x18_getter)(void) = fake_getter;
struct thread_data *get_thread_data(void) { return &thread; }
void *get_syscall_frame(struct thread_data *unused) { (void)unused; return frame_pointer; }
NTSTATUS KeUserModeCallback(ULONG id, const void *opaque, ULONG length, void **result, ULONG *result_length)
{
    const pear_abi_callback *arguments = opaque;
    pear_abi_request *request = (void *)(uintptr_t)arguments->request;
    ++callbacks;
    if (id || length != sizeof(*arguments)) abort();
    request->callback_count = request->nested_count = request->frame_distinct = request->register_checks = 1;
    request->callback_teb_matches = request->native_calls = request->teb_matches = 2;
    NTSTATUS status = request->inject_error ? (NTSTATUS)PEAR_ABI_ERROR : 0;
    reply = (pear_abi_reply){PEAR_ABI_MAGIC, arguments->cookie, arguments->cookie ^ UINT64_C(0x5a5a), (uint32_t)status};
    *result = &reply;
    *result_length = sizeof(reply);
    if (scenario == 20) mode = 1;
    if (scenario == 21) status = (NTSTATUS)0xc000000d;
    if (scenario == 22) *result = NULL;
    if (scenario == 23) --*result_length;
    if (scenario == 24) ++reply.value;
    if (scenario == 25) ++reply.cookie;
    if (scenario == 26) --request->nested_count;
    if (scenario == 27) --request->teb_matches;
    if (scenario == 28) --request->callback_teb_matches;
    if (scenario == 29) --request->frame_distinct;
    if (scenario == 30) --request->register_checks;
    if (scenario == 31) frame_pointer = NULL;
    return status;
}
int main(int argc, char **argv)
{
    if (argc != 2) return 3;
    scenario = (unsigned)strtoul(argv[1], NULL, 10);
    setenv("PEAR_WINE_ABI_FIXTURE", "1", 1);
    setenv("PEAR_BOOTSTRAP_NONCE", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1);
    pear_abi_request request = {0};
    request.magic = PEAR_ABI_MAGIC;
    request.version = 1;
    request.operation = scenario == 1 || scenario == 2 || scenario >= 20 ? 1 : 0;
    request.sequence = scenario == 2 ? 16 : 0;
    request.guest_teb = (uintptr_t)thread.teb;
    request.outer_cookie = PEAR_ABI_OUTER + request.sequence;
    request.inner_cookie = PEAR_ABI_INNER + request.sequence;
    request.inject_error = scenario == 2;
    request.host_entry = request.host_exit = UINT64_MAX;
    if (scenario == 3) unsetenv("PEAR_WINE_ABI_FIXTURE");
    if (scenario == 4) setenv("PEAR_BOOTSTRAP_NONCE", "bad nonce", 1);
    if (scenario == 5) ++request.magic;
    if (scenario == 6) ++request.version;
    if (scenario == 7) request.operation = 3;
    if (scenario == 8) request.sequence = 64;
    if (scenario == 9) ++request.outer_cookie;
    if (scenario == 10) ++request.inner_cookie;
    if (scenario == 11) request.inject_error = 1;
    if (scenario == 12) request.native_calls = 1;
    if (scenario == 13) pear_x18_getter = NULL;
    if (scenario == 14) ++request.guest_teb;
    if (scenario == 15) mode = 1;
    if (scenario >= 40) {
        request.operation = 2;
        request.outer_cookie = PEAR_ABI_INNER;
        request.inner_cookie = PEAR_ABI_LEAF;
        request.parent_frame = (uintptr_t)fake_parent;
        *(uintptr_t *)(fake_frame + 0x110) = request.parent_frame;
        if (scenario == 41) *(uintptr_t *)(fake_frame + 0x110) = 0;
        if (scenario == 42) request.parent_frame = 0;
        if (scenario == 43) request.parent_frame = (uintptr_t)fake_frame;
        if (scenario == 44) frame_pointer = NULL;
    }
    NTSTATUS status = pear_abi_unix_entry(&request);
    printf("{\"status\":%u,\"callbacks\":%u,\"getter_calls\":%u,\"native_calls\":%llu,\"errors\":%llu}\n",
           (unsigned)status, callbacks, getter_calls, (unsigned long long)request.native_calls,
           (unsigned long long)request.error_count);
    return 0;
}
'''


@unittest.skipUnless(platform.system() == 'Darwin' and platform.machine() == 'arm64',
                     'ordinary native ARM64 compiler harness unavailable; not a runtime pass')
class NativeBridgeContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='pear-abi-contract-')
        cls.root = Path(cls.temporary.name)
        # Place exact canonical bytes beside synthetic headers for quoted includes.
        (cls.root / 'pear_abi_fixture.c').write_bytes(FIXTURE.read_bytes())
        for name in ('config.h', 'windef.h', 'winbase.h', 'winternl.h'):
            (cls.root / name).write_text('/* Synthetic C harness declarations only. */\n')
        (cls.root / 'ntstatus.h').write_text('''#include <stdint.h>
typedef int32_t NTSTATUS;
typedef uint32_t ULONG;
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
''')
        (cls.root / 'unix_private.h').write_text('''struct thread_data { void *teb; };
struct thread_data *get_thread_data(void);
void *get_syscall_frame(struct thread_data *);
NTSTATUS KeUserModeCallback(ULONG, const void *, ULONG, void **, ULONG *);
''')
        (cls.root / 'main.c').write_text(HARNESS)
        sdk = subprocess.check_output(['/usr/bin/xcrun', '--show-sdk-path'], text=True).strip()
        compiler = subprocess.check_output(['/usr/bin/xcrun', '--find', 'clang'], text=True).strip()
        cls.binary = cls.root / 'bridge-contract'
        subprocess.run([compiler, '-std=c11', '-arch', 'arm64', '-isysroot', sdk,
                        '-Wall', '-Wextra', '-Werror', '-I', str(cls.root), '-I', str(FIXTURE.parent),
                        str(cls.root / 'main.c'), '-o', str(cls.binary)],
                       check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_case(self, scenario):
        completed = subprocess.run([str(self.binary), str(scenario)], check=True,
                                   capture_output=True, text=True, timeout=3)
        self.assertEqual(completed.stderr, '')
        return json.loads(completed.stdout)

    def test_plain_request_records_host_checks_and_native_entry(self):
        self.assertEqual(self.run_case(0), {'status': 0, 'callbacks': 0, 'getter_calls': 2,
                                          'native_calls': 1, 'errors': 0})

    def test_nested_callback_requires_matching_reply_and_restoration(self):
        self.assertEqual(self.run_case(1), {'status': 0, 'callbacks': 1, 'getter_calls': 2,
                                          'native_calls': 2, 'errors': 0})

    def test_deterministic_error_remains_an_error_status(self):
        result = self.run_case(2)
        self.assertEqual(result['status'], 0xc0000001)
        self.assertEqual(result['errors'], 1)
        self.assertEqual(result['callbacks'], 1)

    def test_absent_opt_in_or_malformed_nonce_does_not_enter_callback(self):
        for case in (3, 4):
            with self.subTest(case=case):
                result = self.run_case(case)
                self.assertEqual(result['status'], 0xc00000bb)
                self.assertEqual(result['callbacks'], 0)
                self.assertEqual(result['getter_calls'], 0)

    def test_invalid_protocol_and_missing_getter_fail_before_callback(self):
        for case in range(5, 14):
            with self.subTest(case=case):
                result = self.run_case(case)
                self.assertEqual(result['status'], 0xc000000d)
                self.assertEqual(result['callbacks'], 0)
                self.assertEqual(result['getter_calls'], 0)

    def test_wrong_real_teb_or_foreign_entry_mode_rejected(self):
        for case in (14, 15):
            with self.subTest(case=case):
                result = self.run_case(case)
                self.assertEqual(result['status'], 0xc000000d)
                self.assertEqual(result['callbacks'], 0)

    def test_nested_request_checks_actual_private_frame_predecessor(self):
        result = self.run_case(40)
        self.assertEqual(result['status'], 0)
        self.assertEqual(result['native_calls'], 1)
        self.assertEqual(result['callbacks'], 0)
        for case in range(41, 45):
            with self.subTest(case=case):
                result = self.run_case(case)
                self.assertEqual(result['status'], 0xc000000d)
                self.assertEqual(result['callbacks'], 0)

    def test_callback_mode_reply_counts_and_nested_state_cannot_be_missing(self):
        for case in range(20, 32):
            with self.subTest(case=case):
                result = self.run_case(case)
                self.assertEqual(result['status'], 0xc000000d)
                self.assertEqual(result['callbacks'], 1)


if __name__ == '__main__':
    unittest.main()
