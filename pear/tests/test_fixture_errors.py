# SPDX-FileCopyrightText: 2026 Pear contributors
# SPDX-License-Identifier: MIT
"""First-error and cleanup regression checks against actual original PE fixtures.

The ordinary C harness replaces Win32/native services with explicit injected
results and compiles the real fixture control flow. It does not run a PE, Wine,
custom page mode or x18 transitions and cannot establish runtime qualification.
The original harness code is SPDX-License-Identifier: MIT.
"""
from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest

FIXTURES = Path(__file__).resolve().parent / 'fixtures'

API_HARNESS = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef wchar_t WCHAR;
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef struct { DWORD cb,dwFlags; HANDLE hStdInput,hStdOutput,hStdError; } STARTUPINFOW;
typedef struct { HANDLE hProcess,hThread; } PROCESS_INFORMATION;
#define TRUE 1
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)
#define ERROR_SUCCESS 0
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_INVALID_DATA 13
#define ERROR_TIMEOUT 1460
#define MEM_RESERVE 1
#define MEM_COMMIT 2
#define MEM_RELEASE 4
#define PAGE_READWRITE 4
#define TLS_OUT_OF_INDEXES 0xffffffffu
#define GENERIC_WRITE 1
#define GENERIC_READ 2
#define CREATE_NEW 1
#define OPEN_EXISTING 2
#define FILE_ATTRIBUTE_NORMAL 0
#define FILE_BEGIN 0
#define INVALID_SET_FILE_POINTER 0xffffffffu
#define STARTF_USESTDHANDLES 1
#define STD_INPUT_HANDLE 0
#define STD_OUTPUT_HANDLE 1
#define STD_ERROR_HANDLE 2
#define CREATE_UNICODE_ENVIRONMENT 1
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 258
#define WAIT_FAILED 0xffffffffu
static unsigned scenario, file_closes, deletes, thread_closes, process_closes, tls_frees, memory_frees, terminations;
static DWORD last_error;
static void *tls;
static int tls_reads;
static unsigned char disk[64];
static DWORD disk_size;
static DWORD GetLastError(void) { return last_error; }
static void SetLastError(DWORD value) { last_error=value; }
static const WCHAR *GetCommandLineW(void) { return L""; }
static DWORD GetEnvironmentVariableW(const WCHAR *name,WCHAR *out,DWORD size)
{
    const WCHAR *value=L"pear value \u03a9\ud55c\uae00\U0001f680";
    (void)name;(void)size;
    wcscpy(out,value);
    return (DWORD)wcslen(value);
}
static void *VirtualAlloc(void *address,size_t size,DWORD type,DWORD protection)
{
    void *p=calloc(1,size);(void)address;(void)type;(void)protection;
    if (p && scenario==7) ((unsigned char *)p)[0]=1;
    return p;
}
static BOOL VirtualFree(void *address,size_t size,DWORD type)
{
    (void)size;(void)type; memory_frees++;free(address);
    if (scenario==7 || scenario==8) {last_error=118;return 0;}
    return 1;
}
static DWORD TlsAlloc(void) { return 4; }
static void *TlsGetValue(DWORD slot)
{
    (void)slot;tls_reads++;
    if (scenario==6 && tls_reads==1) {last_error=116;return NULL;}
    last_error=0;
    if (scenario==16 && tls_reads>1) return NULL;
    if (scenario==17 && tls_reads>1) {last_error=117;return NULL;}
    return tls;
}
static BOOL TlsSetValue(DWORD slot,void *value)
{
    (void)slot;
    if (scenario==5) {last_error=115;return 0;}
    tls=value;return 1;
}
static BOOL TlsFree(DWORD slot)
{
    (void)slot;tls_frees++;
    if (scenario==5 || scenario==6 || scenario==16 || scenario==17) {last_error=220;return 0;}
    return 1;
}
static HANDLE CreateFileW(const WCHAR *name,DWORD access,DWORD share,void *security,DWORD disposition,DWORD attrs,HANDLE template)
{
    (void)name;(void)access;(void)share;(void)security;(void)attrs;(void)template;
    if (disposition==OPEN_EXISTING) {last_error=ERROR_FILE_NOT_FOUND;return INVALID_HANDLE_VALUE;}
    return (HANDLE)10;
}
static BOOL WriteFile(HANDLE handle,const void *data,DWORD size,DWORD *written,void *overlapped)
{
    (void)overlapped;
    if (handle==(HANDLE)20) { *written=(DWORD)fwrite(data,1,size,stdout);return *written==size; }
    if (scenario==1) {last_error=111;return 0;}
    memcpy(disk,data,size);disk_size=size;*written=size-(scenario==14);return 1;
}
static DWORD SetFilePointer(HANDLE handle,long distance,void *high,DWORD origin)
{
    (void)handle;(void)distance;(void)high;(void)origin;
    if (scenario==18) {last_error=122;return INVALID_SET_FILE_POINTER;}
    if (scenario==19) {last_error=123;return 7;}
    if (scenario==20) {last_error=0;return INVALID_SET_FILE_POINTER;}
    return 0;
}
static BOOL ReadFile(HANDLE handle,void *data,DWORD size,DWORD *read_count,void *overlapped)
{
    (void)handle;(void)size;(void)overlapped;
    if (scenario==2) {last_error=112;return 0;}
    memcpy(data,disk,disk_size);*read_count=disk_size;
    if (scenario==15) ((unsigned char *)data)[0]^=1;
    return 1;
}
static BOOL CloseHandle(HANDLE handle)
{
    if (handle==(HANDLE)10) {
        file_closes++;
        if (scenario==1 || scenario==2 || scenario==14 || scenario==15 || scenario==18 || scenario==19 || scenario==20) {last_error=221;return 0;}
        if (scenario==9) {last_error=119;return 0;}
    } else if (handle==(HANDLE)11) {
        thread_closes++;
        if (scenario==4) {last_error=114;return 0;}
    } else if (handle==(HANDLE)12) {
        process_closes++;
        if (scenario==3 || scenario==4 || scenario==11 || scenario==12 || scenario==13) {last_error=222;return 0;}
    } else abort();
    return 1;
}
static BOOL DeleteFileW(const WCHAR *name)
{
    (void)name;deletes++;
    if (scenario==1 || scenario==2 || scenario==14 || scenario==15 || scenario==18 || scenario==19 || scenario==20) {last_error=223;return 0;}
    if (scenario==10) {last_error=120;return 0;}
    return 1;
}
static DWORD GetModuleFileNameW(HANDLE module,WCHAR *out,DWORD size)
{(void)module;(void)size;wcscpy(out,L"C:\\fixture.exe");return (DWORD)wcslen(out);}
static HANDLE GetStdHandle(DWORD handle) {(void)handle;return (HANDLE)20;}
static BOOL CreateProcessW(const WCHAR *app,WCHAR *command,void *pa,void *ta,BOOL inherit,DWORD flags,void *env,void *cwd,STARTUPINFOW *startup,PROCESS_INFORMATION *process)
{
    (void)app;(void)command;(void)pa;(void)ta;(void)inherit;(void)flags;(void)env;(void)cwd;(void)startup;
    process->hThread=(HANDLE)11;process->hProcess=(HANDLE)12;return 1;
}
static DWORD WaitForSingleObject(HANDLE handle,DWORD timeout)
{
    (void)handle;(void)timeout;
    if (scenario==11) {last_error=121;return WAIT_FAILED;}
    if (scenario==12) return WAIT_TIMEOUT;
    return WAIT_OBJECT_0;
}
static BOOL TerminateProcess(HANDLE handle,DWORD code)
{(void)handle;(void)code;terminations++;last_error=224;return 0;}
static BOOL GetExitCodeProcess(HANDLE handle,DWORD *code)
{
    (void)handle;
    if (scenario==3) {last_error=113;return 0;}
    *code=scenario==13 ? 99 : 37;return 1;
}
'''

API_MAIN = r'''
int main(int argc,char **argv)
{
    int valid;
    if(argc!=2)return 2;
    scenario=(unsigned)atoi(argv[1]);
    wcscpy(words[1],arg_space);wcscpy(words[2],arg_unicode);
    if(scenario==21) {wcscpy(words[2],arg_space);wcscpy(words[3],arg_unicode);valid=basics(4,1);}
    else if(scenario==0) valid=basics(3,0) && files() && child_roundtrip();
    else if(scenario==5 || scenario==6 || scenario==7 || scenario==8 || scenario==16 || scenario==17)valid=basics(3,0);
    else if(scenario==3 || scenario==4 || scenario==11 || scenario==12 || scenario==13)valid=child_roundtrip();
    else valid=files();
    printf("{\"valid\":%d,\"checks\":%u,\"step\":%u,\"code\":%u,\"hash\":\"%016llx\","
           "\"child_exit\":%u,\"file_closes\":%u,\"deletes\":%u,\"thread_closes\":%u,"
           "\"process_closes\":%u,\"tls_frees\":%u,\"memory_frees\":%u,\"terminations\":%u}\n",
           valid,checks,error_step,error_code,(unsigned long long)payload_hash,child_exit,file_closes,deletes,
           thread_closes,process_closes,tls_frees,memory_frees,terminations);
    if(!report(scenario==21))return 10;
    return 0;
}
'''

ABI_HARNESS = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
typedef void *HMODULE;
typedef wchar_t WCHAR;
typedef long LONG;
typedef unsigned long ULONG;
#define WINAPI
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 4
#define GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT 2
#define MEM_RESERVE 0x2000
#define PAGE_NOACCESS 1
typedef struct { unsigned State,Protect; } MEMORY_BASIC_INFORMATION;
typedef LONG (*kernel_callback)(void *,ULONG);
typedef struct { HMODULE module;kernel_callback delegate;unsigned unload_attempts,held_mapping_checks,error_step; } pear_lifetime_control;
typedef LONG (*pear_lifetime_configure)(pear_lifetime_control *);
typedef struct { uint64_t outer_cookie; } pear_abi_request;
static unsigned error_step,lifetime_error,loads,callback_unload_attempts,held_mapping_checks;
static unsigned callback_holds,continuation_holds,callback_releases,continuation_releases,retirements,compatible_reuses;
static uintptr_t previous_module;
static uint64_t expected_teb,unix_handle;
static void *dispatcher;
static unsigned scenario,unload_target_calls,unload_continuation_calls,free_calls,events_loaded,events_retired,gateway_calls;
static unsigned target_refs,continuation_refs;
static pear_lifetime_control *configured;
static uint64_t teb[32],peb[32];
static kernel_callback old_table[1];
static const HMODULE target=(void *)0x100000,continuation_image=(void *)0x200000;
static uint64_t held_callback_call(pear_abi_request *,unsigned);
static LONG guest_callback(void *opaque,ULONG length) {(void)opaque;(void)length;return 0;}
static LONG callback(void *opaque,ULONG length) {(void)opaque;(void)length;return 0;}
static LONG configure(pear_lifetime_control *control) {configured=control;return scenario==1 ? -1 : 0;}
static HMODULE LoadLibraryW(const WCHAR *name)
{
    (void)name;if(scenario==10)return NULL;target_refs=1;continuation_refs=0;return target;
}
static void *GetProcAddress(HMODULE module,const char *name)
{
    (void)module;
    if(!strcmp(name,"PearConfigure"))return (void *)(uintptr_t)configure;
    if(scenario==8)return NULL;
    return (void *)(uintptr_t)callback;
}
static LONG addref(unsigned flags,HMODULE module)
{
    (void)flags;
    if(module==target) {if(scenario==6)return -1;target_refs++;}
    else {if(scenario==7)return -1;continuation_refs++;}
    return 0;
}
static int GetModuleHandleExW(unsigned flags,const WCHAR *address,HMODULE *module)
{
    (void)flags;
    if((uintptr_t)address==(uintptr_t)held_callback_call) {
        if(scenario==15)return 0;
        *module=continuation_image;return 1;
    }
    return 0;
}
static HMODULE GetModuleHandleW(const WCHAR *name) {(void)name;return continuation_image;}
static int lifetime_event(unsigned round,const char *event,HMODULE module,kernel_callback cb)
{
    (void)round;(void)module;(void)cb;
    if(!strcmp(event,"loaded")) {events_loaded++;return scenario!=2;}
    events_retired++;return scenario!=12;
}
static uint64_t pear_abi_gateway(void *dispatch,uint64_t handle,pear_abi_request *request,uint64_t cookie)
{
    (void)dispatch;(void)handle;(void)request;(void)cookie;
    kernel_callback *table=*(kernel_callback **)((char *)peb+0x58);
    if(table[0]!=callback || !configured || target_refs!=2 || continuation_refs!=1)abort();
    gateway_calls++;
    configured->unload_attempts=1;configured->held_mapping_checks=1;target_refs--;
    if(scenario==3 || scenario==13)configured->error_step=1;
    if(scenario==13) {error_step=4;return 0xc0000001u;}
    if(scenario==14)return UINT64_C(1)<<32;
    return 0;
}
static LONG unload(HMODULE module)
{
    if(module==target) {
        unload_target_calls++;
        if(scenario==1 || scenario==2 || scenario==3 || scenario==4 || scenario==7 || scenario==13 || scenario==15)return -1;
        if(!target_refs)abort();target_refs--;
    } else {
        unload_continuation_calls++;
        if(scenario==1 || scenario==2 || scenario==3 || scenario==4 || scenario==5 || scenario==13)return -1;
        if(!continuation_refs)abort();continuation_refs--;
    }
    return 0;
}
static int FreeLibrary(HMODULE module)
{
    (void)module;free_calls++;
    if(scenario==1 || scenario==2 || scenario==6 || scenario==7 || scenario==8 || scenario==9 || scenario==15)return 0;
    if(!target_refs)abort();target_refs--;return 1;
}
static size_t VirtualQuery(const void *address,MEMORY_BASIC_INFORMATION *memory,size_t size)
{
    (void)address;memory->State=scenario==11 ? 0 : MEM_RESERVE;memory->Protect=0;return size;
}
static int state_valid(const pear_abi_request *request,uint32_t expected)
{(void)request;(void)expected;return scenario!=16;}
'''

ABI_MAIN = r'''
int main(int argc,char **argv)
{
    pear_abi_request request={0};
    if(argc!=2)return 2;
    scenario=(unsigned)atoi(argv[1]);
    expected_teb=(uintptr_t)teb;
    *(uint64_t *)((char *)teb+0x60)=(uintptr_t)peb;
    *(kernel_callback **)((char *)peb+0x58)=old_table;
    if(scenario==9)previous_module=0x300000;
    if(scenario==16)error_step=4;
    unsigned count=scenario==0 ? 32 : 1;
    for(unsigned i=0;i<count;i++) {
        uint64_t observed=held_callback_call(&request,i);
        uint32_t expected=0;
        do {
/* ACTUAL_OUTER_CHECK */
        } while(0);
        if(*(kernel_callback **)((char *)peb+0x58)!=old_table)abort();
    }
    printf("{\"lifetime_error\":%u,\"error_step\":%u,\"loads\":%u,\"callback_holds\":%u,"
           "\"continuation_holds\":%u,\"callback_releases\":%u,\"continuation_releases\":%u,"
           "\"retirements\":%u,\"compatible_reuses\":%u,\"unload_target_calls\":%u,"
           "\"unload_continuation_calls\":%u,\"free_calls\":%u,\"events_loaded\":%u,"
           "\"events_retired\":%u,\"gateway_calls\":%u,\"target_refs\":%u,\"continuation_refs\":%u}\n",
           lifetime_error,error_step,loads,callback_holds,continuation_holds,callback_releases,continuation_releases,
           retirements,compatible_reuses,unload_target_calls,unload_continuation_calls,free_calls,
           events_loaded,events_retired,gateway_calls,target_refs,continuation_refs);
    return 0;
}
'''


def api_source():
    source = (FIXTURES / 'api_pe.c').read_text()
    start = source.index('static const WCHAR arg_space[]')
    end = source.index('static int architecture_check(void)')
    return API_HARNESS + source[start:end] + API_MAIN


def abi_source():
    source = (FIXTURES / 'abi_pe.c').read_text()
    start = source.index('static uint64_t held_callback_call(')
    end = source.index('\n}\n', start) + 3
    helpers = '\n'.join(line for line in source.splitlines() if line.startswith('static void record_')) + '\n'
    outer_start = source.index('            if ((observed >> 32) || (uint32_t)observed != expected || !state_valid(&request, expected))')
    outer_end = source.index('\n            }', outer_start) + len('\n            }')
    return ABI_HARNESS + helpers + source[start:end] + ABI_MAIN.replace(
        '/* ACTUAL_OUTER_CHECK */', source[outer_start:outer_end])


@unittest.skipUnless(shutil.which('clang'), 'ordinary C compiler unavailable; not a runtime pass')
class FixtureErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='pear-fixture-errors-')
        cls.root = Path(cls.temporary.name)
        cls.binaries = {}
        for kind, source in (('api', api_source()), ('abi', abi_source())):
            path = cls.root / (kind + '.c')
            path.write_text(source)
            binary = cls.root / kind
            result = subprocess.run(['clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                                     '-Wno-unused-function', '-O1', '-fsanitize=undefined', '-fno-sanitize-recover=all',
                                     str(path), '-o', str(binary)], capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stderr)
            cls.binaries[kind] = binary

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_case(self, kind, case):
        result = subprocess.run([str(self.binaries[kind]), str(case)], check=True,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.stderr, '')
        return [json.loads(line) for line in result.stdout.splitlines()]

    def api_failure(self, case, step, code):
        actual, report = self.run_case('api', case)
        self.assertEqual((actual['valid'], actual['step'], actual['code']), (0, step, code))
        self.assertEqual((report['error_step'], report['win32_error']), (step, code))
        return actual

    def test_api_success_report_unchanged(self):
        actual, report = self.run_case('api', 0)
        self.assertEqual((actual['valid'], actual['checks']), (1, 255))
        self.assertEqual(report, {'version': 1, 'record_kind': 'pear_api_result', 'role': 'parent',
                                 'checks_bitmask': 255, 'error_step': 0, 'win32_error': 0,
                                 'fnv1a64': 'eb776cf97e933998', 'child_exit': 37})

    def test_api_child_success_report_unchanged(self):
        actual, report = self.run_case('api', 21)
        self.assertEqual((actual['valid'], actual['checks']), (1, 15))
        self.assertEqual(report, {'version': 1, 'record_kind': 'pear_api_result', 'role': 'child',
                                 'checks_bitmask': 15, 'error_step': 0, 'win32_error': 0,
                                 'fnv1a64': '0000000000000000', 'child_exit': 0})

    def test_io_error_precedes_close_and_delete_failures(self):
        for case, step, code in [(1, 5, 111), (2, 5, 112), (9, 5, 119), (10, 7, 120),
                                 (14, 5, 13), (15, 5, 13), (18, 5, 122), (19, 5, 13), (20, 5, 13)]:
            with self.subTest(case=case):
                row = self.api_failure(case, step, code)
                self.assertEqual((row['file_closes'], row['deletes']), (1, 1))

    def test_tls_error_precedes_free_failure(self):
        for case, code in [(5, 115), (6, 116), (16, 13), (17, 117)]:
            with self.subTest(case=case):
                row = self.api_failure(case, 4, code)
                self.assertEqual((row['tls_frees'], row['memory_frees']), (1, 1))

    def test_memory_content_failure_precedes_free_failure(self):
        for case, code in [(7, 13), (8, 118)]:
            with self.subTest(case=case):
                self.assertEqual(self.api_failure(case, 3, code)['memory_frees'], 1)

    def test_child_error_precedes_cleanup_failures(self):
        for case, code in [(3, 113), (4, 114), (11, 121), (12, 1460), (13, 13)]:
            with self.subTest(case=case):
                row = self.api_failure(case, 8, code)
                self.assertEqual((row['thread_closes'], row['process_closes']), (1, 1))
                if case in (11, 12):
                    self.assertEqual(row['terminations'], 1)

    def test_abi_success_keeps_holds_releases_and_reuse(self):
        row, = self.run_case('abi', 0)
        for key in ('loads', 'callback_holds', 'continuation_holds', 'callback_releases',
                    'continuation_releases', 'retirements', 'events_loaded', 'events_retired',
                    'gateway_calls', 'unload_target_calls', 'unload_continuation_calls'):
            self.assertEqual(row[key], 32)
        self.assertEqual(row['compatible_reuses'], 31)
        for key in ('lifetime_error', 'error_step', 'free_calls', 'target_refs', 'continuation_refs'):
            self.assertEqual(row[key], 0)

    def test_abi_first_error_survives_later_release_failures(self):
        # Expected actual cleanup-call counts were observed in the preserved
        # pre-fix fixture harness; changing attribution must not skip cleanup.
        cases = {
            1: (5, 8, 1, 1, 1), 2: (6, 8, 1, 1, 1), 3: (7, 8, 2, 1, 0),
            4: (8, 8, 2, 1, 0), 5: (9, 8, 1, 2, 0), 6: (3, 8, 0, 0, 1),
            7: (4, 8, 1, 0, 1), 8: (3, 8, 0, 0, 1), 9: (2, 8, 0, 0, 1),
            10: (1, 8, 0, 0, 0), 11: (10, 8, 1, 1, 0), 12: (11, 8, 1, 1, 0),
            13: (7, 4, 2, 1, 0), 14: (0, 5, 1, 1, 0), 15: (4, 8, 1, 0, 1),
        }
        for case, expected in cases.items():
            with self.subTest(case=case):
                row, = self.run_case('abi', case)
                self.assertEqual(tuple(row[key] for key in ('lifetime_error', 'error_step',
                                 'unload_target_calls', 'unload_continuation_calls', 'free_calls')), expected)

    def test_abi_guest_error_survives_outer_bridge_failure(self):
        row, = self.run_case('abi', 16)
        self.assertEqual((row['lifetime_error'], row['error_step']), (0, 4))
        self.assertEqual((row['unload_target_calls'], row['unload_continuation_calls']), (1, 1))


if __name__ == '__main__':
    unittest.main()
