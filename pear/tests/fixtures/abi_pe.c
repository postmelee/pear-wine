/* Original Pear Stage 3 fixture, SPDX-License-Identifier: MIT.
 * The callback table and TEB offsets are from the pinned Wine ARM64 ABI.
 * No guest x18 substitution, direct native call or Apple setter occurs here.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "lifetime_pe.h"
#define PEAR_ABI_PROTOCOL_ONLY
#include "abi_native.c"

#if !defined(__aarch64__) || defined(__arm64ec__)
#error This fixture requires an ordinary ARM64 Windows PE target.
#endif

typedef LONG (WINAPI *unix_dispatcher)(uint64_t, unsigned, void *);
typedef LONG (WINAPI *callback_return)(void *, ULONG, LONG);
typedef LONG (WINAPI *kernel_callback)(void *, ULONG);
extern uint64_t pear_abi_gateway(unix_dispatcher, uint64_t, pear_abi_request *, uint64_t);
static unix_dispatcher dispatcher;
static callback_return return_callback;
static uint64_t unix_handle, expected_teb;
static unsigned error_step, roundtrips, callbacks, nested_calls, error_returns, gateways;
static unsigned native_calls, teb_checks, frame_checks, host_checks;
static uint64_t bad_registers;
static uint32_t inactive_status;
typedef LONG (WINAPI *addref_dll)(ULONG, HMODULE);
typedef LONG (WINAPI *unload_dll)(HMODULE);
typedef struct pear_unicode_string { USHORT Length, MaximumLength; WCHAR *Buffer; } pear_unicode_string;
typedef LONG (WINAPI *load_dll)(const WCHAR *, DWORD *, const pear_unicode_string *, HMODULE *);
static addref_dll addref;
static unload_dll unload;
static load_dll load;
static unsigned lifetime_error, loads, callback_unload_attempts, held_mapping_checks;
static unsigned callback_holds, continuation_holds, callback_releases, continuation_releases;
static unsigned retirements, compatible_reuses, rejected_imports, failed_load_cleanup_checks;
static uint32_t named_import_status, ordinal_import_status;
static uintptr_t previous_module;
static unsigned relocation_error, relocation_copies, relocation_loads, relocation_calls;
static unsigned relocation_code_checks, relocation_data_checks, relocation_value_checks, relocation_retirements;
static DWORD relocation_win32_error;
static int relocation_event(unsigned copy, unsigned round, HMODULE module, LONG status,
                            const pear_relocation_observation *value, ULONG peer_value);
static int relocation_retired_event(unsigned copy, HMODULE module);


static void record_error(unsigned step) { if (!error_step) error_step = step; }
static void record_lifetime_error(unsigned step) { if (!lifetime_error) lifetime_error = step; }
static int lifetime_event(unsigned round, const char *event, HMODULE module, kernel_callback callback);
static int rejection_event(const char *event, uint32_t status, int handle_null, int provider_absent);

static uint64_t current_teb(void)
{
    uint64_t value;
    __asm__ volatile("mov %0, x18" : "=r"(value));
    return value;
}

static void initialize(pear_abi_request *request, unsigned operation, unsigned sequence)
{
    uint64_t *fields = (uint64_t *)request;
    for (unsigned i = 0; i < sizeof(*request) / sizeof(*fields); ++i) fields[i] = 0;
    request->magic = PEAR_ABI_MAGIC;
    request->version = 1;
    request->operation = operation;
    request->sequence = sequence;
    request->guest_teb = expected_teb;
    request->outer_cookie = (operation == 2 ? PEAR_ABI_INNER : PEAR_ABI_OUTER) + sequence;
    request->inner_cookie = (operation == 2 ? PEAR_ABI_LEAF : PEAR_ABI_INNER) + sequence;
    request->inject_error = operation == 1 && sequence >= 16;
    request->host_entry = request->host_exit = UINT64_MAX;
}

static int state_valid(const pear_abi_request *request, uint32_t status)
{
    unsigned expected_calls = request->operation == 1 ? 2 : 1;
    return request->host_entry == 0 && request->host_exit == 0 &&
        request->native_calls == expected_calls && request->teb_matches == expected_calls &&
        request->bridge_status == status && current_teb() == expected_teb;
}

static LONG WINAPI guest_callback(void *opaque, ULONG length)
{
    pear_abi_callback *arguments = opaque;
    pear_abi_reply reply = {PEAR_ABI_MAGIC, 0, 0, 0};
    pear_abi_request inner;
    LONG result = (LONG)UINT32_C(0xc000000d);
    if (length != sizeof(*arguments) || arguments->magic != PEAR_ABI_MAGIC ||
        arguments->sequence >= 32 || arguments->guest_teb != expected_teb ||
        arguments->cookie != PEAR_ABI_INNER + arguments->sequence ||
        arguments->inject_error != (arguments->sequence >= 16)) goto failed;
    pear_abi_request *outer = (pear_abi_request *)(uintptr_t)arguments->request;
    if (!outer || outer->magic != PEAR_ABI_MAGIC || outer->sequence != arguments->sequence ||
        outer->operation != 1 || outer->guest_teb != expected_teb || current_teb() != expected_teb) goto failed;
    ++outer->callback_count;
    ++outer->callback_teb_matches;
    initialize(&inner, 2, (unsigned)arguments->sequence);
    inner.parent_frame = outer->native_frame;
    if ((uintptr_t)&inner == (uintptr_t)outer || inner.outer_cookie == outer->outer_cookie) goto failed;
    uint64_t observed = pear_abi_gateway(dispatcher, unix_handle, &inner, inner.outer_cookie);
    ++gateways;
    bad_registers |= observed >> 32;
    if ((uint32_t)observed || (observed >> 32) || !state_valid(&inner, 0)) goto failed;
    outer->frame_distinct = inner.native_frame != outer->native_frame && inner.parent_frame == outer->native_frame;
    if (!outer->frame_distinct) goto failed;
    ++outer->register_checks;
    ++outer->nested_count;
    ++outer->callback_teb_matches;
    outer->native_calls += inner.native_calls;
    outer->teb_matches += inner.teb_matches;
    ++nested_calls;
    host_checks += 2;
    result = arguments->inject_error ? (LONG)PEAR_ABI_ERROR : 0;
    reply.cookie = arguments->cookie;
    reply.value = reply.cookie ^ UINT64_C(0x5a5a);
    reply.status = (uint32_t)result;
    return_callback(&reply, sizeof(reply), result);
    /* A valid active callback must never return into this guest frame. */
    ExitProcess(94);
failed:
    record_error(4);
    return_callback(NULL, 0, result);
    ExitProcess(95);
}

/* This fixture owns the only callback table on its single execution thread.
 * Capture the exact target once, keep that private table stable across the
 * complete Unix call, and hold both modules until native reply consumption.
 * No callback-local finally block runs after a direct NtCallbackReturn. */
static uint64_t held_callback_call(pear_abi_request *request, unsigned sequence)
{
    HMODULE module = NULL, continuation = NULL, observed_module = NULL;
    int callback_ref = 0, continuation_ref = 0;
    uint64_t observed = UINT32_C(0xc0000001);
    kernel_callback callback = NULL;
    pear_lifetime_control control = {0};
    uint64_t peb = *(uint64_t *)(uintptr_t)(expected_teb + 0x60);
    kernel_callback **table_location = (kernel_callback **)(uintptr_t)(peb + 0x58);
    module = LoadLibraryW(L"lifetime-arm64.dll");
    if (!module) { record_lifetime_error(1); goto done; }
    ++loads;
    if (previous_module && previous_module != (uintptr_t)module) { record_lifetime_error(2); goto done; }
    if (previous_module) ++compatible_reuses;
    pear_lifetime_configure configure = (pear_lifetime_configure)(uintptr_t)GetProcAddress(module, "PearConfigure");
    callback = (kernel_callback)(uintptr_t)GetProcAddress(module, "PearCallback");
    if (!configure || !callback || addref(0, module)) { record_lifetime_error(3); goto done; }
    callback_ref = 1;
    ++callback_holds;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (const WCHAR *)(uintptr_t)held_callback_call, &continuation) ||
        continuation != GetModuleHandleW(NULL) || addref(0, continuation)) { record_lifetime_error(4); goto done; }
    continuation_ref = 1;
    ++continuation_holds;
    control.module = module;
    control.delegate = guest_callback;
    if (configure(&control)) { record_lifetime_error(5); goto done; }
    if (!lifetime_event(sequence, "loaded", module, callback)) { record_lifetime_error(6); goto done; }
    kernel_callback table[] = {callback};
    kernel_callback *saved_table = *table_location;
    *table_location = table;
    observed = pear_abi_gateway(dispatcher, unix_handle, request, request->outer_cookie);
    *table_location = saved_table;
    callback_unload_attempts += control.unload_attempts;
    held_mapping_checks += control.held_mapping_checks;
    if (control.error_step || control.unload_attempts != 1 || control.held_mapping_checks != 1)
        record_lifetime_error(7);
    /* The native entry has returned after reading its callback reply. No
     * discarded callback stack payload is touched by these release calls. */
    if (unload(module)) { record_lifetime_error(8); goto done; }
    callback_ref = 0;
    ++callback_releases;
    if (unload(continuation)) { record_lifetime_error(9); goto done; }
    continuation_ref = 0;
    ++continuation_releases;
    MEMORY_BASIC_INFORMATION memory;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                          GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                          (const WCHAR *)(uintptr_t)callback, &observed_module) || observed_module ||
        VirtualQuery((const void *)(uintptr_t)callback, &memory, sizeof(memory)) != sizeof(memory) ||
        memory.State != MEM_RESERVE || (memory.Protect && memory.Protect != PAGE_NOACCESS)) {
        record_lifetime_error(10);
        goto done;
    }
    ++retirements;
    previous_module = (uintptr_t)module;
    if (!lifetime_event(sequence, "retired", module, callback)) record_lifetime_error(11);
done:
    if (callback_ref && unload(module)) record_lifetime_error(12);
    if (continuation_ref && unload(continuation)) record_lifetime_error(13);
    if (module && !control.unload_attempts && !FreeLibrary(module)) record_lifetime_error(14);
    if (lifetime_error) record_error(8);
    return observed;
}

static int rejected_imports_check(void)
{
    WCHAR *names[] = {L"missing-name-arm64.dll", L"missing-ordinal-arm64.dll"};
    uint32_t expected[] = {UINT32_C(0xc0000139), UINT32_C(0xc0000138)};
    for (unsigned i = 0; i < 2; ++i) {
        HMODULE module = NULL;
        unsigned length = 0;
        while (names[i][length]) ++length;
        pear_unicode_string name = {(USHORT)(length * sizeof(WCHAR)),
                                    (USHORT)((length + 1) * sizeof(WCHAR)), names[i]};
        uint32_t status = (uint32_t)load(NULL, 0, &name, &module);
        int absent = !GetModuleHandleW(L"lifetime-arm64.dll") && !GetModuleHandleW(names[i]);
        if (!rejection_event(i ? "ordinal" : "name", status, !module, absent)) return 0;
        if (i) ordinal_import_status = status;
        else named_import_status = status;
        if (status != expected[i] || module || !absent) {
            if (module) FreeLibrary(module);
            record_lifetime_error(15 + i);
            return 0;
        }
        ++rejected_imports;
        ++failed_load_cleanup_checks;
    }
    return 1;
}

static void relocation_fail(unsigned step, DWORD code)
{
    if (!relocation_error) { relocation_error = step; relocation_win32_error = code; }
}

static int relocation_path_append(WCHAR *path, unsigned capacity, const WCHAR *suffix)
{
    unsigned at = 0, length = 0;
    while (at < capacity && path[at]) ++at;
    while (suffix[length]) ++length;
    if (at == capacity || length >= capacity - at) return 0;
    for (unsigned i = 0; i <= length; ++i) path[at + i] = suffix[i];
    return 1;
}

static int relocation_check(void)
{
    static const WCHAR *names[] = {L"pear-relocation-a.dll", L"pear-relocation-b.dll"};
    static const char *exports[] = {"PearRelocationProbe", "PearRelocationCode", "PearRelocationData",
                                   "PearRelocationCodePointer", "PearRelocationDataPointer", "PearSecurityCookie"};
    /* Single-thread fixture storage avoids introducing a CRT stack-probe dependency. */
    static WCHAR source[1024], paths[2][1024];
    HMODULE modules[2] = {NULL, NULL};
    uintptr_t symbols[2][6] = {{0}};
    ULONG_PTR security_cookies[2] = {0, 0};
    ULONG expected_values[2] = {0x13579bdfu, 0x13579bdfu};
    DWORD length = GetModuleFileNameW(NULL, source, 1024);
    if (!length) { relocation_fail(1, GetLastError()); goto done; }
    if (length >= 1024) { relocation_fail(1, ERROR_BUFFER_OVERFLOW); goto done; }
    while (length && source[length - 1] != L'\\' && source[length - 1] != L'/') --length;
    if (!length) { relocation_fail(1, ERROR_INVALID_DATA); goto done; }
    source[length] = 0;
    if (!relocation_path_append(source, 1024, L"lifetime-arm64.dll")) {
        relocation_fail(1, ERROR_BUFFER_OVERFLOW); goto done;
    }
    for (unsigned i = 0; i < 2; ++i) {
        length = GetCurrentDirectoryW(1024, paths[i]);
        if (!length) { relocation_fail(2, GetLastError()); goto done; }
        if (length >= 1024 || !relocation_path_append(paths[i], 1024, L"\\") ||
            !relocation_path_append(paths[i], 1024, names[i])) {
            relocation_fail(2, ERROR_BUFFER_OVERFLOW); goto done;
        }
        /* TRUE refuses existing files. Retain only these owned fixture copies
         * for independent host byte/PE export/relocation binding after unload. */
        if (!CopyFileW(source, paths[i], TRUE)) { relocation_fail(3, GetLastError()); goto done; }
        ++relocation_copies;
        modules[i] = LoadLibraryW(paths[i]);
        if (!modules[i]) { relocation_fail(4, GetLastError()); goto done; }
        ++relocation_loads;
        for (unsigned j = 0; j < 6; ++j) {
            symbols[i][j] = (uintptr_t)GetProcAddress(modules[i], exports[j]);
            if (!symbols[i][j]) { relocation_fail(5, GetLastError()); goto done; }
        }
    }
    if (modules[0] == modules[1]) { relocation_fail(6, ERROR_INVALID_DATA); goto done; }
    for (unsigned round = 0; round < 2; ++round) {
        for (unsigned i = 0; i < 2; ++i) {
            pear_relocation_observation value = {0};
            ULONG desired = (round ? 0x50607080u : 0x10203040u) + i;
            LONG status = ((pear_relocation_probe)symbols[i][0])(&value, desired);
            ++relocation_calls;
            ULONG peer_value = *(volatile ULONG *)symbols[1 - i][2];
            if (!relocation_event(i, round, modules[i], status, &value, peer_value)) {
                relocation_fail(7, GetLastError()); goto done;
            }
            if (status) { relocation_fail(8, ERROR_INVALID_DATA); goto done; }
            /* EAT-derived GetProcAddress targets are independent of DIR64 cells. */
            if (value.code_slot != symbols[i][3] || value.code_address != symbols[i][1] ||
                value.code_pointer != symbols[i][1]) { relocation_fail(9, ERROR_INVALID_DATA); goto done; }
            ++relocation_code_checks;
            if (value.data_slot != symbols[i][4] || value.data_address != symbols[i][2] ||
                value.data_pointer != symbols[i][2]) { relocation_fail(10, ERROR_INVALID_DATA); goto done; }
            ++relocation_data_checks;
            if (value.before != expected_values[i] || value.after != desired ||
                value.call_result != (desired ^ 0xa5c31f27u) || peer_value != expected_values[1 - i]) {
                relocation_fail(11, ERROR_INVALID_DATA); goto done;
            }
            if (value.security_cookie_address != symbols[i][5] ||
                value.security_cookie != *(volatile ULONG_PTR *)symbols[i][5] ||
                !value.security_cookie || value.security_cookie >= ((ULONG_PTR)1 << 48) ||
                value.security_cookie == PEAR_SECURITY_COOKIE_DEFAULT ||
                (round && value.security_cookie != security_cookies[i])) {
                relocation_fail(15, ERROR_INVALID_DATA); goto done;
            }
            security_cookies[i] = value.security_cookie;
            ++relocation_value_checks;
            expected_values[i] = desired;
        }
    }
done:
    for (unsigned i = 0; i < 2; ++i) {
        if (modules[i]) {
            HMODULE observed = NULL;
            MEMORY_BASIC_INFORMATION memory;
            if (!FreeLibrary(modules[i])) { relocation_fail(12, GetLastError()); continue; }
            if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                  GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                  (const WCHAR *)(uintptr_t)modules[i], &observed) || observed) {
                relocation_fail(13, ERROR_INVALID_DATA); continue;
            }
            SIZE_T queried = VirtualQuery(modules[i], &memory, sizeof(memory));
            if (!queried) { relocation_fail(13, GetLastError()); continue; }
            if (queried != sizeof(memory) || memory.State != MEM_RESERVE ||
                (memory.Protect && memory.Protect != PAGE_NOACCESS)) {
                relocation_fail(13, ERROR_INVALID_DATA); continue;
            }
            ++relocation_retirements;
            if (!relocation_retired_event(i, modules[i])) relocation_fail(14, GetLastError());
        }
    }
    return !relocation_error && relocation_copies == 2 && relocation_loads == 2 && relocation_calls == 4 &&
        relocation_code_checks == 4 && relocation_data_checks == 4 && relocation_value_checks == 4 &&
        relocation_retirements == 2;
}

static int exercise(void)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) { record_error(1); return 0; }
    unix_dispatcher *dispatch_export = (unix_dispatcher *)(uintptr_t)GetProcAddress(ntdll, "__wine_unix_call_dispatcher");
    uint64_t *handle_export = (uint64_t *)(uintptr_t)GetProcAddress(ntdll, "__wine_unixlib_handle");
    return_callback = (callback_return)(uintptr_t)GetProcAddress(ntdll, "NtCallbackReturn");
    addref = (addref_dll)(uintptr_t)GetProcAddress(ntdll, "LdrAddRefDll");
    unload = (unload_dll)(uintptr_t)GetProcAddress(ntdll, "LdrUnloadDll");
    load = (load_dll)(uintptr_t)GetProcAddress(ntdll, "LdrLoadDll");
    if (!dispatch_export || !handle_export || !return_callback || !addref || !unload || !load ||
        !*dispatch_export || !*handle_export) {
        record_error(1); return 0;
    }
    dispatcher = *dispatch_export;
    unix_handle = *handle_export;
    expected_teb = current_teb();
    if (!expected_teb || *(uint64_t *)(uintptr_t)(expected_teb + 0x30) != expected_teb) {
        record_error(2); return 0;
    }
    inactive_status = (uint32_t)return_callback(NULL, 0, 0);
    if (inactive_status != PEAR_ABI_NO_CALLBACK || current_teb() != expected_teb) {
        record_error(3); return 0;
    }
    uint64_t peb = *(uint64_t *)(uintptr_t)(expected_teb + 0x60);
    if (!peb) { record_error(2); return 0; }
    if (!relocation_check()) { record_error(10); return 0; }
    if (!rejected_imports_check()) { record_error(9); return 0; }
    for (unsigned operation = 0; operation < 2 && !error_step; ++operation) {
        unsigned count = operation ? 32 : 64;
        for (unsigned sequence = 0; sequence < count && !error_step; ++sequence) {
            pear_abi_request request;
            initialize(&request, operation, sequence);
            uint32_t expected = request.inject_error ? PEAR_ABI_ERROR : 0;
            uint64_t observed = operation ? held_callback_call(&request, sequence) :
                pear_abi_gateway(dispatcher, unix_handle, &request, request.outer_cookie);
            ++gateways;
            bad_registers |= observed >> 32;
            if ((observed >> 32) || (uint32_t)observed != expected || !state_valid(&request, expected)) {
                record_error(5); break;
            }
            ++request.register_checks;
            native_calls += (unsigned)request.native_calls;
            teb_checks += (unsigned)request.teb_matches;
            host_checks += 2;
            if (operation) {
                if (request.callback_count != 1 || request.nested_count != 1 || request.callback_teb_matches != 2 ||
                    request.register_checks != 2 || request.callback_status != expected || request.frame_distinct != 1 ||
                    request.error_count != request.inject_error) { record_error(6); break; }
                ++callbacks;
                ++frame_checks;
                error_returns += (unsigned)request.error_count;
            } else ++roundtrips;
        }
    }
    if (error_step) return 0;
    inactive_status = (uint32_t)return_callback(NULL, 0, 0);
    if (inactive_status != PEAR_ABI_NO_CALLBACK || current_teb() != expected_teb) { record_error(7); return 0; }
    return roundtrips == 64 && callbacks == 32 && nested_calls == 32 && error_returns == 16 &&
        gateways == 128 && native_calls == 128 && teb_checks == 128 && frame_checks == 32 && host_checks == 256 &&
        !lifetime_error && loads == 32 && callback_unload_attempts == 32 && held_mapping_checks == 32 &&
        callback_holds == 32 && continuation_holds == 32 && callback_releases == 32 &&
        continuation_releases == 32 && retirements == 32 && compatible_reuses == 31 &&
        rejected_imports == 2 && failed_load_cleanup_checks == 2;
}

static char output[1024];
static unsigned output_length;
static void text(const char *s) { while (*s && output_length < sizeof(output) - 1) output[output_length++] = *s++; }
static void number(uint64_t value)
{
    char reverse[21]; unsigned length = 0;
    do { reverse[length++] = '0' + value % 10; value /= 10; } while (value);
    while (length) output[output_length++] = reverse[--length];
}
static int flush(void)
{
    DWORD written = 0;
    int valid = WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output, output_length, &written, NULL);
    if (valid && written != output_length) { SetLastError(ERROR_WRITE_FAULT); valid = 0; }
    output_length = 0;
    return valid;
}
static int lifetime_event(unsigned round, const char *event, HMODULE module, kernel_callback callback)
{
    text("{\"version\":1,\"record_kind\":\"pear_lifetime_event\",\"round\":"); number(round);
    text(",\"event\":\""); text(event); text("\",\"module_base\":"); number((uintptr_t)module);
    text(",\"callback_address\":"); number((uintptr_t)callback); text("}\n");
    return flush();
}
static int rejection_event(const char *event, uint32_t status, int handle_null, int provider_absent)
{
    text("{\"version\":1,\"record_kind\":\"pear_import_rejection\",\"event\":\""); text(event);
    text("\",\"status\":"); number(status);
    text(",\"handle_null\":"); text(handle_null ? "true" : "false");
    text(",\"provider_absent\":"); text(provider_absent ? "true" : "false"); text("}\n");
    return flush();
}
static int relocation_event(unsigned copy, unsigned round, HMODULE module, LONG status,
                            const pear_relocation_observation *value, ULONG peer_value)
{
    text("{\"version\":1,\"record_kind\":\"pear_relocation_event\",\"event\":\"probe\",\"copy\":"); number(copy);
    text(",\"round\":"); number(round); text(",\"module_base\":"); number((uintptr_t)module);
    text(",\"status\":"); number((uint32_t)status);
    text(",\"code_slot\":"); number(value->code_slot);
    text(",\"code_pointer\":"); number(value->code_pointer);
    text(",\"code_address\":"); number(value->code_address);
    text(",\"data_slot\":"); number(value->data_slot);
    text(",\"data_pointer\":"); number(value->data_pointer);
    text(",\"data_address\":"); number(value->data_address);
    text(",\"before\":"); number(value->before); text(",\"after\":"); number(value->after);
    text(",\"call_result\":"); number(value->call_result); text(",\"peer_value\":"); number(peer_value);
    text(",\"security_cookie_address\":"); number(value->security_cookie_address);
    text(",\"security_cookie\":"); number(value->security_cookie);
    text("}\n"); return flush();
}
static int relocation_retired_event(unsigned copy, HMODULE module)
{
    text("{\"version\":1,\"record_kind\":\"pear_relocation_event\",\"event\":\"retired\",\"copy\":"); number(copy);
    text(",\"module_base\":"); number((uintptr_t)module); text("}\n"); return flush();
}
static int relocation_report(void)
{
    int passed = !relocation_error && relocation_copies == 2 && relocation_loads == 2 && relocation_calls == 4 &&
        relocation_code_checks == 4 && relocation_data_checks == 4 && relocation_value_checks == 4 && relocation_retirements == 2;
    text("{\"version\":1,\"record_kind\":\"pear_relocation_result\",\"passed\":"); text(passed ? "true" : "false");
    text(",\"error_step\":"); number(relocation_error); text(",\"win32_error\":"); number(relocation_win32_error);
    text(",\"copies\":"); number(relocation_copies); text(",\"loads\":"); number(relocation_loads);
    text(",\"probe_calls\":"); number(relocation_calls); text(",\"code_pointer_checks\":"); number(relocation_code_checks);
    text(",\"data_pointer_checks\":"); number(relocation_data_checks); text(",\"value_checks\":"); number(relocation_value_checks);
    text(",\"retirements\":"); number(relocation_retirements); text("}\n"); return flush();
}
static int lifetime_report(int valid)
{
    text("{\"version\":1,\"record_kind\":\"pear_lifetime_result\",\"passed\":"); text(valid ? "true" : "false");
    text(",\"error_step\":"); number(lifetime_error);
    text(",\"loads\":"); number(loads);
    text(",\"callback_unload_attempts\":"); number(callback_unload_attempts);
    text(",\"held_mapping_checks\":"); number(held_mapping_checks);
    text(",\"callback_holds\":"); number(callback_holds);
    text(",\"continuation_holds\":"); number(continuation_holds);
    text(",\"callback_releases\":"); number(callback_releases);
    text(",\"continuation_releases\":"); number(continuation_releases);
    text(",\"retirements\":"); number(retirements);
    text(",\"compatible_reuses\":"); number(compatible_reuses);
    text(",\"named_import_status\":"); number(named_import_status);
    text(",\"ordinal_import_status\":"); number(ordinal_import_status);
    text(",\"rejected_imports\":"); number(rejected_imports);
    text(",\"failed_load_cleanup_checks\":"); number(failed_load_cleanup_checks); text("}\n");
    return flush();
}
static int report(int valid)
{
    text("{\"version\":1,\"record_kind\":\"pear_abi_result\",\"passed\":"); text(valid ? "true" : "false");
    text(",\"error_step\":"); number(error_step);
    text(",\"roundtrips\":"); number(roundtrips);
    text(",\"callbacks\":"); number(callbacks);
    text(",\"nested_calls\":"); number(nested_calls);
    text(",\"error_returns\":"); number(error_returns);
    text(",\"gateway_calls\":"); number(gateways);
    text(",\"native_calls\":"); number(native_calls);
    text(",\"teb_checks\":"); number(teb_checks);
    text(",\"frame_checks\":"); number(frame_checks);
    text(",\"host_checks\":"); number(host_checks);
    text(",\"register_failure_mask\":"); number(bad_registers);
    text(",\"inactive_callback_status\":"); number(inactive_status);
    text("}\n");
    return flush();
}

void WINAPI mainCRTStartup(void)
{
    int valid = exercise();
    if (!relocation_report() || !lifetime_report(valid) || !report(valid)) ExitProcess(90);
    ExitProcess(valid ? 0 : 92);
}
