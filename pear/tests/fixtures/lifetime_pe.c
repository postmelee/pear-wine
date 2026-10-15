/* Original Pear Stage 3 fixture, SPDX-License-Identifier: MIT.
 * A real PE DLL consumes its initial caller reference from inside a kernel
 * callback. The outer PE wrapper owns a separate LdrAddRefDll reference until
 * the native bridge has consumed the direct NtCallbackReturn stack payload.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stddef.h>
#include "lifetime_pe.h"

/* The linker recognizes this original, minimal PE64 load-config prefix.
 * Its SecurityCookie field requires a real DIR64 relocation. Only Wine's
 * normal loader initializes this ordinary-data destination; the fixture reads it. */
__declspec(dllexport) volatile ULONG_PTR PearSecurityCookie = PEAR_SECURITY_COOKIE_DEFAULT;
typedef struct pear_load_config {
    DWORD Size;
    unsigned char reserved[84];
    ULONG_PTR SecurityCookie;
} pear_load_config;
_Static_assert(sizeof(pear_load_config) == 96, "PE64 load-config prefix size");
_Static_assert(offsetof(pear_load_config, SecurityCookie) == 88, "PE64 cookie field offset");
const pear_load_config _load_config_used = {96, {0}, (ULONG_PTR)&PearSecurityCookie};

/* These exported volatile pointer cells require actual PE DIR64 fixups.
 * Independent export RVAs let the host bind their file and runtime values. */
__declspec(dllexport) volatile ULONG PearRelocationData = 0x13579bdfu;
__declspec(dllexport) ULONG WINAPI PearRelocationCode(ULONG value) { return value ^ 0xa5c31f27u; }
__declspec(dllexport) ULONG (WINAPI * volatile PearRelocationCodePointer)(ULONG) = PearRelocationCode;
__declspec(dllexport) volatile ULONG * volatile PearRelocationDataPointer = &PearRelocationData;

/* A test-only exported, non-inlined boundary keeps these inputs opaque. The
 * fresh volatile loads cannot inherit the caller's earlier equality checks.
 * Record exactly the pointers used for both memory access and the code call. */
__declspec(dllexport) __declspec(noinline) void WINAPI PearRelocationAccess(
    pear_relocation_observation *out, ULONG value,
    ULONG (WINAPI * volatile *code_cell)(ULONG), volatile ULONG * volatile *data_cell)
{
    ULONG (WINAPI *code)(ULONG) = *code_cell;
    volatile ULONG *data = *data_cell;
    out->code_pointer = (ULONG_PTR)code;
    out->data_pointer = (ULONG_PTR)data;
    out->before = *data;
    *data = value;
    out->after = *data;
    out->call_result = code(value);
}

__declspec(dllexport) LONG WINAPI PearRelocationProbe(pear_relocation_observation *out, ULONG value)
{
    if (!out) return (LONG)0xc000000d;
    ULONG (WINAPI *code)(ULONG) = PearRelocationCodePointer;
    volatile ULONG *data = PearRelocationDataPointer;
    out->code_slot = (ULONG_PTR)&PearRelocationCodePointer;
    out->code_pointer = (ULONG_PTR)code;
    out->code_address = (ULONG_PTR)PearRelocationCode;
    out->data_slot = (ULONG_PTR)&PearRelocationDataPointer;
    out->data_pointer = (ULONG_PTR)data;
    out->data_address = (ULONG_PTR)&PearRelocationData;
    if (code != PearRelocationCode || data != &PearRelocationData) return (LONG)0xc0000001;
    PearRelocationAccess(out, value, &PearRelocationCodePointer, &PearRelocationDataPointer);
    out->security_cookie_address = (ULONG_PTR)&PearSecurityCookie;
    out->security_cookie = PearSecurityCookie;
    return 0;
}

static pear_lifetime_control *control;

__declspec(dllexport) LONG WINAPI PearConfigure(pear_lifetime_control *value)
{
    if (!value || !value->module || !value->delegate || value->unload_attempts ||
        value->held_mapping_checks || value->error_step || control) return (LONG)0xc000000d;
    control = value;
    return 0;
}

__declspec(dllexport) LONG WINAPI PearCallback(void *arguments, ULONG length)
{
    pear_lifetime_control *state = control;
    HMODULE observed = NULL;
    if (!state || state->unload_attempts || !FreeLibrary(state->module)) ExitProcess(96);
    ++state->unload_attempts;
    /* The same DLL code is executing after its caller reference was consumed.
     * Query without changing references so this does not mask a missing hold. */
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (const WCHAR *)(ULONG_PTR)PearCallback, &observed) || observed != state->module) {
        state->error_step = 1;
        ExitProcess(97);
    }
    ++state->held_mapping_checks;
    return state->delegate(arguments, length);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
