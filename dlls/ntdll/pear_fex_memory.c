/* Original Pear private PE owner thunk, MIT-licensed. */
#include <stdarg.h>
#include <string.h>
#include "ntstatus.h"
#include "windef.h"
#include "winternl.h"
#include "wine/pear_fex_memory.h"
#include "unixlib.h"
#include "ntdll_misc.h"

/* Bound by Wine's selected translator load, before ProcessInit. Pinning keeps
 * return-address ownership stable for the process lifetime. This is private
 * paired-runtime admission, not an isolation boundary against in-process code. */
static void *memory_translator_module;
NTSTATUS pear_fex_bind_module(HMODULE module)
{
#ifdef __arm64ec__
    static const char *const required[] = {"ProcessInit", "ThreadInit", "BeginSimulation",
        "ExitToX64", "DispatchJump", "RetToEntryThunk", "ResetToConsistentState"};
    const IMAGE_ARM64EC_METADATA *metadata;
    void *owner;
    unsigned int i;
    NTSTATUS status;
    if (!module || (memory_translator_module && memory_translator_module != module))
        return STATUS_INVALID_PARAMETER;
    metadata = arm64ec_get_module_metadata(module);
    if (!metadata || (metadata->Version != 1 && metadata->Version != 2) || !metadata->CodeMapCount)
        return STATUS_INVALID_IMAGE_FORMAT;
    for (i = 0; i < ARRAY_SIZE(required); ++i)
    {
        void *entry = RtlFindExportedRoutineByName(module, required[i]);
        if (!entry || !RtlPcToFileHeader(entry, &owner) || owner != module)
            return STATUS_PROCEDURE_NOT_FOUND;
    }
    if ((status = LdrAddRefDll(1, module))) return status;
    memory_translator_module = module;
    return STATUS_SUCCESS;
#else
    (void)module;
    return STATUS_NOT_SUPPORTED;
#endif
}
static BOOL memory_admitted_caller(void *return_address)
{
    MEMORY_BASIC_INFORMATION info;
    SIZE_T actual = 0;
    /* The translator is already pinned by pear_fex_bind_module. Memory
     * callbacks may run under the process heap lock, so they must not acquire
     * the loader lock through RtlPcToFileHeader. Query Wine's existing image
     * allocation identity instead; no new module or caller is admitted. */
    if (!memory_translator_module || !return_address ||
        NtQueryVirtualMemory(NtCurrentProcess(), return_address, MemoryBasicInformation,
                             &info, sizeof(info), &actual)) return FALSE;
    return actual == sizeof(info) && info.State == MEM_COMMIT && info.Type == MEM_IMAGE &&
           info.AllocationBase == memory_translator_module;
}

static uint32_t memory_reply_failure(struct pear_fex_memory_response *response,
                                     uint32_t status, NTSTATUS native_status)
{
    memset(response, 0, sizeof(*response));
    response->version = PEAR_FEX_MEMORY_VERSION; response->size = sizeof(*response);
    response->status = status;
    if (native_status) { response->native_error_domain = PEAR_FEX_ERROR_NTSTATUS;
                         response->native_error_code = (int32_t)native_status; }
    return status;
}
static NTSTATUS memory_record_access(const void *pointer, SIZE_T size, BOOL writable)
{
    ULONG_PTR cursor = (ULONG_PTR)pointer, end;
    if (!pointer || cursor > ~(ULONG_PTR)0-size) return STATUS_INVALID_PARAMETER;
    end = cursor+size;
    while (cursor < end)
    {
        MEMORY_BASIC_INFORMATION info;
        SIZE_T actual;
        NTSTATUS status = NtQueryVirtualMemory(NtCurrentProcess(), (const void *)cursor,
                                               MemoryBasicInformation, &info, sizeof(info), &actual);
        ULONG flags;
        if (status) return status;
        if (actual != sizeof(info) || (ULONG_PTR)info.BaseAddress > cursor || !info.RegionSize ||
            (ULONG_PTR)info.BaseAddress > ~(ULONG_PTR)0-info.RegionSize ||
            (ULONG_PTR)info.BaseAddress+info.RegionSize <= cursor || info.State != MEM_COMMIT ||
            info.Protect & (PAGE_GUARD|PAGE_NOACCESS)) return STATUS_ACCESS_DENIED;
        flags = info.Protect & 0xff;
        if (writable && flags != PAGE_READWRITE && flags != PAGE_WRITECOPY &&
            flags != PAGE_EXECUTE_READWRITE && flags != PAGE_EXECUTE_WRITECOPY) return STATUS_ACCESS_DENIED;
        if (!writable && flags != PAGE_READONLY && flags != PAGE_READWRITE && flags != PAGE_WRITECOPY &&
            flags != PAGE_EXECUTE_READ && flags != PAGE_EXECUTE_READWRITE && flags != PAGE_EXECUTE_WRITECOPY)
            return STATUS_ACCESS_DENIED;
        cursor = min((ULONG_PTR)info.BaseAddress+info.RegionSize, end);
    }
    return STATUS_SUCCESS;
}
#ifdef PEAR_FEX_MEMORY_FINITE_FIXTURE
static BOOL memory_fixture_nonce(void)
{
    UNICODE_STRING name, value;
    WCHAR text[33];
    unsigned int i;
    RtlInitUnicodeString(&name, L"PEAR_FEX_MEMORY_FIXTURE_NONCE");
    value.Buffer = text; value.Length = 0; value.MaximumLength = sizeof(text);
    if (RtlQueryEnvironmentVariable_U(NULL, &name, &value) || value.Length != 32*sizeof(WCHAR)) return FALSE;
    for (i = 0; i < 32; ++i)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return FALSE;
    return TRUE;
}
#endif

uint32_t WINAPI __wine_pear_fex_memory(const struct pear_fex_memory_request *request,
                                      struct pear_fex_memory_response *response)
{
    struct pear_fex_memory_call call;
    NTSTATUS status;
    void *caller = NULL;
    /* The fixed response must be writable before reporting any failure. This
     * bounded query is not a general pointer, permission or source-origin grant. */
    if ((status = memory_record_access(response, sizeof(*response), TRUE))) return PEAR_FEX_INVALID_REQUEST;
    if ((status = memory_record_access(request, sizeof(*request), FALSE)))
        return memory_reply_failure(response, PEAR_FEX_INVALID_REQUEST, status);
    memcpy(&call.request, request, sizeof(call.request));
    memset(&call.response, 0, sizeof(call.response));
    /* EC calls are admitted only from the translator selected and pinned by
     * Wine. The original native fixture remains an independent finite path. */
    if (!memory_admitted_caller(__builtin_return_address(0)))
    {
#ifdef PEAR_FEX_MEMORY_FINITE_FIXTURE
        if (!memory_fixture_nonce() ||
            !RtlPcToFileHeader(__builtin_return_address(0), &caller) ||
            caller != NtCurrentTeb()->Peb->ImageBaseAddress ||
            call.request.ec_role == PEAR_FEX_ROLE_ARM64EC)
            return memory_reply_failure(response, PEAR_FEX_UNAVAILABLE, 0);
#else
        (void)caller;
        return memory_reply_failure(response, PEAR_FEX_UNAVAILABLE, 0);
#endif
    }
    status = WINE_UNIX_CALL(unix_pear_fex_memory, &call);
    if (status && call.response.status == PEAR_FEX_OK)
        memory_reply_failure(&call.response, PEAR_FEX_NATIVE_FAILURE, status);
    if (call.response.version != PEAR_FEX_MEMORY_VERSION || call.response.size != sizeof(call.response) ||
        call.response.status > PEAR_FEX_QUARANTINED)
        return memory_reply_failure(response, PEAR_FEX_VERSION_MISMATCH, 0);
    memcpy(response, &call.response, sizeof(*response));
    return call.response.status;
}
