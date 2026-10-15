/* Original Pear Stage 3 fixture, SPDX-License-Identifier: MIT.
 * The shared protocol is included by abi_pe.c; the native body is copied
 * verbatim into Wine through an attributable patch. It is not a new FFI path:
 * Wine's Unix dispatcher calls this entry, which uses KeUserModeCallback.
 */
#if 0
#pragma makedep unix
#endif
#ifndef PEAR_ABI_PROTOCOL_ONLY
#include "config.h"
#endif
#include <stdint.h>
#include <stddef.h>

#define PEAR_ABI_MAGIC UINT64_C(0x5045415241424933)
#define PEAR_ABI_OUTER UINT64_C(0x1122334400000000)
#define PEAR_ABI_INNER UINT64_C(0x5566778800000000)
#define PEAR_ABI_LEAF UINT64_C(0x3344556600000000)
#define PEAR_ABI_ERROR UINT32_C(0xc0000001)
#define PEAR_ABI_NO_CALLBACK UINT32_C(0xc0000258)
#define PEAR_ABI_INDEX 8

typedef struct pear_abi_request {
    uint64_t magic, version, operation, sequence;
    uint64_t guest_teb, outer_cookie, inner_cookie, inject_error;
    uint64_t native_calls, callback_count, nested_count, error_count;
    uint64_t host_entry, host_exit, teb_matches, callback_teb_matches;
    uint64_t callback_status, bridge_status, frame_distinct, register_checks;
    uint64_t native_frame, parent_frame;
} pear_abi_request;

typedef struct pear_abi_callback {
    uint64_t magic, request, sequence, guest_teb, cookie, inject_error;
} pear_abi_callback;

typedef struct pear_abi_reply {
    uint64_t magic, cookie, value, status;
} pear_abi_reply;

_Static_assert(sizeof(pear_abi_request) == 176, "Fixed guest/native protocol");
_Static_assert(sizeof(pear_abi_callback) == 48, "Fixed callback protocol");
_Static_assert(sizeof(pear_abi_reply) == 32, "Fixed callback return protocol");
_Static_assert(offsetof(pear_abi_request, guest_teb) == 32, "Guest TEB protocol offset");
_Static_assert(offsetof(pear_abi_request, register_checks) == 152, "Register protocol offset");

#ifndef PEAR_ABI_PROTOCOL_ONLY
#include <stdlib.h>
#include <string.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "unix_private.h"

#if defined(__APPLE__) && defined(__aarch64__)
extern unsigned char (*pear_x18_getter)(void);

static int fixture_enabled(void)
{
    const char *enabled = getenv("PEAR_WINE_ABI_FIXTURE");
    const char *nonce = getenv("PEAR_BOOTSTRAP_NONCE");
    if (!enabled || strcmp(enabled, "1") || !nonce || strlen(nonce) != 32) return 0;
    for (unsigned i = 0; i < 32; ++i)
        if (!((nonce[i] >= '0' && nonce[i] <= '9') || (nonce[i] >= 'a' && nonce[i] <= 'f'))) return 0;
    return 1;
}
#endif

NTSTATUS pear_abi_unix_entry(void *opaque)
{
#if defined(__APPLE__) && defined(__aarch64__)
    pear_abi_request *request = opaque;
    if (!fixture_enabled()) return STATUS_NOT_SUPPORTED;
    if (!request || request->magic != PEAR_ABI_MAGIC || request->version != 1 ||
        request->operation > 2 || request->sequence >= (request->operation ? 32 : 64) ||
        request->inject_error != (request->operation == 1 && request->sequence >= 16) ||
        request->outer_cookie != (request->operation == 2 ? PEAR_ABI_INNER : PEAR_ABI_OUTER) + request->sequence ||
        request->inner_cookie != (request->operation == 2 ? PEAR_ABI_LEAF : PEAR_ABI_INNER) + request->sequence ||
        request->native_frame || request->native_calls || request->callback_count || request->nested_count || request->error_count ||
        !pear_x18_getter) return STATUS_INVALID_PARAMETER;
    request->host_entry = pear_x18_getter();
    if (request->host_entry) return STATUS_INVALID_PARAMETER;
    request->native_calls = 1;
    /* Pinned Wine signal_arm64.c defines prev_frame at offset 0x110. These
     * private addresses never leave the fixture protocol in public output. */
    request->native_frame = (uintptr_t)get_syscall_frame(get_thread_data());
    if (!request->native_frame ||
        (request->operation == 2 && (!request->parent_frame || request->native_frame == request->parent_frame ||
          *(const uintptr_t *)(uintptr_t)(request->native_frame + 0x110) != request->parent_frame)) ||
        (request->operation != 2 && request->parent_frame)) return STATUS_INVALID_PARAMETER;
    request->teb_matches = request->guest_teb == (uintptr_t)get_thread_data()->teb;
    if (!request->teb_matches) return STATUS_INVALID_PARAMETER;
    NTSTATUS result = STATUS_SUCCESS;
    if (request->operation == 1) {
        pear_abi_callback arguments = {PEAR_ABI_MAGIC, (uintptr_t)request, request->sequence,
            request->guest_teb, request->inner_cookie, request->inject_error};
        void *returned = NULL;
        ULONG length = 0;
        result = KeUserModeCallback(0, &arguments, sizeof(arguments), &returned, &length);
        request->callback_status = (uint32_t)result;
        /* Getter verification precedes any normal host work after the callback.
         * The assembly boundary owns mode changes, not this test bridge. */
        request->host_exit = pear_x18_getter();
        if (request->host_exit ||
            (uintptr_t)get_syscall_frame(get_thread_data()) != request->native_frame) return STATUS_INVALID_PARAMETER;
        NTSTATUS expected = request->inject_error ? (NTSTATUS)PEAR_ABI_ERROR : STATUS_SUCCESS;
        if (result != expected || !returned || length != sizeof(pear_abi_reply)) return STATUS_INVALID_PARAMETER;
        const pear_abi_reply *reply = returned;
        if (reply->magic != PEAR_ABI_MAGIC || reply->cookie != request->inner_cookie ||
            reply->value != (request->inner_cookie ^ UINT64_C(0x5a5a)) || reply->status != (uint32_t)expected ||
            request->callback_count != 1 || request->nested_count != 1 || request->frame_distinct != 1 ||
            request->callback_teb_matches != 2 || request->native_calls != 2 || request->teb_matches != 2 ||
            request->register_checks != 1) return STATUS_INVALID_PARAMETER;
        request->error_count = request->inject_error;
    } else request->host_exit = pear_x18_getter();
    if (request->host_exit) return STATUS_INVALID_PARAMETER;
    request->bridge_status = (uint32_t)result;
    return result;
#else
    (void)opaque;
    return STATUS_NOT_SUPPORTED;
#endif
}
#endif
