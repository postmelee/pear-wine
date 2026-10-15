/* Original Pear private Wine/FEX memory bridge. MIT-licensed.
 * This is an internal paired ABI, not a public Windows API. */
#ifndef __WINE_PEAR_FEX_MEMORY_H
#define __WINE_PEAR_FEX_MEMORY_H
#include <stdint.h>
#include <stddef.h>

#define PEAR_FEX_MEMORY_VERSION 3u
#define PEAR_FEX_MEMORY_OBSERVATION_SLOTS 1024u
#define PEAR_FEX_MEMORY_RECORD_BYTES 128u
#define PEAR_FEX_MEMORY_UNIX_INDEX 10u
#define PEAR_FEX_MEMORY_PAGE_BYTES UINT64_C(4096)
#define PEAR_FEX_MEMORY_SHARED_BYTES UINT64_C(536870912)
#define PEAR_FEX_MEMORY_DISPATCHER_BYTES UINT64_C(1048576)
#define PEAR_FEX_MEMORY_SEPARATOR_BYTES UINT64_C(65536)
#define PEAR_FEX_MEMORY_MAX_EXTENTS 128u
#define PEAR_FEX_MEMORY_MAX_EXECUTORS 64u
#define PEAR_FEX_MEMORY_MAX_CONTINUATIONS 128u
#define PEAR_FEX_MEMORY_MAX_DESCRIPTORS 64u
#define PEAR_FEX_MEMORY_METADATA_BYTES 262144u

enum pear_fex_memory_opcode {
    PEAR_FEX_RESERVE = 1, PEAR_FEX_BEGIN_WRITE = 2, PEAR_FEX_PUBLISH = 3,
    PEAR_FEX_ABORT_WRITE = 4, PEAR_FEX_RETIRE = 5, PEAR_FEX_QUERY = 6,
    PEAR_FEX_EXECUTOR_REGISTER = 7, PEAR_FEX_EXECUTOR_ENTRY = 8,
    PEAR_FEX_EXECUTOR_EXIT = 9, PEAR_FEX_CONTINUATION_PIN = 10,
    PEAR_FEX_CONTINUATION_UNPIN = 11, PEAR_FEX_EXECUTOR_UNREGISTER = 12,
    PEAR_FEX_EXECUTOR_HANDOFF = 13, PEAR_FEX_EXECUTOR_RESUME = 14, PEAR_FEX_OBSERVE_METADATA = 15
};
enum pear_fex_memory_status {
    PEAR_FEX_OK = 0, PEAR_FEX_INVALID_REQUEST = 1, PEAR_FEX_VERSION_MISMATCH = 2,
    PEAR_FEX_UNAVAILABLE = 3, PEAR_FEX_CAPACITY = 4,
    PEAR_FEX_QUIESCENCE_TIMEOUT = 5, PEAR_FEX_STALE_IDENTITY = 6,
    PEAR_FEX_NATIVE_FAILURE = 7, PEAR_FEX_QUARANTINED = 8
};
enum pear_fex_memory_error_domain {
    PEAR_FEX_ERROR_NONE = 0, PEAR_FEX_ERROR_ERRNO = 1,
    PEAR_FEX_ERROR_NTSTATUS = 2, PEAR_FEX_ERROR_MACH = 3
};
enum pear_fex_memory_class {
    PEAR_FEX_CLASS_NONE = 0, PEAR_FEX_CLASS_SHARED = 1,
    PEAR_FEX_CLASS_DISPATCHER = 2
};
enum pear_fex_memory_role {
    PEAR_FEX_ROLE_NONE = 0, PEAR_FEX_ROLE_ARM64EC = 1,
    PEAR_FEX_ROLE_NATIVE = 2
};
enum pear_fex_memory_state {
    PEAR_FEX_STATE_NONE = 0, PEAR_FEX_RESERVED_NONE = 1,
    PEAR_FEX_WRITING_RW_NX = 2, PEAR_FEX_PUBLISHED_RX = 3,
    PEAR_FEX_RETIRING = 4, PEAR_FEX_RETIRED_NONE = 5
};
enum pear_fex_memory_protection {
    PEAR_FEX_PROTECTION_NONE = 0, PEAR_FEX_PROTECTION_RW_NX = 1,
    PEAR_FEX_PROTECTION_RX = 2
};
enum pear_fex_memory_executor_state {
    PEAR_FEX_EXECUTOR_NONE = 0, PEAR_FEX_NATIVE_IDLE = 1,
    PEAR_FEX_MANAGED_ACTIVE = 2, PEAR_FEX_NATIVE_PINNED = 3,
    PEAR_FEX_PARKED = 4, PEAR_FEX_UNREGISTERED = 5
};
enum pear_fex_memory_capability {
    PEAR_FEX_SINGLE_MAP_JIT = 1u, PEAR_FEX_OBSERVED_4K = 2u,
    PEAR_FEX_GLOBAL_GATE = 4u, PEAR_FEX_CHECKED_EC_BITMAP = 8u,
    PEAR_FEX_CAPABILITIES_MASK = 15u
};

struct pear_fex_memory_request {
    uint32_t version, size, opcode, flags;
    uint64_t owner_pid, allocation_id, generation, write_epoch;
    uint64_t executor_id, continuation_id, extent_offset, extent_size;
    uint64_t operation_offset, operation_size;
    uint32_t allocation_class, ec_role, expected_state, reserved0;
    uint64_t reserved1, reserved2;
};
struct pear_fex_memory_response {
    uint32_t version, size, status, flags, native_error_domain;
    int32_t native_error_code;
    uint32_t allocation_class, ec_role;
    uint64_t owner_pid, allocation_id, generation, write_epoch;
    uint64_t executor_id, continuation_id, extent_offset, extent_size;
    uint64_t private_write_base;
    uint32_t lifecycle_state, effective_protection;
    uint64_t capabilities, reserved0;
};
/* Read-only opcode 15 response; no field grants executable access. */
struct pear_fex_memory_metadata {
    uint32_t version, size, status, reserved0, native_error_domain;
    int32_t native_error_code;
    uint64_t owner_pid;
    uint64_t mapping_bytes;
    uint64_t baseline_mapping_bytes;
    uint64_t page_bytes;
    uint64_t leaf_coverage_bytes;
    uint64_t leaf_backing_bytes;
    uint64_t baseline_leaves;
    uint64_t additional_leaves;
    uint64_t view_block_bytes;
    uint64_t view_record_bytes;
    uint64_t available_view_slots;
    uint64_t fixed_native_bytes;
    uint64_t reserved1;
};
struct pear_fex_memory_call {
    struct pear_fex_memory_request request;
    struct pear_fex_memory_response response;
};

#ifdef __cplusplus
#define PEAR_FEX_ASSERT(expr, text) static_assert(expr, text)
#define PEAR_FEX_ALIGNOF(type) alignof(type)
#else
#define PEAR_FEX_ASSERT(expr, text) _Static_assert(expr, text)
#define PEAR_FEX_ALIGNOF(type) _Alignof(type)
#endif
PEAR_FEX_ASSERT(sizeof(struct pear_fex_memory_request) == 128, "Pear request size");
PEAR_FEX_ASSERT(sizeof(struct pear_fex_memory_response) == 128, "Pear response size");
PEAR_FEX_ASSERT(sizeof(struct pear_fex_memory_metadata) == 128, "Pear metadata size");
PEAR_FEX_ASSERT(sizeof(struct pear_fex_memory_call) == 256, "Pear private transport size");
PEAR_FEX_ASSERT(PEAR_FEX_ALIGNOF(struct pear_fex_memory_request) == 8, "Pear request alignment");
PEAR_FEX_ASSERT(PEAR_FEX_ALIGNOF(struct pear_fex_memory_response) == 8, "Pear response alignment");
#define PEAR_FEX_FIELD(type, name, offset) \
    PEAR_FEX_ASSERT(offsetof(struct type, name) == offset, "Pear " #name " offset")
PEAR_FEX_FIELD(pear_fex_memory_request, version, 0);
PEAR_FEX_FIELD(pear_fex_memory_request, size, 4);
PEAR_FEX_FIELD(pear_fex_memory_request, opcode, 8);
PEAR_FEX_FIELD(pear_fex_memory_request, flags, 12);
PEAR_FEX_FIELD(pear_fex_memory_request, owner_pid, 16);
PEAR_FEX_FIELD(pear_fex_memory_request, allocation_id, 24);
PEAR_FEX_FIELD(pear_fex_memory_request, generation, 32);
PEAR_FEX_FIELD(pear_fex_memory_request, write_epoch, 40);
PEAR_FEX_FIELD(pear_fex_memory_request, executor_id, 48);
PEAR_FEX_FIELD(pear_fex_memory_request, continuation_id, 56);
PEAR_FEX_FIELD(pear_fex_memory_request, extent_offset, 64);
PEAR_FEX_FIELD(pear_fex_memory_request, extent_size, 72);
PEAR_FEX_FIELD(pear_fex_memory_request, operation_offset, 80);
PEAR_FEX_FIELD(pear_fex_memory_request, operation_size, 88);
PEAR_FEX_FIELD(pear_fex_memory_request, allocation_class, 96);
PEAR_FEX_FIELD(pear_fex_memory_request, ec_role, 100);
PEAR_FEX_FIELD(pear_fex_memory_request, expected_state, 104);
PEAR_FEX_FIELD(pear_fex_memory_request, reserved0, 108);
PEAR_FEX_FIELD(pear_fex_memory_request, reserved1, 112);
PEAR_FEX_FIELD(pear_fex_memory_request, reserved2, 120);
PEAR_FEX_FIELD(pear_fex_memory_response, version, 0);
PEAR_FEX_FIELD(pear_fex_memory_response, size, 4);
PEAR_FEX_FIELD(pear_fex_memory_response, status, 8);
PEAR_FEX_FIELD(pear_fex_memory_response, flags, 12);
PEAR_FEX_FIELD(pear_fex_memory_response, native_error_domain, 16);
PEAR_FEX_FIELD(pear_fex_memory_response, native_error_code, 20);
PEAR_FEX_FIELD(pear_fex_memory_response, allocation_class, 24);
PEAR_FEX_FIELD(pear_fex_memory_response, ec_role, 28);
PEAR_FEX_FIELD(pear_fex_memory_response, owner_pid, 32);
PEAR_FEX_FIELD(pear_fex_memory_response, allocation_id, 40);
PEAR_FEX_FIELD(pear_fex_memory_response, generation, 48);
PEAR_FEX_FIELD(pear_fex_memory_response, write_epoch, 56);
PEAR_FEX_FIELD(pear_fex_memory_response, executor_id, 64);
PEAR_FEX_FIELD(pear_fex_memory_response, continuation_id, 72);
PEAR_FEX_FIELD(pear_fex_memory_response, extent_offset, 80);
PEAR_FEX_FIELD(pear_fex_memory_response, extent_size, 88);
PEAR_FEX_FIELD(pear_fex_memory_response, private_write_base, 96);
PEAR_FEX_FIELD(pear_fex_memory_response, lifecycle_state, 104);
PEAR_FEX_FIELD(pear_fex_memory_response, effective_protection, 108);
PEAR_FEX_FIELD(pear_fex_memory_response, capabilities, 112);
PEAR_FEX_FIELD(pear_fex_memory_response, reserved0, 120);
PEAR_FEX_FIELD(pear_fex_memory_metadata, owner_pid, 24);
PEAR_FEX_FIELD(pear_fex_memory_metadata, mapping_bytes, 32);
PEAR_FEX_FIELD(pear_fex_memory_metadata, baseline_mapping_bytes, 40);
PEAR_FEX_FIELD(pear_fex_memory_metadata, page_bytes, 48);
PEAR_FEX_FIELD(pear_fex_memory_metadata, leaf_coverage_bytes, 56);
PEAR_FEX_FIELD(pear_fex_memory_metadata, leaf_backing_bytes, 64);
PEAR_FEX_FIELD(pear_fex_memory_metadata, baseline_leaves, 72);
PEAR_FEX_FIELD(pear_fex_memory_metadata, additional_leaves, 80);
PEAR_FEX_FIELD(pear_fex_memory_metadata, view_block_bytes, 88);
PEAR_FEX_FIELD(pear_fex_memory_metadata, view_record_bytes, 96);
PEAR_FEX_FIELD(pear_fex_memory_metadata, available_view_slots, 104);
PEAR_FEX_FIELD(pear_fex_memory_metadata, fixed_native_bytes, 112);
PEAR_FEX_FIELD(pear_fex_memory_metadata, reserved1, 120);
#undef PEAR_FEX_FIELD
#undef PEAR_FEX_ALIGNOF
#undef PEAR_FEX_ASSERT
#endif
