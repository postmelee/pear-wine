/* Original Pear bounded code-owner protocol. MIT-licensed.
 * Never called from a raw signal handler. All waiters are compiled native
 * gates outside MAP_JIT; the source caller owns saved-context reconstruction. */
#if 0
#pragma makedep unix
#endif
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "pear_fex_memory_private.h"
#include "PearAbortObservation.h"

#define PAGE PEAR_FEX_MEMORY_PAGE_BYTES
#define SHARED_UNIT UINT64_C(16777216)
#define DISPATCH_UNIT UINT64_C(16384)
#define PAGE_COUNT ((PEAR_FEX_MEMORY_SHARED_BYTES + PEAR_FEX_MEMORY_DISPATCHER_BYTES) / PAGE)
#define PERMISSION_BYTES ((PAGE_COUNT + 3) / 4)
#define WAIT_SECONDS 2

struct owner_extent {
    uint64_t id, generation, epoch, offset, size;
    uint32_t allocation_class, role, state;
    unsigned live, quarantined;
};
struct owner_executor {
    uint64_t id, allocation_id, generation, epoch, continuation;
    uint32_t role, state;
    pthread_t thread;
    /* Private diagnostic identity, never part of the owner wire ABI. */
    uint64_t diagnostic_host, diagnostic_start_lo, diagnostic_start_hi;
    unsigned diagnostic_valid;
};
struct owner_continuation {
    uint64_t id, executor, allocation_id, generation, epoch, offset;
};
struct owner_descriptor {
    uint64_t executor, continuation, allocation_id, generation, epoch, offset;
};
struct owner_write {
    uint64_t executor, extent_id, generation, epoch, offset, size;
    uint32_t previous_state;
};
struct owner_metadata {
    struct owner_extent extents[PEAR_FEX_MEMORY_MAX_EXTENTS];
    struct owner_executor executors[PEAR_FEX_MEMORY_MAX_EXECUTORS];
    struct owner_continuation continuations[PEAR_FEX_MEMORY_MAX_CONTINUATIONS];
    struct owner_descriptor descriptors[PEAR_FEX_MEMORY_MAX_DESCRIPTORS];
    uint8_t permissions[PERMISSION_BYTES];
    uint8_t old_permissions[PERMISSION_BYTES];
    uint8_t touched[(PAGE_COUNT + 7) / 8];
    struct owner_write write;
    struct pear_fex_memory_backend backend;
    struct pear_fex_memory_backing backing;
    uint64_t identity, generation, epoch;
    uint32_t shared_used;
    uint64_t dispatcher_used;
    _Atomic unsigned initialized;
    unsigned gate_closed, quarantined;
};
static struct owner_metadata owner;
static pthread_mutex_t owner_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t owner_condition = PTHREAD_COND_INITIALIZER;
_Static_assert(sizeof(owner) + sizeof(owner_mutex) + sizeof(owner_condition) <=
               PEAR_FEX_MEMORY_METADATA_BYTES, "New NX owner metadata budget");

static uint32_t fail(struct pear_fex_memory_response *r, uint32_t status,
                     const struct pear_fex_memory_error *error)
{
    memset(r, 0, sizeof(*r));
    r->version = PEAR_FEX_MEMORY_VERSION;
    r->size = sizeof(*r);
    r->status = status;
    if (error) { r->native_error_domain = error->domain; r->native_error_code = error->code; }
    return status;
}
static int range(uint64_t offset, uint64_t size, uint64_t limit)
{
    return size && offset <= limit && size <= limit - offset;
}
static int role_valid(uint32_t role)
{
    return (role == PEAR_FEX_ROLE_NATIVE || role == PEAR_FEX_ROLE_ARM64EC) &&
           owner.backend.role(role) &&
           (role != PEAR_FEX_ROLE_ARM64EC || owner.backend.ec_register);
}
static uint64_t fresh(uint64_t *value)
{
    if (*value == UINT64_MAX) return 0;
    return ++*value;
}
static struct owner_executor *executor(uint64_t id)
{
    unsigned i;
    for (i = 0; i < PEAR_FEX_MEMORY_MAX_EXECUTORS; ++i)
        if (owner.executors[i].id == id && id &&
            owner.executors[i].state != PEAR_FEX_UNREGISTERED &&
            pthread_equal(owner.executors[i].thread, pthread_self())) return &owner.executors[i];
    return NULL;
}
static struct owner_extent *extent(const struct pear_fex_memory_request *q)
{
    unsigned i;
    for (i = 0; i < PEAR_FEX_MEMORY_MAX_EXTENTS; ++i)
    {
        struct owner_extent *e = &owner.extents[i];
        if (e->live && e->id == q->allocation_id && e->generation == q->generation &&
            e->offset == q->extent_offset && e->size == q->extent_size &&
            e->allocation_class == q->allocation_class && e->role == q->ec_role) return e;
    }
    return NULL;
}
static struct owner_continuation *continuation(uint64_t id, const struct owner_executor *x,
                                               const struct owner_extent *e)
{
    unsigned i;
    for (i = 0; i < PEAR_FEX_MEMORY_MAX_CONTINUATIONS; ++i)
    {
        struct owner_continuation *c = &owner.continuations[i];
        if (id && c->id == id && c->executor == x->id && c->allocation_id == e->id &&
            c->generation == e->generation) return c;
    }
    return NULL;
}
static uint64_t usable(const struct owner_extent *e)
{
    return e->size - (e->allocation_class == PEAR_FEX_CLASS_SHARED ? PAGE : 0);
}
static uint64_t page_index(uint64_t offset)
{
    if (offset >= owner.backing.dispatcher_offset)
        return PEAR_FEX_MEMORY_SHARED_BYTES / PAGE + (offset - owner.backing.dispatcher_offset) / PAGE;
    return (offset - owner.backing.shared_offset) / PAGE;
}
static uint32_t page_get(const uint8_t *data, uint64_t index)
{
    return (data[index / 4] >> ((index & 3) * 2)) & 3;
}
static void page_set(uint8_t *data, uint64_t index, uint32_t protection)
{
    unsigned shift = (index & 3) * 2;
    data[index / 4] = (data[index / 4] & ~(3u << shift)) | (protection << shift);
}
static void set_pages(uint64_t offset, uint64_t size, uint32_t protection)
{
    uint64_t i = page_index(offset), end = i + size / PAGE;
    for (; i < end; ++i)
    {
        page_set(owner.permissions, i, protection);
        if (protection == PEAR_FEX_PROTECTION_RW_NX) owner.touched[i/8] |= 1u << (i & 7);
    }
}
static int observe(uint64_t offset, uint64_t size, struct pear_fex_memory_error *error)
{
    uint64_t cursor = offset, end = offset + size;
    while (cursor < end)
    {
        uint32_t protection = page_get(owner.permissions, page_index(cursor));
        uint64_t run = cursor + PAGE;
        while (run < end && page_get(owner.permissions, page_index(run)) == protection) run += PAGE;
        if (owner.backend.query(cursor, run - cursor, protection, error)) return 0;
        cursor = run;
    }
    return 1;
}
static int protect(uint64_t offset, uint64_t size, uint32_t protection,
                   struct pear_fex_memory_error *error)
{
    if (owner.backend.protect(offset, size, protection, error) ||
        owner.backend.query(offset, size, protection, error)) return 0;
    set_pages(offset, size, protection);
    return 1;
}
static int restore(struct pear_fex_memory_error *error)
{
    uint64_t cursor = owner.write.offset, end = cursor + owner.write.size;
    while (cursor < end)
    {
        uint32_t protection = page_get(owner.old_permissions, page_index(cursor));
        uint64_t run = cursor + PAGE;
        while (run < end && page_get(owner.old_permissions, page_index(run)) == protection) run += PAGE;
        if (!protect(cursor, run - cursor, protection, error)) return 0;
        cursor = run;
    }
    return 1;
}
static int active(uint64_t writer)
{
    unsigned i;
    for (i = 0; i < PEAR_FEX_MEMORY_MAX_EXECUTORS; ++i)
        if (owner.executors[i].state == PEAR_FEX_MANAGED_ACTIVE ||
            (owner.executors[i].state == PEAR_FEX_NATIVE_PINNED && owner.executors[i].id != writer)) return 1;
    return 0;
}
/* Opt-in is sampled before initialization locks. The counter and snapshot
 * copy use the existing owner mutex; output uses only the dispatch-local copy. */
#define TIMEOUT_OBSERVATION_LIMIT 8
struct timeout_row {
    uint64_t id, host, start_lo, start_hi;
    uint32_t state, role;
    unsigned identity_valid;
};
struct timeout_snapshot {
    uint64_t writer;
    unsigned present, sequence, opcode, active, pinned, count, truncated;
    struct timeout_row rows[TIMEOUT_OBSERVATION_LIMIT];
};
static unsigned timeout_observation_enabled, timeout_observation_count;
static unsigned thread_observation_enabled;
static unsigned abort_observation_enabled, abort_observation_count;
static void emit_abort(const struct PearAbortRecord *d, unsigned present) {
    char buffer[1536]; int saved_errno=errno, n;
    if (!present) return;
    n=pear_abort_format(buffer,sizeof(buffer),3,d);
    if (n>0 && (size_t)n<sizeof(buffer)) (void)write(STDERR_FILENO,buffer,n);
    errno=saved_errno;
}

static void capture_timeout(struct timeout_snapshot *s, unsigned opcode)
{
    unsigned i;
    if (!timeout_observation_enabled || timeout_observation_count >= TIMEOUT_OBSERVATION_LIMIT) return;
    s->present = 1; s->sequence = timeout_observation_count++;
    s->writer = owner.write.executor; s->opcode = opcode;
    for (i = 0; i < PEAR_FEX_MEMORY_MAX_EXECUTORS; ++i)
    {
        const struct owner_executor *x = &owner.executors[i];
        if (x->state == PEAR_FEX_MANAGED_ACTIVE) ++s->active;
        else if (x->state == PEAR_FEX_NATIVE_PINNED && x->id != s->writer) ++s->pinned;
        else continue;
        if (s->count < TIMEOUT_OBSERVATION_LIMIT)
        {
            struct timeout_row *row = &s->rows[s->count++];
            row->id = x->id; row->state = x->state; row->role = x->role;
            row->host = x->diagnostic_host; row->start_lo = x->diagnostic_start_lo;
            row->start_hi = x->diagnostic_start_hi; row->identity_valid = x->diagnostic_valid;
        }
        else ++s->truncated;
    }
}
static void emit_timeout(const struct timeout_snapshot *s)
{
    char buffer[4096];
    int saved_errno = errno, n;
    unsigned i;
    size_t used;
    if (!s->present) return;
    n = snprintf(buffer, sizeof(buffer),
                 "PEAR_OWNER_TIMEOUT seq=%u opcode=%u writer=%" PRIu64 " active=%u pinned=%u rows=%u truncated=%u\n",
                 s->sequence, s->opcode, s->writer, s->active, s->pinned, s->count, s->truncated);
    if (n < 0 || (size_t)n >= sizeof(buffer)) goto done;
    used = n;
    for (i = 0; i < s->count; ++i)
    {
        const struct timeout_row *row = &s->rows[i];
        n = snprintf(buffer + used, sizeof(buffer) - used,
                     "PEAR_OWNER_ROW seq=%u index=%u id=%" PRIu64 " state=%u role=%u\n",
                     s->sequence, i, row->id, row->state, row->role);
        if (n < 0 || (size_t)n >= sizeof(buffer) - used) goto done;
        used += n;
        if (thread_observation_enabled)
        {
            n = snprintf(buffer + used, sizeof(buffer) - used,
                         "PEAR_OWNER_THREAD seq=%u index=%u id=%" PRIu64 " valid=%u host=%" PRIu64
                         " register_lo=%" PRIu64 " register_hi=%" PRIu64 "\n",
                         s->sequence, i, row->id, row->identity_valid, row->host, row->start_lo, row->start_hi);
            if (n < 0 || (size_t)n >= sizeof(buffer) - used) goto done;
            used += n;
        }
    }
    /* A short or failed write is incomplete evidence, never an owner error. */
    (void)write(STDERR_FILENO, buffer, used);
 done:
    errno = saved_errno;
}

/* Registration identity is copied at successful commit, emitted after unlock.
 * This reuses the already captured opt-in identity and never adds a host query. */
#define REGISTRATION_OBSERVATION_LIMIT 128
struct registration_snapshot {
    uint64_t pid, id, host, start_lo, start_hi;
    unsigned present, sequence, role, valid;
};
static unsigned registration_observation_count;
static void capture_registration(struct registration_snapshot *s, const struct owner_executor *x)
{
    if (!thread_observation_enabled || registration_observation_count >= REGISTRATION_OBSERVATION_LIMIT) return;
    s->present = 1; s->sequence = registration_observation_count++;
    s->pid = owner.backing.owner_pid; s->id = x->id; s->role = x->role;
    s->valid = x->diagnostic_valid; s->host = x->diagnostic_host;
    s->start_lo = x->diagnostic_start_lo; s->start_hi = x->diagnostic_start_hi;
}
static void emit_registration(const struct registration_snapshot *s)
{
    char buffer[512];
    int saved_errno = errno, n;
    if (!s->present) return;
    n = snprintf(buffer, sizeof(buffer),
                 "PEAR_OWNER_REGISTER1 pid=%" PRIu64 " seq=%u id=%" PRIu64 " role=%u valid=%u host=%" PRIu64
                 " register_lo=%" PRIu64 " register_hi=%" PRIu64 "\n",
                 s->pid, s->sequence, s->id, s->role, s->valid, s->host, s->start_lo, s->start_hi);
    /* No retry, grant or dispatch error is created for incomplete output. */
    if (n > 0 && (size_t)n < sizeof(buffer)) (void)write(STDERR_FILENO, buffer, n);
    errno = saved_errno;
}

static int pins(const struct owner_extent *e)
{
    unsigned i;
    for (i = 0; i < PEAR_FEX_MEMORY_MAX_CONTINUATIONS; ++i)
        if (owner.continuations[i].id && owner.continuations[i].allocation_id == e->id &&
            owner.continuations[i].generation == e->generation) return 1;
    for (i = 0; i < PEAR_FEX_MEMORY_MAX_EXECUTORS; ++i)
        if (owner.executors[i].allocation_id == e->id && owner.executors[i].generation == e->generation &&
            owner.executors[i].state == PEAR_FEX_MANAGED_ACTIVE) return 1;
    return 0;
}
static int monotonic_deadline(struct timespec *deadline, struct pear_fex_memory_error *error)
{
    if (clock_gettime(CLOCK_MONOTONIC, deadline))
    { error->domain = PEAR_FEX_ERROR_ERRNO; error->code = errno; return 0; }
    deadline->tv_sec += WAIT_SECONDS;
    return 1;
}
static int wait_condition(const struct timespec *deadline)
{
    struct timespec now, remaining;
    int status;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return errno;
    remaining.tv_sec = deadline->tv_sec-now.tv_sec;
    remaining.tv_nsec = deadline->tv_nsec-now.tv_nsec;
    if (remaining.tv_nsec < 0) { --remaining.tv_sec; remaining.tv_nsec += 1000000000; }
    if (remaining.tv_sec < 0 || (!remaining.tv_sec && !remaining.tv_nsec)) return ETIMEDOUT;
#ifdef __APPLE__
    status = pthread_cond_timedwait_relative_np(&owner_condition, &owner_mutex, &remaining);
#else
    /* Portable source controls use the default POSIX condition clock. Darwin's
     * actual admitted path above is relative to the monotonic finite deadline. */
    if (clock_gettime(CLOCK_REALTIME, &now)) return errno;
    now.tv_sec += remaining.tv_sec; now.tv_nsec += remaining.tv_nsec;
    if (now.tv_nsec >= 1000000000) { ++now.tv_sec; now.tv_nsec -= 1000000000; }
    status = pthread_cond_timedwait(&owner_condition, &owner_mutex, &now);
#endif
    return status;
}
static uint32_t wait_native(struct pear_fex_memory_error *native_error,
                            struct timeout_snapshot *snapshot, unsigned opcode)
{
    struct timespec deadline;
    int error;
    if (!monotonic_deadline(&deadline, native_error)) return PEAR_FEX_NATIVE_FAILURE;
    while (active(owner.write.executor))
    {
        error = wait_condition(&deadline);
        if (error == ETIMEDOUT) { capture_timeout(snapshot, opcode); return PEAR_FEX_QUIESCENCE_TIMEOUT; }
        if (error) { native_error->domain = PEAR_FEX_ERROR_ERRNO; native_error->code = error; return PEAR_FEX_NATIVE_FAILURE; }
    }
    return PEAR_FEX_OK;
}
static uint32_t park(struct owner_executor *x, struct pear_fex_memory_error *native_error)
{
    uint32_t previous = x->state;
    int error;
    struct timespec deadline;
    if (previous != PEAR_FEX_NATIVE_IDLE && previous != PEAR_FEX_NATIVE_PINNED)
        return PEAR_FEX_INVALID_REQUEST;
    if (!monotonic_deadline(&deadline, native_error)) return PEAR_FEX_NATIVE_FAILURE;
    while (owner.gate_closed && !owner.quarantined)
    {
        x->state = PEAR_FEX_PARKED;
        pthread_cond_broadcast(&owner_condition);
        error = wait_condition(&deadline);
        if (error)
        {
            x->state = previous;
            if (error == ETIMEDOUT) return PEAR_FEX_QUIESCENCE_TIMEOUT;
            native_error->domain = PEAR_FEX_ERROR_ERRNO; native_error->code = error;
            return PEAR_FEX_NATIVE_FAILURE;
        }
    }
    x->state = previous;
    return owner.quarantined ? PEAR_FEX_QUARANTINED : PEAR_FEX_OK;
}
static void open_gate(void)
{
    memset(&owner.write, 0, sizeof(owner.write));
    owner.gate_closed = 0;
    pthread_cond_broadcast(&owner_condition);
}
static void quarantine(struct owner_extent *e)
{
    e->quarantined = 1;
    owner.quarantined = 1;
    owner.gate_closed = 1;
    pthread_cond_broadcast(&owner_condition);
}
static void reply(struct pear_fex_memory_response *r, const struct owner_extent *e,
                  const struct owner_executor *x, uint64_t c)
{
    r->owner_pid = owner.backing.owner_pid;
    if (e)
    {
        r->allocation_id = e->id; r->generation = e->generation; r->write_epoch = e->epoch;
        r->extent_offset = e->offset; r->extent_size = e->size;
        r->allocation_class = e->allocation_class; r->ec_role = e->role;
        r->lifecycle_state = e->state;
    }
    if (x) { r->executor_id = x->id; r->flags = x->state; }
    r->continuation_id = c;
}

/* A closed opcode mask controls every nonheader request word. */
static int shape(const struct pear_fex_memory_request *q)
{
    uint64_t values[] = {q->allocation_id, q->generation, q->write_epoch, q->executor_id,
        q->continuation_id, q->extent_offset, q->extent_size, q->operation_offset,
        q->operation_size, q->allocation_class, q->ec_role, q->expected_state};
    const unsigned T = (1u<<0)|(1u<<1)|(1u<<5)|(1u<<6)|(1u<<9)|(1u<<10);
    const unsigned E = 1u<<2, X = 1u<<3, C = 1u<<4, O = (1u<<7)|(1u<<8), S = 1u<<11;
    unsigned mask, i;
    if (q->size != sizeof(*q) || q->flags || q->reserved0 || q->reserved1 || q->reserved2 ||
        q->allocation_class > PEAR_FEX_CLASS_DISPATCHER || q->ec_role > PEAR_FEX_ROLE_NATIVE ||
        q->expected_state > PEAR_FEX_RETIRED_NONE) return 0;
    switch (q->opcode)
    {
    case PEAR_FEX_RESERVE: mask = X | (1u<<6)|(1u<<9)|(1u<<10); break;
    case PEAR_FEX_BEGIN_WRITE: mask = T|E|X|C|O|S; break;
    case PEAR_FEX_PUBLISH: case PEAR_FEX_ABORT_WRITE: mask = T|E|X|C|S; break;
    case PEAR_FEX_RETIRE: mask = T|E|X|S; break;
    case PEAR_FEX_QUERY: mask = T|X|C; break;
    case PEAR_FEX_EXECUTOR_REGISTER: case PEAR_FEX_OBSERVE_METADATA: mask = 1u<<10; break;
    case PEAR_FEX_EXECUTOR_ENTRY: case PEAR_FEX_EXECUTOR_HANDOFF:
    case PEAR_FEX_EXECUTOR_RESUME: mask = T|E|X|C|O|S; break;
    case PEAR_FEX_EXECUTOR_EXIT: mask = T|E|X|S; break;
    case PEAR_FEX_CONTINUATION_PIN: mask = T|E|X|O|S; break;
    case PEAR_FEX_CONTINUATION_UNPIN: mask = T|E|X|C|S; break;
    case PEAR_FEX_EXECUTOR_UNREGISTER: mask = X; break;
    default: return 0;
    }
    for (i = 0; i < sizeof(values)/sizeof(values[0]); ++i)
        if (!(mask & (1u<<i)) && values[i]) return 0;
    return 1;
}

/* Resolve the sole original descriptor while the owner mutex is held.
 * Original continuation epoch is never supplied as the requested current epoch.
 * Reuse this entire check after park released/reacquired the mutex. */
static struct owner_descriptor *resume_descriptor(const struct pear_fex_memory_request *q,
    const struct owner_executor *x, const struct owner_extent *e, const struct owner_continuation *c)
{
    struct owner_descriptor *found = NULL;
    unsigned i, count = 0;
    if (!x || !e || !c || e->allocation_class != PEAR_FEX_CLASS_DISPATCHER ||
        e->state != PEAR_FEX_PUBLISHED_RX || q->expected_state != PEAR_FEX_PUBLISHED_RX ||
        !q->write_epoch || !c->epoch || e->epoch < c->epoch ||
        x->state != PEAR_FEX_NATIVE_PINNED || x->role != e->role ||
        x->continuation != c->id || x->allocation_id != e->id || x->generation != e->generation ||
        x->epoch != c->epoch || q->operation_size != 4 || q->operation_offset != c->offset ||
        (q->operation_offset & 3) || !range(q->operation_offset, 4, usable(e))) return NULL;
    for (i = 0; i < PEAR_FEX_MEMORY_MAX_CONTINUATIONS; ++i)
        if (owner.continuations[i].id && owner.continuations[i].executor == x->id &&
            owner.continuations[i].id != c->id) return NULL;
    for (i = 0; i < PEAR_FEX_MEMORY_MAX_DESCRIPTORS; ++i)
        if (owner.descriptors[i].executor == x->id)
        { found = &owner.descriptors[i]; ++count; }
    if (count != 1 || !found || found->continuation != c->id || found->allocation_id != e->id ||
        found->generation != e->generation || found->epoch != c->epoch || found->offset != c->offset)
        return NULL;
    return found;
}

uint32_t pear_fex_memory_initialize(const struct pear_fex_memory_backend *backend,
                                    struct pear_fex_memory_error *error)
{
    uint32_t status = PEAR_FEX_OK;
    const char *observation;
    unsigned enabled, thread_enabled, abort_enabled;
    int saved_errno;
    struct pear_fex_memory_backing backing = {0};
    if (!error) return PEAR_FEX_INVALID_REQUEST;
    memset(error, 0, sizeof(*error));
    if (!backend || !backend->initialize || !backend->query || !backend->protect ||
        !backend->view || !backend->role || !backend->entry) return PEAR_FEX_INVALID_REQUEST;
    if (atomic_load_explicit(&owner.initialized, memory_order_acquire) &&
        owner.backing.owner_pid != (uint64_t)getpid()) return PEAR_FEX_STALE_IDENTITY;
    saved_errno = errno;
    observation = getenv("PEAR_FEX_OWNER_OBSERVE");
    enabled = observation && !strcmp(observation, "1");
    observation = getenv("PEAR_FEX_THREAD_OBSERVE");
    thread_enabled = observation && !strcmp(observation, "1");
    observation = getenv("PEAR_FEX_ABORT_OBSERVE");
    abort_enabled = observation && !strcmp(observation, "1");
    errno = saved_errno;
    pthread_mutex_lock(&owner_mutex);
    if (owner.initialized)
    {
        if (owner.backing.owner_pid != (uint64_t)getpid() ||
            memcmp(&owner.backend, backend, sizeof(*backend))) status = PEAR_FEX_STALE_IDENTITY;
        goto done;
    }
    if (backend->initialize(&backing, error)) { status = PEAR_FEX_NATIVE_FAILURE; goto done; }
    if (backing.owner_pid != (uint64_t)getpid() || !backing.private_base ||
        backing.shared_offset & (UINT64_C(65536)-1) || backing.dispatcher_offset & (DISPATCH_UNIT-1) ||
        backing.shared_offset > UINT64_MAX - PEAR_FEX_MEMORY_SHARED_BYTES - PEAR_FEX_MEMORY_SEPARATOR_BYTES ||
        backing.dispatcher_offset != backing.shared_offset + PEAR_FEX_MEMORY_SHARED_BYTES + PEAR_FEX_MEMORY_SEPARATOR_BYTES ||
        backing.dispatcher_offset > UINT64_MAX - PEAR_FEX_MEMORY_DISPATCHER_BYTES ||
        backing.private_base > UINT64_MAX - backing.dispatcher_offset - PEAR_FEX_MEMORY_DISPATCHER_BYTES ||
        (backing.capabilities & ~PEAR_FEX_CAPABILITIES_MASK) ||
        (backing.capabilities & (PEAR_FEX_SINGLE_MAP_JIT | PEAR_FEX_OBSERVED_4K)) != 3)
    { status = PEAR_FEX_UNAVAILABLE; goto done; }
    if (backend->query(backing.shared_offset, PEAR_FEX_MEMORY_SHARED_BYTES, PEAR_FEX_PROTECTION_NONE, error) ||
        backend->query(backing.dispatcher_offset, PEAR_FEX_MEMORY_DISPATCHER_BYTES, PEAR_FEX_PROTECTION_NONE, error))
    { status = PEAR_FEX_NATIVE_FAILURE; goto done; }
    owner.backend = *backend; owner.backing = backing;
    owner.backing.capabilities = (backing.capabilities & ~PEAR_FEX_CHECKED_EC_BITMAP) | PEAR_FEX_GLOBAL_GATE;
    timeout_observation_enabled = enabled;
    thread_observation_enabled = enabled && thread_enabled;
    abort_observation_enabled = enabled && thread_enabled && abort_enabled;
    atomic_store_explicit(&owner.initialized, 1, memory_order_release);
 done:
    pthread_mutex_unlock(&owner_mutex);
    return status;
}

uint32_t pear_fex_memory_poll(uint64_t id)
{
    struct owner_executor *x;
    uint32_t status;
    struct pear_fex_memory_error error = {0};
    if (atomic_load_explicit(&owner.initialized, memory_order_acquire) &&
        owner.backing.owner_pid != (uint64_t)getpid()) return PEAR_FEX_STALE_IDENTITY;
    pthread_mutex_lock(&owner_mutex);
    if (!owner.initialized || owner.backing.owner_pid != (uint64_t)getpid()) status = PEAR_FEX_UNAVAILABLE;
    else if (!(x = executor(id))) status = PEAR_FEX_STALE_IDENTITY;
    else status = park(x, &error);
    pthread_mutex_unlock(&owner_mutex);
    return status;
}

uint32_t pear_fex_memory_dispatch(const struct pear_fex_memory_request *q,
                                  struct pear_fex_memory_response *r)
{
    struct owner_executor *x = NULL;
    struct owner_extent *e = NULL;
    struct owner_continuation *c = NULL;
    struct pear_fex_memory_error error = {0};
    uint32_t status = PEAR_FEX_OK;
    unsigned i;
    struct timeout_snapshot snapshot = {0};
    struct registration_snapshot registration = {0};
    struct PearAbortRecord d = {0};
    unsigned abort_reason=0, abort_previous=0, abort_previous_known=0, abort_present=0;
    uint64_t diagnostic_host = 0, diagnostic_lo = 0, diagnostic_hi = 0;
    unsigned diagnostic_valid = 0;
    if (!r) return PEAR_FEX_INVALID_REQUEST;
    fail(r, PEAR_FEX_OK, NULL);
    if (!q) return fail(r, PEAR_FEX_INVALID_REQUEST, NULL);
    if (q->version != PEAR_FEX_MEMORY_VERSION) return fail(r, PEAR_FEX_VERSION_MISMATCH, NULL);
    if (!shape(q)) return fail(r, PEAR_FEX_INVALID_REQUEST, NULL);
    if (atomic_load_explicit(&owner.initialized, memory_order_acquire) &&
        owner.backing.owner_pid != (uint64_t)getpid()) return fail(r, PEAR_FEX_STALE_IDENTITY, NULL);
    /* Query only our registering thread outside the owner lock. Initialization
     * publishes the immutable opt-in with owner.initialized. Query failure is
     * unknown diagnostic identity and cannot change the dispatch result. */
    if (atomic_load_explicit(&owner.initialized, memory_order_acquire) &&
        thread_observation_enabled && q->opcode == PEAR_FEX_EXECUTOR_REGISTER)
    {
        struct timespec lo = {0}, hi = {0};
        int saved_errno = errno;
        if (!clock_gettime(CLOCK_MONOTONIC, &lo) &&
            !pthread_threadid_np(NULL, &diagnostic_host) && diagnostic_host &&
            !clock_gettime(CLOCK_MONOTONIC, &hi))
        {
            diagnostic_lo = (uint64_t)lo.tv_sec * UINT64_C(1000000000) + lo.tv_nsec;
            diagnostic_hi = (uint64_t)hi.tv_sec * UINT64_C(1000000000) + hi.tv_nsec;
            diagnostic_valid = diagnostic_lo && diagnostic_hi >= diagnostic_lo;
        }
        if (!diagnostic_valid) diagnostic_host = diagnostic_lo = diagnostic_hi = 0;
        errno = saved_errno;
    }
    pthread_mutex_lock(&owner_mutex);
    if (!owner.initialized) { status = PEAR_FEX_UNAVAILABLE; goto done; }
    if (q->owner_pid != owner.backing.owner_pid || q->owner_pid != (uint64_t)getpid())
    { status = PEAR_FEX_STALE_IDENTITY; goto done; }
    if (owner.quarantined) { abort_reason=1; status = PEAR_FEX_QUARANTINED; goto done; }
    if (q->opcode == PEAR_FEX_OBSERVE_METADATA)
    {
        struct pear_fex_memory_metadata metadata = {0};
        if (!role_valid(q->ec_role) || !owner.backend.metadata)
        { status = PEAR_FEX_UNAVAILABLE; goto done; }
        if (owner.backend.metadata(&metadata, &error))
        { status = PEAR_FEX_NATIVE_FAILURE; goto done; }
        if (metadata.fixed_native_bytes > UINT64_MAX - sizeof(owner) - sizeof(owner_mutex) - sizeof(owner_condition))
        { status = PEAR_FEX_CAPACITY; goto done; }
        metadata.version = PEAR_FEX_MEMORY_VERSION; metadata.size = sizeof(metadata);
        metadata.owner_pid = owner.backing.owner_pid;
        metadata.fixed_native_bytes += sizeof(owner) + sizeof(owner_mutex) + sizeof(owner_condition);
        memcpy(r, &metadata, sizeof(metadata));
        goto done;
    }
    if (q->executor_id && !(x = executor(q->executor_id))) { status = PEAR_FEX_STALE_IDENTITY; goto done; }
    if (q->allocation_id && !(e = extent(q))) { status = PEAR_FEX_STALE_IDENTITY; goto done; }
    if (!q->allocation_id && (q->generation || q->extent_offset ||
        (q->opcode != PEAR_FEX_RESERVE && (q->allocation_class || q->extent_size))))
    { status = PEAR_FEX_INVALID_REQUEST; goto done; }
    if (e && e->quarantined) { abort_reason=2; status = PEAR_FEX_QUARANTINED; goto done; }
    if (q->continuation_id && (!x || !e || !(c = continuation(q->continuation_id, x, e))))
    { status = PEAR_FEX_STALE_IDENTITY; goto done; }
    if (q->opcode != PEAR_FEX_QUERY && q->opcode != PEAR_FEX_EXECUTOR_REGISTER && !x)
    { status = PEAR_FEX_INVALID_REQUEST; goto done; }
    if (e && x && e->role != x->role) { status = PEAR_FEX_INVALID_REQUEST; goto done; }

    switch (q->opcode)
    {
    case PEAR_FEX_EXECUTOR_REGISTER:
        if (!role_valid(q->ec_role)) { status = PEAR_FEX_UNAVAILABLE; break; }
        for (i = 0; i < PEAR_FEX_MEMORY_MAX_EXECUTORS; ++i)
            if (owner.executors[i].id && owner.executors[i].state != PEAR_FEX_UNREGISTERED &&
                pthread_equal(owner.executors[i].thread, pthread_self())) { status = PEAR_FEX_INVALID_REQUEST; goto done; }
        for (i = 0; i < PEAR_FEX_MEMORY_MAX_EXECUTORS; ++i)
            if (!owner.executors[i].id || owner.executors[i].state == PEAR_FEX_UNREGISTERED) break;
        if (i == PEAR_FEX_MEMORY_MAX_EXECUTORS || !fresh(&owner.identity)) { status = PEAR_FEX_CAPACITY; break; }
        x = &owner.executors[i]; memset(x, 0, sizeof(*x));
        x->id = owner.identity; x->thread = pthread_self(); x->role = q->ec_role; x->state = PEAR_FEX_NATIVE_IDLE;
        x->diagnostic_host = diagnostic_host; x->diagnostic_start_lo = diagnostic_lo;
        x->diagnostic_start_hi = diagnostic_hi; x->diagnostic_valid = diagnostic_valid;
        reply(r, NULL, x, 0);
        capture_registration(&registration, x); break;
    case PEAR_FEX_RESERVE:
    {
        uint64_t unit, offset, mask;
        unsigned count, first, limit;
        if (x->state != PEAR_FEX_NATIVE_IDLE && x->state != PEAR_FEX_NATIVE_PINNED)
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        if (x->role != q->ec_role || !role_valid(q->ec_role) || owner.gate_closed)
        { status = PEAR_FEX_UNAVAILABLE; break; }
        if (q->allocation_class == PEAR_FEX_CLASS_SHARED)
        {
            if (q->extent_size != SHARED_UNIT && q->extent_size != SHARED_UNIT*2 &&
                q->extent_size != SHARED_UNIT*4 && q->extent_size != SHARED_UNIT*8)
            { status = PEAR_FEX_INVALID_REQUEST; break; }
            unit = SHARED_UNIT; limit = 32; offset = owner.backing.shared_offset;
        }
        else if (q->allocation_class == PEAR_FEX_CLASS_DISPATCHER && q->extent_size == DISPATCH_UNIT)
        { unit = DISPATCH_UNIT; limit = 64; offset = owner.backing.dispatcher_offset; }
        else { status = PEAR_FEX_INVALID_REQUEST; break; }
        count = q->extent_size / unit;
        for (first = 0; first + count <= limit; ++first)
        {
            mask = ((UINT64_C(1) << count) - 1) << first;
            if (!(mask & (q->allocation_class == PEAR_FEX_CLASS_SHARED ? owner.shared_used : owner.dispatcher_used))) break;
        }
        for (i = 0; i < PEAR_FEX_MEMORY_MAX_EXTENTS; ++i) if (!owner.extents[i].live) break;
        if (first + count > limit || i == PEAR_FEX_MEMORY_MAX_EXTENTS ||
            owner.identity == UINT64_MAX || owner.generation == UINT64_MAX)
        { status = PEAR_FEX_CAPACITY; break; }
        offset += first * unit;
        if (owner.backend.query(offset, q->extent_size, PEAR_FEX_PROTECTION_NONE, &error))
        { status = PEAR_FEX_NATIVE_FAILURE; break; }
        e = &owner.extents[i]; memset(e, 0, sizeof(*e));
        e->id = fresh(&owner.identity); e->generation = fresh(&owner.generation);
        if (owner.backend.view(offset, q->extent_size, e->id, e->generation, q->allocation_class, q->ec_role, 1, &error))
        { memset(e, 0, sizeof(*e)); status = PEAR_FEX_NATIVE_FAILURE; break; }
        e->offset = offset; e->size = q->extent_size; e->allocation_class = q->allocation_class;
        e->role = q->ec_role; e->state = PEAR_FEX_RESERVED_NONE; e->live = 1;
        if (e->allocation_class == PEAR_FEX_CLASS_SHARED) owner.shared_used |= (uint32_t)mask;
        else owner.dispatcher_used |= mask;
        reply(r, e, x, 0); r->effective_protection = PEAR_FEX_PROTECTION_NONE; break;
    }
    case PEAR_FEX_QUERY:
        if (e)
        {
            if (!observe(e->offset, e->size, &error)) { status = PEAR_FEX_NATIVE_FAILURE; break; }
            {
                uint64_t first = page_index(e->offset), end = first + e->size/PAGE, cursor;
                uint32_t uniform = page_get(owner.permissions, first);
                for (cursor = first + 1; cursor < end; ++cursor)
                    if (page_get(owner.permissions, cursor) != uniform)
                    { status = PEAR_FEX_UNAVAILABLE; goto done; }
                reply(r, e, x, q->continuation_id);
                r->effective_protection = uniform;
            }
        }
        else
        {
            if (q->ec_role || q->continuation_id) { status = PEAR_FEX_INVALID_REQUEST; break; }
            reply(r, NULL, x, 0);
        }
        r->capabilities = owner.backing.capabilities;
        break;
    case PEAR_FEX_BEGIN_WRITE:
    {
        uint64_t offset, end;
        if (!e || owner.gate_closed || e->state != q->expected_state || q->write_epoch != e->epoch ||
            (e->state != PEAR_FEX_RESERVED_NONE && e->state != PEAR_FEX_PUBLISHED_RX) ||
            (x->state != PEAR_FEX_NATIVE_IDLE && x->state != PEAR_FEX_NATIVE_PINNED) ||
            (x->state == PEAR_FEX_NATIVE_PINNED && (!x->continuation || (c && x->continuation != c->id))) ||
            !range(q->operation_offset, q->operation_size, usable(e)) || owner.epoch == UINT64_MAX)
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        offset = e->offset + (q->operation_offset & ~(PAGE - 1));
        end = e->offset + ((q->operation_offset + q->operation_size + PAGE - 1) & ~(PAGE - 1));
        owner.gate_closed = 1; owner.write.executor = x->id;
        if ((status = wait_native(&error, &snapshot, q->opcode)) != PEAR_FEX_OK) { open_gate(); break; }
        if (!observe(offset, end - offset, &error)) { open_gate(); status = PEAR_FEX_NATIVE_FAILURE; break; }
        memcpy(owner.old_permissions, owner.permissions, sizeof(owner.permissions));
        owner.write = (struct owner_write){x->id, e->id, e->generation, fresh(&owner.epoch), offset, end-offset, e->state};
        if (!protect(offset, end-offset, PEAR_FEX_PROTECTION_RW_NX, &error))
        {
            struct pear_fex_memory_error rollback_error = {0};
            if (!restore(&rollback_error)) { quarantine(e); status = PEAR_FEX_QUARANTINED; }
            else { open_gate(); status = PEAR_FEX_NATIVE_FAILURE; }
            break;
        }
        e->epoch = owner.write.epoch; e->state = PEAR_FEX_WRITING_RW_NX;
        reply(r, e, x, q->continuation_id);
        r->private_write_base = owner.backing.private_base + e->offset + q->operation_offset;
        r->effective_protection = PEAR_FEX_PROTECTION_RW_NX; break;
    }
    case PEAR_FEX_PUBLISH: case PEAR_FEX_ABORT_WRITE:
        if (!e || e->state != PEAR_FEX_WRITING_RW_NX || q->expected_state != e->state ||
            q->write_epoch != e->epoch || owner.write.executor != x->id || owner.write.extent_id != e->id ||
            owner.write.generation != e->generation || !owner.gate_closed ||
            (x->state == PEAR_FEX_NATIVE_PINNED && (!x->continuation || (c && x->continuation != c->id))))
        { status = PEAR_FEX_STALE_IDENTITY; break; }
        if (q->opcode == PEAR_FEX_ABORT_WRITE)
        {
            abort_previous=owner.write.previous_state; abort_previous_known=1;
            if (owner.write.previous_state != PEAR_FEX_RESERVED_NONE)
            {
                abort_reason=3;
                struct pear_fex_memory_error none_error = {0};
                if (!protect(e->offset, e->size, PEAR_FEX_PROTECTION_NONE, &none_error)) error = none_error;
                quarantine(e); status = PEAR_FEX_QUARANTINED; break;
            }
            memset((void *)(uintptr_t)(owner.backing.private_base + owner.write.offset), 0, owner.write.size);
            if (!restore(&error)) { abort_reason=4; quarantine(e); status = PEAR_FEX_QUARANTINED; break; }
            e->state = PEAR_FEX_RESERVED_NONE;
            reply(r, e, x, q->continuation_id); open_gate(); break;
        }
        if (!protect(owner.write.offset, owner.write.size, PEAR_FEX_PROTECTION_RX, &error))
        { quarantine(e); status = PEAR_FEX_QUARANTINED; break; }
        if (e->role == PEAR_FEX_ROLE_ARM64EC &&
            owner.backend.ec_register(owner.write.offset, owner.write.size, 1, &error))
        { quarantine(e); status = PEAR_FEX_QUARANTINED; break; }
        if (e->role == PEAR_FEX_ROLE_ARM64EC) owner.backing.capabilities |= PEAR_FEX_CHECKED_EC_BITMAP;
        __builtin___clear_cache((char *)(uintptr_t)(owner.backing.private_base + owner.write.offset),
                               (char *)(uintptr_t)(owner.backing.private_base + owner.write.offset + owner.write.size));
        e->state = PEAR_FEX_PUBLISHED_RX;
        reply(r, e, x, q->continuation_id); r->effective_protection = PEAR_FEX_PROTECTION_RX;
        open_gate(); break;
    case PEAR_FEX_RETIRE:
    {
        uint64_t unit, mask, first;
        if (!e || e->state != q->expected_state || q->write_epoch != e->epoch ||
            (e->state != PEAR_FEX_RESERVED_NONE && e->state != PEAR_FEX_PUBLISHED_RX) ||
            owner.gate_closed || (x->state != PEAR_FEX_NATIVE_IDLE && x->state != PEAR_FEX_NATIVE_PINNED))
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        owner.gate_closed = 1; owner.write.executor = x->id;
        if ((status = wait_native(&error, &snapshot, q->opcode)) != PEAR_FEX_OK) { open_gate(); break; }
        if (pins(e)) { open_gate(); status = PEAR_FEX_UNAVAILABLE; break; }
        e->state = PEAR_FEX_RETIRING;
        if (e->role == PEAR_FEX_ROLE_ARM64EC && owner.backend.ec_register(e->offset, e->size, 0, &error))
        { quarantine(e); status = PEAR_FEX_QUARANTINED; break; }
        if (!protect(e->offset, e->size, PEAR_FEX_PROTECTION_NONE, &error))
        { quarantine(e); status = PEAR_FEX_QUARANTINED; break; }
        /* Virgin NONE/guard pages are never committed just to clear them.
         * The compact source-touched ledger bounds actual clearing runs. */
        {
            uint64_t cursor = e->offset, end = e->offset + usable(e);
            while (cursor < end)
            {
                uint64_t index = page_index(cursor), run;
                if (!(owner.touched[index/8] & (1u << (index & 7)))) { cursor += PAGE; continue; }
                run = cursor + PAGE;
                while (run < end)
                {
                    uint64_t next = page_index(run);
                    if (!(owner.touched[next/8] & (1u << (next & 7)))) break;
                    run += PAGE;
                }
                if (!protect(cursor, run-cursor, PEAR_FEX_PROTECTION_RW_NX, &error))
                { quarantine(e); status = PEAR_FEX_QUARANTINED; goto done; }
                memset((void *)(uintptr_t)(owner.backing.private_base + cursor), 0, run-cursor);
                if (!protect(cursor, run-cursor, PEAR_FEX_PROTECTION_NONE, &error))
                { quarantine(e); status = PEAR_FEX_QUARANTINED; goto done; }
                while (cursor < run)
                {
                    index = page_index(cursor);
                    owner.touched[index/8] &= ~(1u << (index & 7)); cursor += PAGE;
                }
            }
        }
        if (owner.backend.query(e->offset, e->size, PEAR_FEX_PROTECTION_NONE, &error) ||
            owner.backend.view(e->offset, e->size, e->id, e->generation, e->allocation_class, e->role, 0, &error))
        { quarantine(e); status = PEAR_FEX_QUARANTINED; break; }
        e->state = PEAR_FEX_RETIRED_NONE; reply(r, e, x, 0);
        unit = e->allocation_class == PEAR_FEX_CLASS_SHARED ? SHARED_UNIT : DISPATCH_UNIT;
        first = (e->offset - (e->allocation_class == PEAR_FEX_CLASS_SHARED ? owner.backing.shared_offset : owner.backing.dispatcher_offset))/unit;
        mask = ((UINT64_C(1) << (e->size/unit)) - 1) << first;
        if (e->allocation_class == PEAR_FEX_CLASS_SHARED) owner.shared_used &= ~(uint32_t)mask;
        else owner.dispatcher_used &= ~mask;
        e->live = 0; open_gate(); break;
    }
    case PEAR_FEX_EXECUTOR_ENTRY:
        if (!e || e->state != PEAR_FEX_PUBLISHED_RX || q->expected_state != e->state || q->write_epoch != e->epoch ||
            q->operation_size != 4 || q->operation_offset & 3 || !range(q->operation_offset, 4, usable(e)) ||
            (x->state != PEAR_FEX_NATIVE_IDLE && x->state != PEAR_FEX_NATIVE_PINNED) ||
            (x->state == PEAR_FEX_NATIVE_PINNED && (!c || x->continuation != c->id)) ||
            !owner.backend.entry(e->offset, usable(e), q->operation_offset, e->allocation_class, e->role))
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        if (owner.gate_closed && (status = park(x, &error)) != PEAR_FEX_OK) break;
        if (e->state != PEAR_FEX_PUBLISHED_RX || e->epoch != q->write_epoch)
        { status = PEAR_FEX_STALE_IDENTITY; break; }
        if (owner.backend.query(e->offset + (q->operation_offset & ~(PAGE-1)), PAGE, PEAR_FEX_PROTECTION_RX, &error))
        { status = PEAR_FEX_NATIVE_FAILURE; break; }
        x->allocation_id = e->id; x->generation = e->generation; x->epoch = e->epoch;
        x->state = PEAR_FEX_MANAGED_ACTIVE; reply(r, e, x, q->continuation_id);
        r->effective_protection = PEAR_FEX_PROTECTION_RX; break;
    case PEAR_FEX_EXECUTOR_RESUME:
    {
        struct owner_descriptor *d;
        uint64_t original_epoch;
        if (!(d = resume_descriptor(q, x, e, c)))
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        original_epoch = c->epoch;
        if (e->epoch != q->write_epoch) { status = PEAR_FEX_STALE_IDENTITY; break; }
        if (owner.gate_closed && (status = park(x, &error)) != PEAR_FEX_OK) break;
        /* A park may release the mutex. Resolve every actual identity again,
         * retaining the original pin until all native checks have completed. */
        x = executor(q->executor_id); e = extent(q);
        c = x && e ? continuation(q->continuation_id, x, e) : NULL;
        if (!(d = resume_descriptor(q, x, e, c)) || c->epoch != original_epoch)
        { status = PEAR_FEX_STALE_IDENTITY; break; }
        if (e->epoch != q->write_epoch) { status = PEAR_FEX_STALE_IDENTITY; break; }
        if (!owner.backend.entry(e->offset, usable(e), q->operation_offset, e->allocation_class, e->role))
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        if (owner.backend.query(e->offset + (q->operation_offset & ~(PAGE-1)), PAGE,
                                PEAR_FEX_PROTECTION_RX, &error))
        { status = PEAR_FEX_NATIVE_FAILURE; break; }
        /* Atomic commit: no fallible observation, mapping, allocation or wait
         * follows. Existing dispatch releases its already-owned mutex. */
        memset(c, 0, sizeof(*c)); memset(d, 0, sizeof(*d));
        x->continuation = 0; x->allocation_id = e->id; x->generation = e->generation;
        x->epoch = e->epoch; x->state = PEAR_FEX_MANAGED_ACTIVE;
        reply(r, e, x, 0); r->effective_protection = PEAR_FEX_PROTECTION_RX;
        break;
    }
    case PEAR_FEX_EXECUTOR_EXIT:
        if (!e || q->expected_state != PEAR_FEX_PUBLISHED_RX || q->write_epoch != e->epoch ||
            x->state != PEAR_FEX_MANAGED_ACTIVE || x->allocation_id != e->id || x->generation != e->generation ||
            x->epoch != q->write_epoch || x->continuation)
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        for (i = 0; i < PEAR_FEX_MEMORY_MAX_CONTINUATIONS; ++i)
            if (owner.continuations[i].id && owner.continuations[i].executor == x->id)
            { status = PEAR_FEX_INVALID_REQUEST; goto done; }
        x->state = PEAR_FEX_NATIVE_IDLE; x->allocation_id = x->generation = x->epoch = 0;
        pthread_cond_broadcast(&owner_condition); reply(r, e, x, 0); break;
    case PEAR_FEX_CONTINUATION_PIN: case PEAR_FEX_EXECUTOR_HANDOFF:
        if (q->opcode == PEAR_FEX_EXECUTOR_HANDOFF && !q->operation_size)
        {
            struct owner_descriptor *d = NULL;
            /* Poll the existing NX handoff only. A size-four nested handoff
             * remains invalid and this path creates no descriptor or pin. */
            if (!e || !c || e->state != PEAR_FEX_PUBLISHED_RX ||
                q->expected_state != PEAR_FEX_PUBLISHED_RX ||
                q->write_epoch != c->epoch || x->state != PEAR_FEX_NATIVE_PINNED ||
                x->continuation != c->id || x->allocation_id != e->id ||
                x->generation != e->generation || x->epoch != c->epoch ||
                q->operation_offset != c->offset)
            { status = PEAR_FEX_INVALID_REQUEST; break; }
            for (i = 0; i < PEAR_FEX_MEMORY_MAX_DESCRIPTORS; ++i)
                if (owner.descriptors[i].executor == x->id) { d = &owner.descriptors[i]; break; }
            if (!d || d->continuation != c->id || d->allocation_id != e->id ||
                d->generation != e->generation || d->epoch != c->epoch || d->offset != c->offset)
            { status = PEAR_FEX_INVALID_REQUEST; break; }
            status = park(x, &error);
            if (status == PEAR_FEX_OK) reply(r, e, x, c->id);
            break;
        }
        if (!e || e->state != PEAR_FEX_PUBLISHED_RX || q->expected_state != e->state || q->write_epoch != e->epoch ||
            q->operation_size != 4 || q->operation_offset & 3 || !range(q->operation_offset, 4, usable(e)) ||
            (x->state != PEAR_FEX_MANAGED_ACTIVE && (q->opcode != PEAR_FEX_CONTINUATION_PIN || x->state != PEAR_FEX_NATIVE_PINNED)) ||
            x->allocation_id != e->id || x->generation != e->generation || x->epoch != q->write_epoch ||
            !owner.backend.entry(e->offset, usable(e), q->operation_offset, e->allocation_class, e->role))
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        if (q->opcode == PEAR_FEX_EXECUTOR_HANDOFF)
        {
            for (i = 0; i < PEAR_FEX_MEMORY_MAX_DESCRIPTORS; ++i)
                if (owner.descriptors[i].executor == x->id) { status = PEAR_FEX_INVALID_REQUEST; goto done; }
            for (i = 0; i < PEAR_FEX_MEMORY_MAX_DESCRIPTORS; ++i) if (!owner.descriptors[i].executor) break;
            if (i == PEAR_FEX_MEMORY_MAX_DESCRIPTORS) { status = PEAR_FEX_CAPACITY; break; }
        }
        if (!c)
        {
            for (i = 0; i < PEAR_FEX_MEMORY_MAX_CONTINUATIONS; ++i) if (!owner.continuations[i].id) break;
            if (i == PEAR_FEX_MEMORY_MAX_CONTINUATIONS || owner.identity == UINT64_MAX)
            { status = PEAR_FEX_CAPACITY; break; }
            c = &owner.continuations[i];
            *c = (struct owner_continuation){fresh(&owner.identity), x->id, e->id, e->generation, e->epoch, q->operation_offset};
        }
        if (c->offset != q->operation_offset) { status = PEAR_FEX_INVALID_REQUEST; break; }
        if (q->opcode == PEAR_FEX_EXECUTOR_HANDOFF)
        {
            struct owner_descriptor *d;
            for (i = 0; i < PEAR_FEX_MEMORY_MAX_DESCRIPTORS; ++i)
                if (owner.descriptors[i].executor == x->id) { status = PEAR_FEX_INVALID_REQUEST; goto done; }
            for (i = 0; i < PEAR_FEX_MEMORY_MAX_DESCRIPTORS; ++i) if (!owner.descriptors[i].executor) break;
            if (i == PEAR_FEX_MEMORY_MAX_DESCRIPTORS) { status = PEAR_FEX_CAPACITY; break; }
            d = &owner.descriptors[i];
            *d = (struct owner_descriptor){x->id, c->id, e->id, e->generation, e->epoch, q->operation_offset};
            x->continuation = c->id; x->state = PEAR_FEX_NATIVE_PINNED;
            pthread_cond_broadcast(&owner_condition);
            if (owner.gate_closed && (status = park(x, &error)) != PEAR_FEX_OK) break;
        }
        reply(r, e, x, c->id); break;
    case PEAR_FEX_CONTINUATION_UNPIN:
        if (!e || !c || q->write_epoch != c->epoch || q->expected_state != e->state ||
            (e->state != PEAR_FEX_PUBLISHED_RX && e->state != PEAR_FEX_RETIRING) ||
            x->state == PEAR_FEX_MANAGED_ACTIVE || x->state == PEAR_FEX_PARKED)
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        if (x->continuation == c->id) x->continuation = 0;
        for (i = 0; i < PEAR_FEX_MEMORY_MAX_DESCRIPTORS; ++i)
            if (owner.descriptors[i].continuation == c->id) memset(&owner.descriptors[i], 0, sizeof(owner.descriptors[i]));
        memset(c, 0, sizeof(*c));
        if (!x->continuation) { x->state = PEAR_FEX_NATIVE_IDLE; x->allocation_id = x->generation = x->epoch = 0; }
        reply(r, e, x, 0); break;
    case PEAR_FEX_EXECUTOR_UNREGISTER:
        if (x->state != PEAR_FEX_NATIVE_IDLE || x->continuation || x->allocation_id ||
            owner.write.executor == x->id)
        { status = PEAR_FEX_INVALID_REQUEST; break; }
        for (i = 0; i < PEAR_FEX_MEMORY_MAX_CONTINUATIONS; ++i)
            if (owner.continuations[i].id && owner.continuations[i].executor == x->id)
            { status = PEAR_FEX_INVALID_REQUEST; goto done; }
        for (i = 0; i < PEAR_FEX_MEMORY_MAX_DESCRIPTORS; ++i)
            if (owner.descriptors[i].executor == x->id) { status = PEAR_FEX_INVALID_REQUEST; goto done; }
        x->diagnostic_host = x->diagnostic_start_lo = x->diagnostic_start_hi = 0;
        x->diagnostic_valid = 0;
        x->state = PEAR_FEX_UNREGISTERED; reply(r, NULL, x, 0); break;
    default: status = PEAR_FEX_INVALID_REQUEST;
    }
 done:
    if (abort_observation_enabled && q->opcode==PEAR_FEX_ABORT_WRITE &&
        status==PEAR_FEX_QUARANTINED && abort_reason && abort_observation_count<8) {
        ++abort_observation_count; abort_present=1;
    d.pid = (*q).owner_pid;
    d.executor = (*q).executor_id;
    d.allocation = (*q).allocation_id;
    d.generation = (*q).generation;
    d.extent = (*q).extent_offset;
    d.size = (*q).extent_size;
    d.epoch = (*q).write_epoch;
    d.expected = (*q).expected_state;
    d.aclass = (*q).allocation_class;
    d.role = (*q).ec_role;
    d.continuation = (*q).continuation_id;
        d.reason=abort_reason; d.previous=abort_previous; d.previous_known=abort_previous_known;
        d.status=status; d.domain=error.domain; d.code=error.domain ? error.code : 0;
    }
    if (status != PEAR_FEX_OK) fail(r, status, error.domain ? &error : NULL);
    pthread_mutex_unlock(&owner_mutex);
    emit_timeout(&snapshot);
    emit_registration(&registration);
    emit_abort(&d,abort_present);
    return status;
}
