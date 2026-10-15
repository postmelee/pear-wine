/* Original Pear finite Stage 5 fixture protocol. SPDX-License-Identifier: MIT. */
#ifndef PEAR_STAGE5_PROTOCOL_H
#define PEAR_STAGE5_PROTOCOL_H
#include <stdint.h>
#define PEAR_STAGE5_MAGIC UINT64_C(0x5045415253350001)
#define PEAR_STAGE5_MESSAGE (0x8000u + 0x351u)
#define PEAR_STAGE5_CYCLES 20u
#define PEAR_STAGE5_TOKEN(cycle) (UINT64_C(0x53350000) + (cycle))
#define PEAR_STAGE5_REPLY(token) ((token) ^ UINT64_C(0x13579bdf))
#define PEAR_STAGE5_PENDING UINT32_C(0x103)
#define PEAR_STAGE5_WAKE_SUBTYPE 0x5335u
#define PEAR_STAGE5_WAKE_TAG UINT64_C(0x505335)
/* Native event values stay below 2^53; Cocoa data2 contains only cycle/turn. */
#define PEAR_STAGE5_WAKE_PAYLOAD(cycle,ordinal) (((uint64_t)(cycle)<<8)|(uint64_t)(ordinal))
#define PEAR_STAGE5_WAKE_VALUE(cycle,ordinal) ((PEAR_STAGE5_WAKE_TAG<<24)|PEAR_STAGE5_WAKE_PAYLOAD(cycle,ordinal))
enum pear_s5_operation { PEAR_S5_INIT=1, PEAR_S5_ARM, PEAR_S5_FIRE,
    PEAR_S5_REENTRY, PEAR_S5_DRAIN, PEAR_S5_FINAL };
enum pear_s5_phase { PEAR_S5_INITIALIZED=0, PEAR_S5_CREATED=1, PEAR_S5_ARMED,
    PEAR_S5_TRIGGERED, PEAR_S5_CLOSE_REQUESTED, PEAR_S5_DISPATCHED,
    PEAR_S5_REENTERED, PEAR_S5_TITLE_CHANGED, PEAR_S5_CALLBACK_RETURNED,
    PEAR_S5_DESTROYED, PEAR_S5_COCOA_DESTROYED, PEAR_S5_DISCARDED,
    PEAR_S5_DEALLOCATED, PEAR_S5_BARRIER, PEAR_S5_DRAINED,
    PEAR_S5_COMPLETED, PEAR_S5_FINALIZED, PEAR_S5_WAKE_POSTED,
    PEAR_S5_WAKE_CONSUMED, PEAR_S5_FINAL_DRAIN };
/* All wire fields are unsigned 64-bit integers; addresses stay private.
 * native_tid is the Wine/Windows thread ID observed on the Unix side.
 * Native event thread_id is separately measured with pthread_threadid_np.
 * Counters in a cycle response are per-cycle; FINAL returns their sums. */
typedef struct pear_s5_request {
    uint64_t magic,version,operation,cycle,hwnd,token,guest_teb,guest_tid;
    uint64_t host_entry,host_exit,native_pid,native_tid,teb,driver_base,driver_entry;
    uint64_t window,queue,created,armed,triggered,cocoa_close,dispatched;
    uint64_t reentered,title_changed,callback_returned,destroyed,cocoa_destroyed;
    uint64_t discarded,deallocated,barriers,drains,late,errors,completed,active;
    uint64_t callback_result;
} pear_s5_request;
#ifdef WINE_UNIX_LIB
/* Scalar native snapshot. queue_total contributes to the finite idle check;
 * the other ownership fields remain private diagnostics. */
struct pear_s5_diag_snapshot {
    uint64_t main_thread,app_windows,app_target,key_windows,key_target;
    uint64_t dragged_windows,dragged_target,capture_target,last_mouse_target;
    uint64_t app_event_type,app_event_target,close_observer_hits,pending_main_requests;
    uint64_t queue_total,queue_target,queue_target_event_refs,queue_target_query_refs;
    uint64_t wine_event_present,wine_event_type,wine_event_target,wine_event_refs;
    uint64_t queue_matches,deallocated,fd_empty;
};
void pear_stage5_diag_app(uintptr_t,struct pear_s5_diag_snapshot *);
void pear_stage5_queue_snapshot(void *,uintptr_t,struct pear_s5_diag_snapshot *);
int pear_stage5_post_wake(uint64_t);
void pear_stage5_window_wake_consumed(unsigned,intptr_t,intptr_t,intptr_t);
void pear_stage5_window_diagnostic_closed(void *);
void pear_stage5_window_diagnostic_deallocating(void *);
void pear_stage5_window_create_begin(void *);
void pear_stage5_window_created(void *,void *,void *);
void pear_stage5_window_close_requested(void *);
void pear_stage5_window_dispatch(void *,void *);
void pear_stage5_window_any_event(void *);
void pear_stage5_window_title_changed(void *,const void *);
void pear_stage5_window_destroy_begin(void *);
void pear_stage5_window_cocoa_destroyed(void *);
void pear_stage5_window_discarded(void *);
void pear_stage5_window_deallocated(void *);
#endif
#endif
