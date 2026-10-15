/* Original Pear Stage 4 fixture protocol. SPDX-License-Identifier: MIT. */
#ifndef PEAR_STAGE4_PROTOCOL_H
#define PEAR_STAGE4_PROTOCOL_H
#include <stdint.h>
#include <stddef.h>
#define PEAR_STAGE4_MAGIC UINT64_C(0x5045415253544734)
#define PEAR_STAGE4_INDEX 9
#define PEAR_STAGE4_SENTINEL UINT64_C(0x3456789a)
#define PEAR_STAGE4_ERROR UINT32_C(0xc0000001)
enum { PEAR_S4_INIT, PEAR_S4_REGISTER, PEAR_S4_ARM, PEAR_S4_SEND,
       PEAR_S4_HOST_WAIT, PEAR_S4_SNAPSHOT, PEAR_S4_ERROR, PEAR_S4_DISARM };
enum { PEAR_S4_GUEST = 1, PEAR_S4_HOST = 2, PEAR_S4_SUSPEND = 3 };
typedef struct pear_s4_signal {
    uint64_t phase, before_count, after_count, signal_number;
    uint64_t entry_mode, handler_mode, return_mode;
    uint64_t before_pc, after_pc, before_x18, after_x18, before_x19, after_x19;
    uint64_t before_sp, after_sp, bad;
} pear_s4_signal;
typedef struct pear_s4_request {
    uint64_t magic, version, operation, slot, phase, guest_teb, guest_tid;
    uint64_t guest_begin, guest_end, host_entry, host_exit, native_pid;
    uint64_t registered, init_seen, init_host_mode, init_tls_matches;
    /* native_tid is Wine data->tid observed in the native half, not a Darwin thread ID. */
    uint64_t native_tid, native_teb, guest_stack_low, guest_stack_high;
    uint64_t kernel_stack_low, kernel_stack_high, host_begin, host_end;
    uint64_t send_status, native_exit_seen, native_exit_mode, ready, error, ntdll_base;
    pear_s4_signal observation;
} pear_s4_request;
_Static_assert(sizeof(pear_s4_signal) == 128, "Fixed signal observation size");
_Static_assert(sizeof(pear_s4_request) == 368, "Fixed Stage 4 request size");
#if defined(_WIN32)
int pear_emit(const char *, const char *const *, const uint64_t *, unsigned);
int pear_exception_initialize(void);
int pear_exception_checks(void);
int pear_exception_finish(void);
int pear_expect_memory_fault(volatile unsigned char *, unsigned, unsigned);
int pear_memory_checks(void);
void pear_guest_spin(volatile long *, volatile long *, uint64_t);
extern const unsigned char pear_guest_spin_begin[], pear_guest_spin_end[];
unsigned pear_fault_read(volatile unsigned char *);
unsigned pear_fault_write(volatile unsigned char *);
extern const unsigned char pear_fault_read_pc[], pear_fault_read_recovery[];
extern const unsigned char pear_fault_write_pc[], pear_fault_write_recovery[];
unsigned pear_raise_software(void *);
int pear_exception_fatal(uint64_t);
#endif
#endif
