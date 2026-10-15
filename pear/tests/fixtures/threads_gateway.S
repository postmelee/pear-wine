/* Original Pear controlled ARM64 fixture leaves. SPDX-License-Identifier: MIT. */
#if !defined(_WIN32) || !defined(__aarch64__) || defined(__arm64ec__)
#error Ordinary Windows ARM64 is required.
#endif
.text
.p2align 2
.globl pear_guest_spin
.globl pear_guest_spin_begin
.globl pear_guest_spin_end
.def pear_guest_spin; .scl 2; .type 32; .endef
.seh_proc pear_guest_spin
pear_guest_spin:
    str x19, [sp, #-16]!
    .seh_save_reg_x x19, 16
    .seh_endprologue
    mov x19, x2
    mov w3, #1
    stlr w3, [x0]
pear_guest_spin_begin:
    ldar w3, [x1]
    cbz w3, pear_guest_spin_begin
pear_guest_spin_end:
    .seh_startepilogue
    ldr x19, [sp], #16
    .seh_save_reg_x x19, 16
    .seh_endepilogue
    ret
.seh_endproc

.macro FAULT_LEAF name, write
.globl \name
.globl \name\()_pc
.globl \name\()_recovery
.def \name; .scl 2; .type 32; .endef
.seh_proc \name
\name:
    str x19, [sp, #-16]!
    .seh_save_reg_x x19, 16
    .seh_endprologue
    movz x19, #0x789a
    movk x19, #0x3456, lsl #16
    mov w1, #0x63
\name\()_pc:
.if \write
    strb w1, [x0]
.else
    ldrb w1, [x0]
.endif
\name\()_recovery:
    mov w0, #0x5a
    .seh_startepilogue
    ldr x19, [sp], #16
    .seh_save_reg_x x19, 16
    .seh_endepilogue
    ret
.seh_endproc
.endm
FAULT_LEAF pear_fault_read, 0
FAULT_LEAF pear_fault_write, 1

.globl pear_raise_software
.def pear_raise_software; .scl 2; .type 32; .endef
.seh_proc pear_raise_software
pear_raise_software:
    stp x29, x30, [sp, #-32]!
    .seh_save_fplr_x 32
    str x19, [sp, #16]
    .seh_save_reg x19, 16
    .seh_endprologue
    mov x16, x0
    movz x19, #0x789a
    movk x19, #0x3456, lsl #16
    movz w0, #0x4401
    movk w0, #0xe042, lsl #16
    mov w1, #0
    mov w2, #0
    mov x3, #0
    blr x16
    movz x4, #0x789a
    movk x4, #0x3456, lsl #16
    cmp x19, x4
    cset w0, eq
    .seh_startepilogue
    ldr x19, [sp, #16]
    .seh_save_reg x19, 16
    ldp x29, x30, [sp], #32
    .seh_save_fplr_x 32
    .seh_endepilogue
    ret
.seh_endproc

.section .drectve,"yn"
.ascii " -export:pear_guest_spin_begin -export:pear_guest_spin_end -export:pear_fault_read_pc -export:pear_fault_read_recovery -export:pear_fault_write_pc -export:pear_fault_write_recovery"
