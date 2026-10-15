/* Original Pear Stage 3 fixture, SPDX-License-Identifier: MIT.
 * Windows ARM64 caller: preserve the real TEB in x18. The sole call is the
 * actual Wine Unix dispatcher, including nested guest callback invocations.
 * Return low 32 bits NTSTATUS, high 32 bits failed-register mask.
 */
#if !defined(_WIN32) || !defined(__aarch64__) || defined(__arm64ec__)
#error The ABI gateway requires an ordinary ARM64 Windows PE target.
#endif
.text
.p2align 2
.globl pear_abi_gateway
.def pear_abi_gateway; .scl 2; .type 32; .endef
.seh_proc pear_abi_gateway
pear_abi_gateway:
    sub sp, sp, #224
    .seh_stackalloc 224
    stp x29, x30, [sp, #0]
    .seh_save_fplr 0
    stp x19, x20, [sp, #16]
    .seh_save_regp x19, 16
    stp x21, x22, [sp, #32]
    .seh_save_regp x21, 32
    stp x23, x24, [sp, #48]
    .seh_save_regp x23, 48
    stp x25, x26, [sp, #64]
    .seh_save_regp x25, 64
    stp x27, x28, [sp, #80]
    .seh_save_regp x27, 80
    stp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    stp d10, d11, [sp, #112]
    .seh_save_fregp d10, 112
    stp d12, d13, [sp, #128]
    .seh_save_fregp d12, 128
    stp d14, d15, [sp, #144]
    .seh_save_fregp d14, 144
    .seh_endprologue
    mov x29, sp
    stp x18, x3, [sp, #160]
    stp x2, x0, [sp, #176]
    str x1, [sp, #192]
    add x19, x3, #19
    add x20, x3, #20
    add x21, x3, #21
    add x22, x3, #22
    add x23, x3, #23
    add x24, x3, #24
    add x25, x3, #25
    add x26, x3, #26
    add x27, x3, #27
    add x28, x3, #28
    .macro SET_D reg, offset
    add x9, x3, #\offset
    fmov \reg, x9
    .endm
    SET_D d8, 108
    SET_D d9, 109
    SET_D d10, 110
    SET_D d11, 111
    SET_D d12, 112
    SET_D d13, 113
    SET_D d14, 114
    SET_D d15, 115
    mov x16, x0
    mov x0, x1
    mov w1, #8
    /* x2 is the request passed through Wine's Unix dispatcher. */
    blr x16
    str w0, [sp, #200]
    mov w10, #0
    ldr x3, [sp, #168]
    .macro CHECK_X reg, offset, bit
    add x9, x3, #\offset
    cmp \reg, x9
    cset w11, ne
    orr w10, w10, w11, lsl #\bit
    .endm
    CHECK_X x19, 19, 0
    CHECK_X x20, 20, 1
    CHECK_X x21, 21, 2
    CHECK_X x22, 22, 3
    CHECK_X x23, 23, 4
    CHECK_X x24, 24, 5
    CHECK_X x25, 25, 6
    CHECK_X x26, 26, 7
    CHECK_X x27, 27, 8
    CHECK_X x28, 28, 9
    .macro CHECK_D reg, offset, bit
    add x9, x3, #\offset
    fmov x12, \reg
    cmp x12, x9
    cset w11, ne
    orr w10, w10, w11, lsl #\bit
    .endm
    CHECK_D d8, 108, 10
    CHECK_D d9, 109, 11
    CHECK_D d10, 110, 12
    CHECK_D d11, 111, 13
    CHECK_D d12, 112, 14
    CHECK_D d13, 113, 15
    CHECK_D d14, 114, 16
    CHECK_D d15, 115, 17
    ldr x9, [sp, #160]
    cmp x18, x9
    cset w11, ne
    orr w10, w10, w11, lsl #18
    mov x9, sp
    cmp x29, x9
    cset w11, ne
    orr w10, w10, w11, lsl #19
    ldr w0, [sp, #200]
    orr x0, x0, x10, lsl #32
    .seh_startepilogue
    ldp d14, d15, [sp, #144]
    .seh_save_fregp d14, 144
    ldp d12, d13, [sp, #128]
    .seh_save_fregp d12, 128
    ldp d10, d11, [sp, #112]
    .seh_save_fregp d10, 112
    ldp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    ldp x27, x28, [sp, #80]
    .seh_save_regp x27, 80
    ldp x25, x26, [sp, #64]
    .seh_save_regp x25, 64
    ldp x23, x24, [sp, #48]
    .seh_save_regp x23, 48
    ldp x21, x22, [sp, #32]
    .seh_save_regp x21, 32
    ldp x19, x20, [sp, #16]
    .seh_save_regp x19, 16
    ldp x29, x30, [sp, #0]
    .seh_save_fplr 0
    add sp, sp, #224
    .seh_stackalloc 224
    .seh_endepilogue
    ret
.seh_endproc
