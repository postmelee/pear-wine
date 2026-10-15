/* SPDX-License-Identifier: MIT */
/* Diagnostic snapshot only; no runtime service or ownership ABI. */
struct pear_query_context
{
    ULONG64 pc, lr;
    ULONG syscall_id, available;
};
extern void pear_get_query_context( struct pear_query_context *context );
