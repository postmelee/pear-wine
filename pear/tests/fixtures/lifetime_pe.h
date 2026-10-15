/* Original Pear Stage 3 fixture protocol, SPDX-License-Identifier: MIT. */
#ifndef PEAR_LIFETIME_PE_H
#define PEAR_LIFETIME_PE_H

typedef LONG (WINAPI *pear_lifetime_callback)(void *, ULONG);
typedef struct pear_lifetime_control {
    HMODULE module;
    pear_lifetime_callback delegate;
    unsigned unload_attempts;
    unsigned held_mapping_checks;
    unsigned error_step;
} pear_lifetime_control;
typedef LONG (WINAPI *pear_lifetime_configure)(pear_lifetime_control *);

#define PEAR_SECURITY_COOKIE_DEFAULT ((ULONG_PTR)0x00002b992ddfa232ULL)

typedef struct pear_relocation_observation {
    ULONG_PTR code_slot, code_pointer, code_address;
    ULONG_PTR data_slot, data_pointer, data_address;
    ULONG before, after, call_result;
    ULONG_PTR security_cookie_address, security_cookie;
} pear_relocation_observation;
typedef LONG (WINAPI *pear_relocation_probe)(pear_relocation_observation *, ULONG);
#endif
