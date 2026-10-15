/* Original Pear Stage 4 finite exception fixture. SPDX-License-Identifier: MIT. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "stage4_protocol.h"
#define PEAR_SOFTWARE_CODE UINT32_C(0xe0424401)
#define PEAR_ACCESS_CODE UINT32_C(0xc0000005)
#define PEAR_GUARD_CODE UINT32_C(0x80000001)
static void *first_handler, *second_handler;
static struct {
    uint64_t active, kind, code, operation, address, fault_pc, recovery_pc, teb;
    uint64_t first, second, order, bad, fatal, sequence;
    uint64_t observed_code, observed_address, observed_pc, observed_access;
    uint64_t observed_x18, observed_x19, observed_sp, exception_pc, continued;
    uint64_t observed_x0, context_flags, exception_flags, parameters;
} expectation;
static uint64_t sequence;
static uint64_t current_teb(void) { uint64_t value; __asm__ volatile("mov %0, x18" : "=r"(value)); return value; }
static int exception_event(const char *kind)
{
    static const char *const names[] = {"sequence","kind","expected_code","operation","address","fault_pc","recovery_pc","teb",
        "first_count","second_count","order","error","code","fault_address","context_pc","access_kind",
        "context_x18","context_x19","context_sp","exception_pc","continued","context_x0","context_flags","exception_flags","parameters","module_base"};
    uint64_t values[] = {expectation.sequence,expectation.kind,expectation.code,expectation.operation,expectation.address,expectation.fault_pc,
        expectation.recovery_pc,expectation.teb,expectation.first,expectation.second,expectation.order,expectation.bad,expectation.observed_code,
        expectation.observed_address,expectation.observed_pc,expectation.observed_access,expectation.observed_x18,expectation.observed_x19,
        expectation.observed_sp,expectation.exception_pc,expectation.continued,expectation.observed_x0,expectation.context_flags,
        expectation.exception_flags,expectation.parameters,(uintptr_t)GetModuleHandleW(NULL)};
    return pear_emit(kind,names,values,sizeof(values)/sizeof(*values));
}
static LONG WINAPI audit_handler(EXCEPTION_POINTERS *p)
{
    if (!expectation.active) return EXCEPTION_CONTINUE_SEARCH;
    EXCEPTION_RECORD *r = p->ExceptionRecord; CONTEXT *c = p->ContextRecord;
    ++expectation.first;
    if (expectation.order || expectation.first != 1) expectation.bad |= 1;
    expectation.order = expectation.order * 10 + 1;
    expectation.observed_code = r->ExceptionCode;
    expectation.observed_pc = c->Pc; expectation.exception_pc = (uintptr_t)r->ExceptionAddress;
    expectation.observed_x0=c->X0; expectation.context_flags=c->ContextFlags; expectation.exception_flags=r->ExceptionFlags; expectation.parameters=r->NumberParameters;
    expectation.observed_x18 = c->X18; expectation.observed_x19 = c->X19; expectation.observed_sp = c->Sp;
    if (r->ExceptionCode != expectation.code || r->ExceptionFlags || c->X18 != expectation.teb ||
        (expectation.kind!=1 && c->X19 != PEAR_STAGE4_SENTINEL) || !c->Pc || (c->Sp & 15)) expectation.bad |= 2;
    if (expectation.kind == 1) {
        if (r->NumberParameters) expectation.bad |= 4;
    } else {
        expectation.observed_access = r->NumberParameters > 0 ? r->ExceptionInformation[0] : UINT64_MAX;
        expectation.observed_address = r->NumberParameters > 1 ? r->ExceptionInformation[1] : 0;
        if (r->NumberParameters != 2 || expectation.observed_address != expectation.address ||
            expectation.observed_access != expectation.operation || c->X0 != expectation.address ||
            c->Pc != expectation.fault_pc || (uintptr_t)r->ExceptionAddress != expectation.fault_pc) expectation.bad |= 8;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
static LONG WINAPI recovery_handler(EXCEPTION_POINTERS *p)
{
    if (!expectation.active) return EXCEPTION_CONTINUE_SEARCH;
    ++expectation.second;
    if (expectation.order != 1 || expectation.second != 1) expectation.bad |= 16;
    expectation.order = expectation.order * 10 + 2;
    if (expectation.bad) { exception_event("pear_exception_event"); ExitProcess(96); }
    if (expectation.fatal) {
        if (!exception_event("pear_stage4_child_fault")) ExitProcess(90);
        TerminateProcess(GetCurrentProcess(),PEAR_ACCESS_CODE);
        ExitProcess(97);
    }
    if (expectation.kind != 1 && expectation.code != PEAR_GUARD_CODE)
        p->ContextRecord->Pc = expectation.recovery_pc;
    return EXCEPTION_CONTINUE_EXECUTION;
}
static void prepare(unsigned kind, unsigned code, unsigned operation, uintptr_t address)
{
    uint64_t *fields = (uint64_t *)&expectation;
    for (unsigned i=0;i<sizeof(expectation)/sizeof(*fields);++i) fields[i]=0;
    expectation.kind=kind; expectation.code=code; expectation.operation=operation;
    expectation.address=address; expectation.teb=current_teb(); expectation.sequence=++sequence;
    expectation.fault_pc=(uintptr_t)(operation ? pear_fault_write_pc : pear_fault_read_pc);
    expectation.recovery_pc=(uintptr_t)(operation ? pear_fault_write_recovery : pear_fault_read_recovery);
    if (kind==1) expectation.fault_pc=expectation.recovery_pc=0;
    expectation.active=1;
}
int pear_exception_initialize(void)
{
    first_handler=AddVectoredExceptionHandler(1,audit_handler);
    if (!first_handler) return 1;
    second_handler=AddVectoredExceptionHandler(0,recovery_handler);
    if (!second_handler) { if(RemoveVectoredExceptionHandler(first_handler)) first_handler=NULL; return 2; }
    return 0;
}
int pear_expect_memory_fault(volatile unsigned char *address,unsigned operation,unsigned expected_code)
{
    if (!first_handler || !second_handler || operation>1 ||
        (expected_code!=PEAR_ACCESS_CODE && expected_code!=PEAR_GUARD_CODE)) return 1;
    prepare(expected_code==PEAR_GUARD_CODE ? 4 : operation ? 3 : 2,expected_code,operation,(uintptr_t)address);
    unsigned result=operation ? pear_fault_write(address) : pear_fault_read(address);
    expectation.active=0;
    expectation.continued=result==0x5a && current_teb()==expectation.teb;
    int passed=!expectation.bad && expectation.first==1 && expectation.second==1 && expectation.order==12 && expectation.continued;
    if (!exception_event("pear_exception_event")) return 3;
    return passed ? 0 : 2;
}
int pear_exception_checks(void)
{
    if (!first_handler || !second_handler) return 1;
    prepare(1,PEAR_SOFTWARE_CODE,0,0);
    unsigned continued=pear_raise_software((void *)RaiseException);
    expectation.active=0; expectation.continued=continued==1 && current_teb()==expectation.teb;
    int passed=!expectation.bad && expectation.first==1 && expectation.second==1 && expectation.order==12 && expectation.continued;
    if (!exception_event("pear_exception_event") || !passed) return 2;
    unsigned char *page=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
    if (!page) return 3;
    static const char *const region_names[]={"base","size","offset"};
    uint64_t region_values[]={(uintptr_t)page,4096,37};
    if(!pear_emit("pear_exception_region",region_names,region_values,3)){VirtualFree(page,0,MEM_RELEASE);return 5;}
    int result=pear_expect_memory_fault(page+37,0,PEAR_ACCESS_CODE);
    int released=VirtualFree(page,0,MEM_RELEASE);
    static const char *const cleanup_names[]={"released","operation_error"};
    uint64_t cleanup_values[]={released,(unsigned)result};
    if(!pear_emit("pear_exception_cleanup",cleanup_names,cleanup_values,2) && !result) result=6;
    if(!released && !result) result=4;
    return result;
}
int pear_exception_finish(void)
{
    int result=0;
    expectation.active=0;
    if (second_handler && !RemoveVectoredExceptionHandler(second_handler)) result=1;
    if (first_handler && !RemoveVectoredExceptionHandler(first_handler)) result=1;
    second_handler=first_handler=NULL;
    return result;
}
int pear_exception_fatal(uint64_t native_pid)
{
    unsigned char *page=VirtualAlloc(NULL,4096,MEM_RESERVE|MEM_COMMIT,PAGE_NOACCESS);
    if (!page || pear_exception_initialize()) return 1;
    prepare(5,PEAR_ACCESS_CODE,0,(uintptr_t)(page+53)); expectation.fatal=1;
    static const char *const names[]={"guest_pid","native_pid","teb","module_base","fault_pc","recovery_pc","address","expected_code","region_base","region_size","region_offset"};
    uint64_t values[]={GetCurrentProcessId(),native_pid,current_teb(),(uintptr_t)GetModuleHandleW(NULL),expectation.fault_pc,
        expectation.recovery_pc,expectation.address,PEAR_ACCESS_CODE,(uintptr_t)page,4096,53};
    if (!pear_emit("pear_stage4_child_ready",names,values,11)) return 2;
    pear_fault_read(page+53);
    return 3;
}
