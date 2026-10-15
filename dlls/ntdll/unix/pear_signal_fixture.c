/* Original Pear Stage 4 native fixture. SPDX-License-Identifier: MIT.
 * Executed only through Wine's ordinary Unix dispatcher. Signal observations
 * use two preallocated slots and lock-free publication; no signal formatting,
 * allocation, TLS lookup or extra POSIX call is introduced by the observer. */
#if 0
#pragma makedep unix
#endif
#include "config.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <dlfcn.h>
#include "ntstatus.h"
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "unix_private.h"
#include "wine/asm.h"
#include "stage4_protocol.h"
#include "wine/pear_bootstrap.h"
#if defined(__APPLE__) && defined(__aarch64__)
#include <sys/ucontext.h>
extern unsigned char (*pear_x18_getter)(void);
_Static_assert(__atomic_always_lock_free(8,0), "Observer publication requires lock-free 64-bit operations");
_Static_assert(__atomic_always_lock_free(4,0), "Observer flags require lock-free 32-bit operations");
struct init_record { uint64_t teb,tid,mode,tls_match,complete; };
struct fixture_slot {
    uint64_t registered,armed,teb,tid,guest_low,guest_high,kernel_low,kernel_high;
    uint64_t guest_begin,guest_end,exit_seen,exit_mode,init_seen,init_mode,init_tls_match,ntdll_base;
    unsigned reported;
    pthread_t thread;
    uint32_t ready,release;
    pear_s4_signal observation;
};
static struct fixture_slot slots[2];
static struct init_record initial[32];
static unsigned initial_count;
static unsigned enabled;
extern int pear_stage4_host_spin(volatile uint32_t *,volatile uint32_t *);
extern const unsigned char pear_stage4_host_begin[],pear_stage4_host_end[];
__ASM_GLOBAL_FUNC(pear_stage4_host_spin,
    "mov w3, #1\n\t"
    "mov x4, #0x80000000\n\t"
    ".globl _pear_stage4_host_begin\n"
    ".set _pear_stage4_host_begin, Lpear_stage4_host_begin\n"
    "Lpear_stage4_host_begin:\n\t"
    "stlr w3, [x0]\n"
    "1: ldar w3, [x1]\n\t"
    "cbnz w3, 2f\n\t"
    "subs x4, x4, #1\n\t"
    "b.ne 1b\n\t"
    ".globl _pear_stage4_host_end\n"
    ".set _pear_stage4_host_end, Lpear_stage4_host_end\n"
    "Lpear_stage4_host_end:\n\t"
    "mov w0, #1\n\tret\n"
    "2: mov w0, #0\n\tret\n")
/* Existing fixed event headers are at most 252 bytes for these event names,
 * 32-bit process IDs, 64-bit timestamps and the validated 32-character nonce.
 * Each detail part is <=220 bytes, so each complete write fits PIPE_BUF.
 * Numbered fixed parts are reassembled only by the independent run verifier. */
_Static_assert(PIPE_BUF>=512,"Stage 4 diagnostics require POSIX atomic pipe writes");
static void emit_parts(const char *event,unsigned slot,unsigned phase,const char *const *names,const uint64_t *values,unsigned count)
{
    for(unsigned first=0,part=0;first<count;first+=3,++part){
        char detail[221];int length;
        if(phase) length=snprintf(detail,sizeof(detail),",\"slot\":%u,\"phase\":%u,\"part\":%u",slot,phase,part);
        else length=snprintf(detail,sizeof(detail),",\"slot\":%u,\"part\":%u",slot,part);
        if(length<0 || (size_t)length>=sizeof(detail))_exit(125);
        for(unsigned at=first;at<count && at<first+3;++at){
            int added=snprintf(detail+length,sizeof(detail)-length,",\"%s\":%llu",names[at],(unsigned long long)values[at]);
            if(added<0 || (size_t)added>=sizeof(detail)-length)_exit(125);
            length+=added;
        }
        if(length>220)_exit(125);
        pear_bootstrap_event("loader",event,detail);
    }
}
static void emit_registration(unsigned index,const struct fixture_slot *slot)
{
    static const char *const names[]={"teb","native_tid","ntdll_base","guest_begin","guest_end","host_begin","host_end","init_seen","init_host_mode","init_tls_matches"};
    uint64_t values[]={slot->teb,slot->tid,slot->ntdll_base,slot->guest_begin,slot->guest_end,
        (uintptr_t)pear_stage4_host_begin,(uintptr_t)pear_stage4_host_end,slot->init_seen,slot->init_mode,slot->init_tls_match};
    emit_parts("stage4_thread_register",index,0,names,values,10);
}
static void emit_signal(unsigned index,const struct fixture_slot *slot,const pear_s4_signal *o)
{
    static const char *const names[]={"teb","native_tid","ntdll_base","guest_begin","guest_end","host_begin","host_end",
        "before_count","after_count","signal","entry_mode","handler_mode","return_mode","before_pc","after_pc","before_x18","after_x18",
        "before_x19","after_x19","before_sp","after_sp","error"};
    uint64_t values[]={slot->teb,slot->tid,slot->ntdll_base,slot->guest_begin,slot->guest_end,(uintptr_t)pear_stage4_host_begin,
        (uintptr_t)pear_stage4_host_end,o->before_count,o->after_count,o->signal_number,o->entry_mode,o->handler_mode,o->return_mode,
        o->before_pc,o->after_pc,o->before_x18,o->after_x18,o->before_x19,o->after_x19,o->before_sp,o->after_sp,o->bad};
    emit_parts("stage4_signal",index,(unsigned)o->phase,names,values,22);
}

static int environment_ok(void)
{
    const char *flag=getenv("PEAR_WINE_STAGE4_FIXTURE"),*nonce=getenv("PEAR_BOOTSTRAP_NONCE");
    if (!flag || strcmp(flag,"1") || !nonce || strlen(nonce)!=32) return 0;
    for (unsigned i=0;i<32;++i) if (!((nonce[i]>='0' && nonce[i]<='9') || (nonce[i]>='a' && nonce[i]<='f'))) return 0;
    return 1;
}
void pear_stage4_thread_start(struct thread_data *data)
{
    if (!__atomic_load_n(&enabled,__ATOMIC_ACQUIRE) || !data->teb) return;
    unsigned index=__atomic_fetch_add(&initial_count,1,__ATOMIC_RELAXED);
    if (index>=32) return;
    struct init_record *record=&initial[index];
    record->teb=(uintptr_t)data->teb; record->tid=data->tid;
    record->mode=pear_x18_getter ? pear_x18_getter() : UINT64_MAX;
    record->tls_match=get_thread_data()==data;
    __atomic_store_n(&record->complete,1,__ATOMIC_RELEASE);
}
void pear_stage4_thread_exit(struct thread_data *data)
{
    if (!__atomic_load_n(&enabled,__ATOMIC_ACQUIRE) || !data) return;
    for (unsigned i=0;i<2;++i) if (__atomic_load_n(&slots[i].registered,__ATOMIC_ACQUIRE) && slots[i].teb==(uintptr_t)data->teb) {
        slots[i].exit_mode=pear_x18_getter ? pear_x18_getter() : UINT64_MAX;
        if(!slots[i].exit_mode){
            char detail[221];
            int length=snprintf(detail,sizeof(detail),",\"slot\":%u,\"teb\":%llu,\"native_tid\":%llu,\"exit_mode\":%llu",
                i,(unsigned long long)slots[i].teb,(unsigned long long)slots[i].tid,(unsigned long long)slots[i].exit_mode);
            if(length<0 || length>220)_exit(125);
            pear_bootstrap_event("loader","stage4_thread_exit",detail);
        }
        __atomic_store_n(&slots[i].exit_seen,1,__ATOMIC_RELEASE);
    }
}
/* Called only after the existing gateway has entered verified host mode. */
void pear_stage4_signal_before(int sig,unsigned entry_mode,unsigned handler_mode,ucontext_t *context)
{
    if (!__atomic_load_n(&enabled,__ATOMIC_ACQUIRE) || sig!=SIGUSR1) return;
    uint64_t sp=context->uc_mcontext->__ss.__sp;
    for (unsigned i=0;i<2;++i) {
        struct fixture_slot *slot=&slots[i];
        if (!__atomic_load_n(&slot->registered,__ATOMIC_ACQUIRE) || !__atomic_load_n(&slot->armed,__ATOMIC_ACQUIRE)) continue;
        if (!((sp>=slot->guest_low && sp<slot->guest_high) || (sp>=slot->kernel_low && sp<slot->kernel_high))) continue;
        pear_s4_signal *o=&slot->observation;
        if (__atomic_load_n(&o->before_count,__ATOMIC_ACQUIRE)) { __atomic_fetch_or(&o->bad,1,__ATOMIC_RELAXED); return; }
        o->signal_number=sig; o->entry_mode=entry_mode; o->handler_mode=handler_mode;
        o->before_pc=context->uc_mcontext->__ss.__pc; o->before_sp=sp;
        o->before_x18=context->uc_mcontext->__ss.__x[18]; o->before_x19=context->uc_mcontext->__ss.__x[19];
        uint64_t low=o->phase==PEAR_S4_HOST ? (uintptr_t)pear_stage4_host_begin : slot->guest_begin;
        uint64_t high=o->phase==PEAR_S4_HOST ? (uintptr_t)pear_stage4_host_end : slot->guest_end;
        if (o->before_pc<low || o->before_pc>=high || handler_mode ||
            entry_mode!=(o->phase==PEAR_S4_HOST ? 0U : 1U)) __atomic_fetch_or(&o->bad,2,__ATOMIC_RELAXED);
        if (o->phase!=PEAR_S4_HOST && (o->before_x18!=slot->teb || o->before_x19!=PEAR_STAGE4_SENTINEL+i)) __atomic_fetch_or(&o->bad,4,__ATOMIC_RELAXED);
        __atomic_store_n(&o->before_count,1,__ATOMIC_RELEASE);
        return;
    }
}
void pear_stage4_signal_after(int sig,unsigned result_mode,ucontext_t *context)
{
    if (!__atomic_load_n(&enabled,__ATOMIC_ACQUIRE) || sig!=SIGUSR1) return;
    uint64_t sp=context->uc_mcontext->__ss.__sp;
    for (unsigned i=0;i<2;++i) {
        struct fixture_slot *slot=&slots[i];
        if (!__atomic_load_n(&slot->registered,__ATOMIC_ACQUIRE) || !__atomic_load_n(&slot->armed,__ATOMIC_ACQUIRE)) continue;
        if (!((sp>=slot->guest_low && sp<slot->guest_high) || (sp>=slot->kernel_low && sp<slot->kernel_high))) continue;
        pear_s4_signal *o=&slot->observation;
        if (!__atomic_load_n(&o->before_count,__ATOMIC_ACQUIRE) || __atomic_load_n(&o->after_count,__ATOMIC_ACQUIRE)) { __atomic_fetch_or(&o->bad,8,__ATOMIC_RELAXED); return; }
        o->return_mode=result_mode; o->after_pc=context->uc_mcontext->__ss.__pc; o->after_sp=sp;
        o->after_x18=context->uc_mcontext->__ss.__x[18]; o->after_x19=context->uc_mcontext->__ss.__x[19];
        if (o->after_pc!=o->before_pc || o->after_sp!=o->before_sp || result_mode!=o->entry_mode ||
            (o->phase!=PEAR_S4_HOST && (o->after_x18!=o->before_x18 || o->after_x19!=o->before_x19))) __atomic_fetch_or(&o->bad,16,__ATOMIC_RELAXED);
        __atomic_store_n(&slot->release,1,__ATOMIC_RELEASE);
        __atomic_store_n(&o->after_count,1,__ATOMIC_RELEASE);
        return;
    }
}
static void snapshot(struct fixture_slot *slot,pear_s4_request *request)
{
    request->registered=__atomic_load_n(&slot->registered,__ATOMIC_ACQUIRE);
    request->native_tid=slot->tid; request->native_teb=slot->teb;
    request->init_seen=slot->init_seen; request->init_host_mode=slot->init_mode; request->init_tls_matches=slot->init_tls_match;
    request->guest_stack_low=slot->guest_low; request->guest_stack_high=slot->guest_high;
    request->kernel_stack_low=slot->kernel_low; request->kernel_stack_high=slot->kernel_high;
    request->host_begin=(uintptr_t)pear_stage4_host_begin; request->host_end=(uintptr_t)pear_stage4_host_end;
    request->ready=__atomic_load_n(&slot->ready,__ATOMIC_ACQUIRE);
    request->native_exit_seen=__atomic_load_n(&slot->exit_seen,__ATOMIC_ACQUIRE);
    if (request->native_exit_seen) request->native_exit_mode=slot->exit_mode;
    request->observation.phase=slot->observation.phase;
    if (__atomic_load_n(&slot->observation.after_count,__ATOMIC_ACQUIRE)) {
        pear_s4_signal *o=&request->observation,*s=&slot->observation;
        o->before_count=__atomic_load_n(&s->before_count,__ATOMIC_ACQUIRE); o->after_count=1;
        o->signal_number=s->signal_number; o->entry_mode=s->entry_mode; o->handler_mode=s->handler_mode; o->return_mode=s->return_mode;
        o->before_pc=s->before_pc; o->after_pc=s->after_pc; o->before_x18=s->before_x18; o->after_x18=s->after_x18;
        o->before_x19=s->before_x19; o->after_x19=s->after_x19; o->before_sp=s->before_sp; o->after_sp=s->after_sp;
        o->bad=__atomic_load_n(&s->bad,__ATOMIC_RELAXED);
    }
    else if (__atomic_load_n(&slot->observation.before_count,__ATOMIC_ACQUIRE)) {
        pear_s4_signal *o=&request->observation,*s=&slot->observation;
        o->before_count=s->before_count; o->signal_number=s->signal_number; o->entry_mode=s->entry_mode; o->handler_mode=s->handler_mode;
        o->before_pc=s->before_pc; o->before_x18=s->before_x18; o->before_x19=s->before_x19; o->before_sp=s->before_sp;
        o->bad=__atomic_load_n(&s->bad,__ATOMIC_RELAXED);
    }
}
#endif
NTSTATUS pear_stage4_unix_entry(void *opaque)
{
#if defined(__APPLE__) && defined(__aarch64__)
    pear_s4_request *request=opaque;
    if (!request || request->magic!=PEAR_STAGE4_MAGIC || request->version!=1 || request->operation>PEAR_S4_DISARM ||
        request->slot>=2 || !pear_x18_getter) return STATUS_INVALID_PARAMETER;
    request->host_entry=pear_x18_getter();
    if (request->host_entry || !environment_ok()) return STATUS_INVALID_PARAMETER;
    request->native_pid=getpid();
    Dl_info image;
    if (!dladdr((void *)pear_stage4_host_begin,&image) || !image.dli_fbase) return STATUS_INVALID_PARAMETER;
    request->ntdll_base=(uintptr_t)image.dli_fbase;
    if (request->operation==PEAR_S4_INIT) {
        if (__atomic_load_n(&enabled,__ATOMIC_ACQUIRE)) return STATUS_INVALID_PARAMETER;
        __atomic_store_n(&enabled,1,__ATOMIC_RELEASE);
        request->host_exit=pear_x18_getter(); return STATUS_SUCCESS;
    }
    if (!__atomic_load_n(&enabled,__ATOMIC_ACQUIRE)) return STATUS_INVALID_PARAMETER;
    struct fixture_slot *slot=&slots[request->slot];
    struct thread_data *data=get_thread_data();
    NTSTATUS result=STATUS_SUCCESS;
    if (request->operation==PEAR_S4_REGISTER) {
        if (__atomic_load_n(&slot->registered,__ATOMIC_ACQUIRE) || !data || !data->teb ||
            request->guest_teb!=(uintptr_t)data->teb || request->guest_tid!=data->tid ||
            !request->guest_begin || request->guest_end<=request->guest_begin || request->guest_end-request->guest_begin>128)
            return STATUS_INVALID_PARAMETER;
        slot->teb=(uintptr_t)data->teb; slot->tid=data->tid; slot->thread=pthread_self(); slot->ntdll_base=request->ntdll_base;
        slot->guest_low=(uintptr_t)data->teb->DeallocationStack; slot->guest_high=(uintptr_t)data->teb->Tib.StackBase;
        slot->kernel_low=(uintptr_t)get_kernel_stack(data); slot->kernel_high=slot->kernel_low+kernel_stack_size;
        slot->guest_begin=request->guest_begin; slot->guest_end=request->guest_end;
        for (unsigned i=0;i<32;++i) if (__atomic_load_n(&initial[i].complete,__ATOMIC_ACQUIRE) && initial[i].teb==slot->teb && initial[i].tid==slot->tid) {
            ++slot->init_seen; slot->init_mode=initial[i].mode; slot->init_tls_match=initial[i].tls_match;
        }
        if (slot->init_seen!=1 || slot->init_mode || slot->init_tls_match!=1) return STATUS_INVALID_PARAMETER;
        emit_registration((unsigned)request->slot,slot);
        __atomic_store_n(&slot->registered,1,__ATOMIC_RELEASE);
    } else {
        if (!__atomic_load_n(&slot->registered,__ATOMIC_ACQUIRE)) return STATUS_INVALID_PARAMETER;
        switch(request->operation) {
        case PEAR_S4_ARM:
            if (__atomic_load_n(&slot->armed,__ATOMIC_ACQUIRE) || request->phase<1 || request->phase>3) return STATUS_INVALID_PARAMETER;
            memset(&slot->observation,0,sizeof(slot->observation)); slot->observation.phase=request->phase;
            __atomic_store_n(&slot->reported,0,__ATOMIC_RELEASE);
            __atomic_store_n(&slot->ready,0,__ATOMIC_RELEASE); __atomic_store_n(&slot->release,0,__ATOMIC_RELEASE);
            __atomic_store_n(&slot->armed,1,__ATOMIC_RELEASE); break;
        case PEAR_S4_SEND:
            if (!__atomic_load_n(&slot->armed,__ATOMIC_ACQUIRE) || pthread_equal(slot->thread,pthread_self()) ||
                __atomic_load_n(&slot->exit_seen,__ATOMIC_ACQUIRE)) return STATUS_INVALID_PARAMETER;
            request->send_status=pthread_kill(slot->thread,SIGUSR1);
            if (request->send_status) result=STATUS_UNSUCCESSFUL;
            break;
        case PEAR_S4_HOST_WAIT:
            if (!pthread_equal(slot->thread,pthread_self()) || !__atomic_load_n(&slot->armed,__ATOMIC_ACQUIRE) ||
                slot->observation.phase!=PEAR_S4_HOST) return STATUS_INVALID_PARAMETER;
            request->error=pear_stage4_host_spin(&slot->ready,&slot->release);
            if (request->error) result=STATUS_TIMEOUT;
            break;
        case PEAR_S4_SNAPSHOT: break;
        case PEAR_S4_ERROR:
            if (!pthread_equal(slot->thread,pthread_self())) return STATUS_INVALID_PARAMETER;
            result=PEAR_STAGE4_ERROR; break;
        case PEAR_S4_DISARM:
            __atomic_store_n(&slot->release,1,__ATOMIC_RELEASE);
            __atomic_store_n(&slot->armed,0,__ATOMIC_RELEASE); break;
        default: return STATUS_INVALID_PARAMETER;
        }
    }
    snapshot(slot,request);
    if(request->operation==PEAR_S4_SNAPSHOT && request->observation.after_count==1 &&
        !__atomic_exchange_n(&slot->reported,1,__ATOMIC_ACQ_REL)) emit_signal((unsigned)request->slot,slot,&request->observation);
    request->host_exit=pear_x18_getter();
    if (request->host_exit) return STATUS_INVALID_PARAMETER;
    return result;
#else
    (void)opaque; return STATUS_NOT_SUPPORTED;
#endif
}
