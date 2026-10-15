/* Original Pear Stage 4 combined fixture. SPDX-License-Identifier: MIT. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "stage4_protocol.h"
#ifndef CONTEXT_ARM64_X18
#define CONTEXT_ARM64_X18 (CONTEXT_ARM64 | 0x10)
#endif
typedef LONG (WINAPI *unix_dispatcher)(uint64_t,unsigned,void *);
static unix_dispatcher dispatcher;
static uint64_t unix_handle,main_teb,native_pid;
static DWORD tls_index=TLS_OUT_OF_INDEXES;
static unsigned error_step,thread_checks,signal_checks,suspend_checks,error_checks;
static DWORD error_code;
static char output[3072];
static unsigned output_length,output_failed;
static CONTEXT suspend_context;
static WCHAR executable[1024],child_command[1100];
static STARTUPINFOW child_startup;
static PROCESS_INFORMATION child_process;
static struct worker {
    HANDLE command_event,done_event,started_event,thread;
    DWORD tid;
    unsigned slot,checks;
    volatile LONG error,command,ready,release;
    uint64_t teb,tls_value;
    pear_s4_request registration;
} workers[2];
/* Freestanding compiler support, not a system C runtime. */
void *memset(void *p,int value,size_t size) { unsigned char *out=p; for(size_t i=0;i<size;++i) out[i]=(unsigned char)value; return p; }
void *memcpy(void *p,const void *q,size_t size) { unsigned char *out=p; const unsigned char *in=q; for(size_t i=0;i<size;++i) out[i]=in[i]; return p; }
static uint64_t current_teb(void) { uint64_t value; __asm__ volatile("mov %0, x18":"=r"(value)); return value; }
static void text(const char *s) { while(*s) { if(output_length==sizeof(output)-1) {output_failed=1;return;} output[output_length++]=*s++; } }
static void number(uint64_t value) { char reversed[21]; unsigned n=0; do {reversed[n++]='0'+value%10;value/=10;}while(value); while(n) {if(output_length==sizeof(output)-1){output_failed=1;return;}output[output_length++]=reversed[--n];} }
int pear_emit(const char *kind,const char *const *names,const uint64_t *values,unsigned count)
{
    if(count>32) return 0;
    output_length=output_failed=0;
    text("{\"version\":1,\"record_kind\":\"");text(kind);text("\"");
    for(unsigned i=0;i<count;++i){text(",\"");text(names[i]);text("\":");number(values[i]);}
    text("}\n");
    if(output_failed) return 0;
    DWORD written=0;
    return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),output,output_length,&written,NULL) && written==output_length;
}
static void fail(unsigned step) { if(!error_step){error_step=step;error_code=GetLastError();} }
static void request_init(pear_s4_request *request,unsigned op,unsigned slot)
{
    uint64_t *fields=(uint64_t *)request;
    for(unsigned i=0;i<sizeof(*request)/sizeof(*fields);++i)fields[i]=0;
    request->magic=PEAR_STAGE4_MAGIC;request->version=1;request->operation=op;request->slot=slot;
    request->host_entry=request->host_exit=UINT64_MAX;
}
static LONG bridge(pear_s4_request *request)
{
    uint64_t teb=current_teb();
    LONG status=dispatcher(unix_handle,PEAR_STAGE4_INDEX,request);
    if(current_teb()!=teb || request->host_entry || request->host_exit) return (LONG)UINT32_C(0xc000000d);
    return status;
}
static int initialize(void)
{
    HMODULE ntdll=GetModuleHandleW(L"ntdll.dll");
    unix_dispatcher *fn=(unix_dispatcher *)(uintptr_t)GetProcAddress(ntdll,"__wine_unix_call_dispatcher");
    uint64_t *handle=(uint64_t *)(uintptr_t)GetProcAddress(ntdll,"__wine_unixlib_handle");
    if(!fn || !*fn || !handle || !*handle) return 0;
    dispatcher=*fn;unix_handle=*handle;main_teb=current_teb();
    pear_s4_request request;request_init(&request,PEAR_S4_INIT,0);
    if(bridge(&request)) return 0;
    native_pid=request.native_pid;return native_pid!=0;
}
static int state_valid(struct worker *worker)
{
    if(current_teb()!=worker->teb || (uintptr_t)TlsGetValue(tls_index)!=worker->tls_value) return 0;
    ++worker->checks;return 1;
}
static DWORD WINAPI worker_entry(void *opaque)
{
    struct worker *worker=opaque;
    worker->teb=current_teb(); worker->tls_value=UINT64_C(0x7300)+worker->slot;
    if(!worker->teb || !TlsSetValue(tls_index,(void *)(uintptr_t)worker->tls_value)){InterlockedExchange(&worker->error,1);goto done;}
    pear_s4_request request;request_init(&request,PEAR_S4_REGISTER,worker->slot);
    request.guest_teb=worker->teb;request.guest_tid=GetCurrentThreadId();
    request.guest_begin=(uintptr_t)pear_guest_spin_begin;request.guest_end=(uintptr_t)pear_guest_spin_end;
    if(bridge(&request) || !request.registered || !state_valid(worker)){InterlockedExchange(&worker->error,2);goto done;}
    worker->registration=request;
    if(!SetEvent(worker->started_event)){InterlockedExchange(&worker->error,3);goto done;}
    for(unsigned trial=0;trial<8;++trial){
        if(WaitForSingleObject(worker->command_event,10000)!=WAIT_OBJECT_0){InterlockedExchange(&worker->error,4);goto done;}
        LONG command=InterlockedCompareExchange(&worker->command,0,0);
        if(command==5) break;
        if(command==1 || command==3) pear_guest_spin(&worker->ready,&worker->release,PEAR_STAGE4_SENTINEL+worker->slot);
        else if(command==2){
            request_init(&request,PEAR_S4_HOST_WAIT,worker->slot);
            if(bridge(&request) || request.error){InterlockedExchange(&worker->error,5);goto done;}
        } else if(command==4){
            request_init(&request,PEAR_S4_ERROR,worker->slot);
            if((uint32_t)bridge(&request)!=PEAR_STAGE4_ERROR){InterlockedExchange(&worker->error,6);goto done;}
        } else {InterlockedExchange(&worker->error,7);goto done;}
        if(!state_valid(worker)){InterlockedExchange(&worker->error,8);goto done;}
        if(!SetEvent(worker->done_event)){InterlockedExchange(&worker->error,9);goto done;}
    }
    if(!state_valid(worker)) InterlockedExchange(&worker->error,10);
done:
    SetEvent(worker->started_event);SetEvent(worker->done_event);
    return (DWORD)InterlockedCompareExchange(&worker->error,0,0);
}
static int send_command(unsigned slot,unsigned command)
{
    struct worker *worker=&workers[slot];
    if(!ResetEvent(worker->done_event)) return 0;
    InterlockedExchange(&worker->ready,0);InterlockedExchange(&worker->release,0);InterlockedExchange(&worker->command,command);
    return SetEvent(worker->command_event);
}
static int wait_ready(unsigned slot,unsigned phase)
{
    ULONGLONG start=GetTickCount64();
    do {
        if(InterlockedCompareExchange(&workers[slot].error,0,0)) return 0;
        if(phase==PEAR_S4_HOST){pear_s4_request request;request_init(&request,PEAR_S4_SNAPSHOT,slot);if(bridge(&request))return 0;if(request.ready)return 1;}
        else if(InterlockedCompareExchange(&workers[slot].ready,0,0))return 1;
        Sleep(1);
    }while(GetTickCount64()-start<5000);
    return 0;
}
static int wait_signal(unsigned slot,pear_s4_request *out)
{
    ULONGLONG start=GetTickCount64();
    do {
        request_init(out,PEAR_S4_SNAPSHOT,slot);
        if(bridge(out)) return 0;
        if(out->observation.after_count) return 1;
        Sleep(1);
    }while(GetTickCount64()-start<5000);
    return 0;
}
static int signal_event(unsigned slot,const pear_s4_request *request,uint64_t send_status)
{
    const pear_s4_signal *o=&request->observation;
    static const char *const names[]={"slot","phase","module_base","teb","native_tid","ntdll_base","guest_begin","guest_end","host_begin","host_end",
        "before_count","after_count","signal","entry_mode","handler_mode","return_mode","before_pc","after_pc","before_x18","after_x18",
        "before_x19","after_x19","before_sp","after_sp","error","send_status"};
    uint64_t values[]={slot,o->phase,(uintptr_t)GetModuleHandleW(NULL),workers[slot].teb,request->native_tid,request->ntdll_base,
        (uintptr_t)pear_guest_spin_begin,(uintptr_t)pear_guest_spin_end,request->host_begin,request->host_end,
        o->before_count,o->after_count,o->signal_number,o->entry_mode,o->handler_mode,o->return_mode,o->before_pc,o->after_pc,
        o->before_x18,o->after_x18,o->before_x19,o->after_x19,o->before_sp,o->after_sp,o->bad,send_status};
    return pear_emit("pear_signal_event",names,values,26);
}
static int run_signal(unsigned slot,unsigned phase)
{
    pear_s4_request request;request_init(&request,PEAR_S4_ARM,slot);request.phase=phase;
    if(bridge(&request) || !send_command(slot,phase) || !wait_ready(slot,phase))return 0;
    request_init(&request,PEAR_S4_SEND,slot);
    LONG result=bridge(&request);uint64_t sent=request.send_status;
    if(result || !wait_signal(slot,&request) || !signal_event(slot,&request,sent))return 0;
    int valid=request.observation.before_count==1 && request.observation.after_count==1 && !request.observation.bad && !sent;
    request_init(&request,PEAR_S4_DISARM,slot);
    if(bridge(&request) || request.observation.bad || request.observation.before_count!=1 || request.observation.after_count!=1)valid=0;
    InterlockedExchange(&workers[slot].release,1);
    if(WaitForSingleObject(workers[slot].done_event,5000)!=WAIT_OBJECT_0 || InterlockedCompareExchange(&workers[slot].error,0,0))valid=0;
    if(valid)++signal_checks;
    return valid;
}
static int run_suspend(void)
{
    unsigned slot=0;pear_s4_request request;
    request_init(&request,PEAR_S4_ARM,slot);request.phase=PEAR_S4_SUSPEND;
    if(bridge(&request) || !send_command(slot,3) || !wait_ready(slot,3))return 0;
    DWORD before=SuspendThread(workers[slot].thread);
    int suspended=before!=(DWORD)-1,valid=before==0;
    memset(&suspend_context,0,sizeof(suspend_context));
    suspend_context.ContextFlags=CONTEXT_ARM64_FULL|CONTEXT_ARM64_X18;
    DWORD context_ok=suspended ? GetThreadContext(workers[slot].thread,&suspend_context) : 0;
    request_init(&request,PEAR_S4_SNAPSHOT,slot);
    if(bridge(&request) || !context_ok || request.observation.before_count!=1 || request.observation.after_count ||
        suspend_context.X18!=workers[slot].teb || suspend_context.X19!=PEAR_STAGE4_SENTINEL ||
        suspend_context.Pc<(uintptr_t)pear_guest_spin_begin || suspend_context.Pc>=(uintptr_t)pear_guest_spin_end ||
        suspend_context.Sp<request.guest_stack_low || suspend_context.Sp>=request.guest_stack_high || (suspend_context.Sp&15))valid=0;
    DWORD resumed=suspended ? ResumeThread(workers[slot].thread) : (DWORD)-1;
    if(resumed!=1 || !wait_signal(slot,&request) || !signal_event(slot,&request,0))valid=0;
    if(request.observation.before_count!=1 || request.observation.after_count!=1 || request.observation.bad)valid=0;
    static const char *const names[]={"slot","suspend_previous","resume_previous","context_ok","context_flags","context_pc","context_sp","context_x18","context_x19","stack_low","stack_high","passed"};
    uint64_t values[]={slot,before,resumed,context_ok,suspend_context.ContextFlags,suspend_context.Pc,suspend_context.Sp,suspend_context.X18,
        suspend_context.X19,request.guest_stack_low,request.guest_stack_high,valid};
    if(!pear_emit("pear_suspend_result",names,values,12))valid=0;
    request_init(&request,PEAR_S4_DISARM,slot);if(bridge(&request) || request.observation.bad || request.observation.before_count!=1 || request.observation.after_count!=1)valid=0;
    InterlockedExchange(&workers[slot].release,1);
    if(WaitForSingleObject(workers[slot].done_event,5000)!=WAIT_OBJECT_0 || InterlockedCompareExchange(&workers[slot].error,0,0))valid=0;
    if(valid)++suspend_checks;
    return valid;
}
static int thread_report(unsigned slot,DWORD exit_code)
{
    pear_s4_request request;ULONGLONG start=GetTickCount64();
    do{request_init(&request,PEAR_S4_SNAPSHOT,slot);if(bridge(&request))return 0;if(request.native_exit_seen)break;Sleep(1);}while(GetTickCount64()-start<5000);
    static const char *const names[]={"slot","teb","tid","tls_value","checks","error","exit_code","registered","init_seen","init_host_mode","init_tls_matches",
        "native_tid","native_teb","native_exit_seen","native_exit_mode","host_entry","host_exit"};
    uint64_t values[]={slot,workers[slot].teb,workers[slot].tid,workers[slot].tls_value,workers[slot].checks,(uint32_t)InterlockedCompareExchange(&workers[slot].error,0,0),exit_code,
        request.registered,request.init_seen,request.init_host_mode,request.init_tls_matches,request.native_tid,request.native_teb,
        request.native_exit_seen,request.native_exit_mode,request.host_entry,request.host_exit};
    return pear_emit("pear_thread_event",names,values,17) && request.native_exit_seen==1 && !request.native_exit_mode && !exit_code;
}
static int workers_run(void)
{
    tls_index=TlsAlloc();if(tls_index==TLS_OUT_OF_INDEXES)return 0;
    for(unsigned i=0;i<2;++i){
        struct worker *w=&workers[i];w->slot=i;
        w->command_event=CreateEventW(NULL,FALSE,FALSE,NULL);w->done_event=CreateEventW(NULL,TRUE,FALSE,NULL);w->started_event=CreateEventW(NULL,TRUE,FALSE,NULL);
        if(!w->command_event || !w->done_event || !w->started_event)return 0;
        w->thread=CreateThread(NULL,0,worker_entry,w,0,&w->tid);if(!w->thread)return 0;
    }
    for(unsigned i=0;i<2;++i)if(WaitForSingleObject(workers[i].started_event,5000)!=WAIT_OBJECT_0 || InterlockedCompareExchange(&workers[i].error,0,0))return 0;
    if(workers[0].teb==workers[1].teb || workers[0].teb==main_teb || workers[1].teb==main_teb || workers[0].tid==workers[1].tid)return 0;
    thread_checks=2;
    if(!run_signal(0,PEAR_S4_GUEST) || !run_signal(1,PEAR_S4_HOST) || !run_suspend())return 0;
    for(unsigned i=0;i<2;++i){if(!send_command(i,4) || WaitForSingleObject(workers[i].done_event,5000)!=WAIT_OBJECT_0 || InterlockedCompareExchange(&workers[i].error,0,0))return 0;++error_checks;}
    return 1;
}
static int workers_cleanup(void)
{
    int valid=1;
    for(unsigned i=0;i<2;++i){struct worker *w=&workers[i];
        if(w->registration.registered){pear_s4_request request;request_init(&request,PEAR_S4_DISARM,i);if(bridge(&request))valid=0;}
        InterlockedExchange(&w->release,1);InterlockedExchange(&w->command,5);
        if(w->command_event && !SetEvent(w->command_event))valid=0;
    }
    for(unsigned i=0;i<2;++i){struct worker *w=&workers[i];
        if(w->thread){DWORD code=UINT32_MAX;if(WaitForSingleObject(w->thread,5000)!=WAIT_OBJECT_0 || !GetExitCodeThread(w->thread,&code))valid=0;
            else if(!thread_report(i,code))valid=0;
            if(!CloseHandle(w->thread))valid=0;}
        if(w->command_event && !CloseHandle(w->command_event))valid=0;
        if(w->done_event && !CloseHandle(w->done_event))valid=0;
        if(w->started_event && !CloseHandle(w->started_event))valid=0;
    }
    if(tls_index!=TLS_OUT_OF_INDEXES && !TlsFree(tls_index))valid=0;
    return valid;
}
static int is_child(void)
{
    const WCHAR *line=GetCommandLineW();static const WCHAR suffix[]=L" --pear-fatal-child";
    unsigned length=0,n=sizeof(suffix)/sizeof(*suffix)-1;
    while(line[length] && length<2048)++length;
    if(length==2048 || length<n)return 0;
    for(unsigned i=0;i<n;++i)if(line[length-n+i]!=suffix[i])return 0;
    return 1;
}
static int fatal_child(void)
{
    DWORD length=GetModuleFileNameW(NULL,executable,1024);
    if(!length || length>=1024)return 0;
    static const WCHAR suffix[]=L"\" --pear-fatal-child";
    child_command[0]='"';for(unsigned i=0;i<length;++i)child_command[i+1]=executable[i];
    for(unsigned i=0;i<sizeof(suffix)/sizeof(*suffix);++i)child_command[length+1+i]=suffix[i];
    child_startup.cb=sizeof(child_startup);child_startup.dwFlags=STARTF_USESTDHANDLES;
    child_startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);child_startup.hStdOutput=GetStdHandle(STD_OUTPUT_HANDLE);child_startup.hStdError=GetStdHandle(STD_ERROR_HANDLE);
    if(!CreateProcessW(executable,child_command,NULL,NULL,TRUE,0,NULL,NULL,&child_startup,&child_process))return 0;
    DWORD wait=WaitForSingleObject(child_process.hProcess,15000),code=UINT32_MAX;
    int query=GetExitCodeProcess(child_process.hProcess,&code);
    if(wait!=WAIT_OBJECT_0){TerminateProcess(child_process.hProcess,98);WaitForSingleObject(child_process.hProcess,5000);}
    int closed_thread=CloseHandle(child_process.hThread),closed_process=CloseHandle(child_process.hProcess);
    static const char *const names[]={"guest_pid","exit_code","wait_result","exit_query","thread_closed","process_closed","expected_code"};
    uint64_t values[]={child_process.dwProcessId,code,wait,query,closed_thread,closed_process,UINT32_C(0xc0000005)};
    return pear_emit("pear_stage4_child_result",names,values,7) && wait==WAIT_OBJECT_0 && query && code==UINT32_C(0xc0000005) && closed_thread && closed_process;
}
void WINAPI mainCRTStartup(void)
{
    if(!initialize())ExitProcess(91);
    if(is_child()){SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);ExitProcess(pear_exception_fatal(native_pid)?94:95);}
    int threads=workers_run();if(!threads)fail(1);
    int cleanup=workers_cleanup();if(!cleanup)fail(2);
    int exceptions=-1;
    if(!error_step){exceptions=pear_exception_initialize();if(exceptions)fail(3);}
    if(!error_step && !exceptions){exceptions=pear_exception_checks();if(exceptions)fail(4);}
    int memory=error_step ? -1 : pear_memory_checks();if(memory)fail(5);
    int removed=pear_exception_finish();if(removed)fail(6);
    int child=!error_step && fatal_child();if(!child)fail(7);
    int passed=!error_step && thread_checks==2 && signal_checks==2 && suspend_checks==1 && error_checks==2 && current_teb()==main_teb;
    static const char *const names[]={"passed","error_step","win32_error","workers","signals","suspends","injected_errors","workers_cleaned","exceptions_status","memory_status","handlers_removed","child_passed","module_base","main_teb","native_pid"};
    uint64_t values[]={passed,error_step,error_code,thread_checks,signal_checks,suspend_checks,error_checks,cleanup,(unsigned)exceptions,(unsigned)memory,!removed,child,(uintptr_t)GetModuleHandleW(NULL),main_teb,native_pid};
    if(!pear_emit("pear_stage4_result",names,values,15))ExitProcess(90);
    ExitProcess(passed?0:92);
}
