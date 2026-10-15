/* Original Pear finite Stage 5 Win32 window fixture. SPDX-License-Identifier: MIT.
 * Native observations separately prove the Cocoa/event boundary. No renderer,
 * proprietary input or C runtime is used by this Windows ARM64 executable. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include "stage5_protocol.h"

typedef LONG (WINAPI *window_control)(pear_s5_request *);
static window_control control;
static HMODULE module,driver;
static uint64_t main_teb,native_pid;
static DWORD main_tid,main_pid,error_code;
static unsigned error_step,cycles_done,class_registered,class_unregistered;
static unsigned total_app,total_reentry,total_close,total_destroy,total_ncdestroy,total_late;
static unsigned native_final,cleanup_complete;
static const WCHAR class_name[]=L"PearStage5Window";
static const WCHAR callback_title[]=L"Pear Stage 5 callback";
static char output[3072];
static unsigned output_length,output_failed;
static struct cycle_state {
    HWND hwnd;
    unsigned cycle,nccreate,create,app_messages,reentries,sysclose,close,destroy,ncdestroy;
    unsigned late_callbacks,title_checks,hwnd_gone,drain_complete;
    uint64_t token,callback_result;
} active;

/* Freestanding compiler support, not a system C runtime. */
void *memset(void *p,int value,size_t size) { unsigned char *out=p;for(size_t i=0;i<size;++i)out[i]=(unsigned char)value;return p; }
void *memcpy(void *p,const void *q,size_t size) { unsigned char *out=p;const unsigned char *in=q;for(size_t i=0;i<size;++i)out[i]=in[i];return p; }
static uint64_t current_teb(void) { uint64_t value;__asm__ volatile("mov %0, x18":"=r"(value));return value; }
static unsigned wlen(const WCHAR *s) { unsigned n=0;while(s[n])++n;return n; }
static int wequal(const WCHAR *a,const WCHAR *b) { while(*a && *a==*b){++a;++b;}return *a==*b; }
static int fail_code(unsigned step,DWORD code) { if(!error_step){error_step=step;error_code=code;}return 0; }
static int fail(unsigned step) { return fail_code(step,GetLastError()); }
static void text(const char *s) { while(*s){if(output_length==sizeof(output)-1){output_failed=1;return;}output[output_length++]=*s++;} }
static void number(uint64_t value) { char digits[21];unsigned n=0;do{digits[n++]='0'+value%10;value/=10;}while(value);while(n){if(output_length==sizeof(output)-1){output_failed=1;return;}output[output_length++]=digits[--n];} }
static int emit(const char *kind,const char *const *names,const uint64_t *values,unsigned count)
{
    if(count>32)return fail_code(90,ERROR_INVALID_DATA);
    output_length=output_failed=0;text("{\"version\":1,\"record_kind\":\"");text(kind);text("\"");
    for(unsigned i=0;i<count;++i){text(",\"");text(names[i]);text("\":");number(values[i]);}
    text("}\n");
    if(output_failed)return fail_code(90,ERROR_INSUFFICIENT_BUFFER);
    DWORD written=0;
    if(!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),output,output_length,&written,NULL))return fail(90);
    return written==output_length || fail_code(90,ERROR_WRITE_FAULT);
}
static int owner_valid(unsigned step)
{
    return (current_teb()==main_teb && GetCurrentThreadId()==main_tid) || fail_code(step,ERROR_INVALID_DATA);
}
static void request_init(pear_s5_request *request,unsigned operation)
{
    memset(request,0,sizeof(*request));request->magic=PEAR_STAGE5_MAGIC;request->version=1;
    request->operation=operation;request->guest_teb=current_teb();request->guest_tid=GetCurrentThreadId();
    if(operation!=PEAR_S5_INIT && operation!=PEAR_S5_FINAL){
        request->cycle=active.cycle;request->hwnd=(uintptr_t)active.hwnd;request->token=active.token;
    }
    request->host_entry=request->host_exit=UINT64_MAX;
}
static LONG bridge(pear_s5_request *request,unsigned step)
{
    if(!owner_valid(12))return (LONG)UINT32_C(0xc000000d);
    LONG result=control(request);
    /* Keep a native operation failure even if its response is incomplete. */
    if(result && (uint32_t)result!=PEAR_STAGE5_PENDING)fail_code(step,(DWORD)result);
    if(!owner_valid(12) || request->host_entry || request->host_exit ||
       request->native_tid!=main_tid || request->teb!=main_teb ||
       (native_pid && request->native_pid!=native_pid)){
        fail_code(12,ERROR_INVALID_DATA);return (LONG)UINT32_C(0xc000000d);
    }
    return result;
}
static int control_ok(unsigned operation,unsigned step,pear_s5_request *out)
{
    request_init(out,operation);LONG status=bridge(out,step);
    if(status)return fail_code(step,(DWORD)status);
    if(out->errors || out->late)return fail_code(step,ERROR_INVALID_DATA);
    return 1;
}

__declspec(dllexport) LRESULT CALLBACK PearWindowProc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp)
{
    if(!owner_valid(20))return 0;
    if(active.ncdestroy && hwnd==active.hwnd){
        ++active.late_callbacks;++total_late;fail_code(21,ERROR_INVALID_DATA);return 0;
    }
    switch(message){
    case WM_MOUSEACTIVATE:
        return MA_NOACTIVATE;
    case WM_NCCREATE:{
        const CREATESTRUCTW *created=(const CREATESTRUCTW *)(uintptr_t)lp;
        if(!created || created->lpCreateParams!=&active || active.hwnd || active.nccreate)
            return fail_code(22,ERROR_INVALID_DATA);
        active.hwnd=hwnd;++active.nccreate;return TRUE;
    }
    case WM_CREATE:
        if(hwnd!=active.hwnd || active.create || !active.nccreate){fail_code(23,ERROR_INVALID_DATA);return -1;}
        ++active.create;return 0;
    case PEAR_STAGE5_MESSAGE:{
        if(hwnd!=active.hwnd || wp!=active.cycle || (uint64_t)lp!=active.token ||
           active.app_messages || active.close || !active.create){fail_code(24,ERROR_INVALID_DATA);return 0;}
        ++active.app_messages;++total_app;
        if(!SetWindowTextW(hwnd,callback_title)){fail(25);return 0;}
        if(!owner_valid(25))return 0;
        WCHAR title[64];
        if(GetWindowTextW(hwnd,title,64)!=(int)wlen(callback_title) || !wequal(title,callback_title)){
            fail_code(26,ERROR_INVALID_DATA);return 0;
        }
        ++active.title_checks;
        pear_s5_request request;
        if(!control_ok(PEAR_S5_REENTRY,27,&request) || request.reentered!=1 || request.title_changed!=1){
            fail_code(27,ERROR_INVALID_DATA);return 0;
        }
        if(!owner_valid(27))return 0;
        ++active.reentries;++total_reentry;
        active.callback_result=PEAR_STAGE5_REPLY(active.token);return (LRESULT)active.callback_result;
    }
    case WM_SYSCOMMAND:
        if((wp&0xfff0u)==SC_CLOSE){
            if(hwnd!=active.hwnd || active.sysclose || active.app_messages!=1 || active.reentries!=1){
                fail_code(28,ERROR_INVALID_DATA);return 0;
            }
            ++active.sysclose;
        }
        break;
    case WM_CLOSE:
        if(hwnd!=active.hwnd || active.close || active.sysclose!=1 || active.reentries!=1){
            fail_code(29,ERROR_INVALID_DATA);return 0;
        }
        ++active.close;++total_close;
        if(!DestroyWindow(hwnd))fail(30);
        owner_valid(30);return 0;
    case WM_DESTROY:
        if(hwnd!=active.hwnd || active.destroy){fail_code(31,ERROR_INVALID_DATA);return 0;}
        ++active.destroy;++total_destroy;return 0;
    case WM_NCDESTROY:
        if(hwnd!=active.hwnd || active.ncdestroy || active.destroy!=1){fail_code(32,ERROR_INVALID_DATA);return 0;}
        ++active.ncdestroy;++total_ncdestroy;break;
    }
    LRESULT result=DefWindowProcW(hwnd,message,wp,lp);
    owner_valid(33);return result;
}

static int pump(unsigned wait_ms)
{
    MSG message;unsigned count=0;
    while(PeekMessageW(&message,NULL,0,0,PM_REMOVE)){
        if(++count>4096 || message.message==WM_QUIT)return fail_code(40,ERROR_INVALID_DATA);
        DispatchMessageW(&message);
        if(error_step || !owner_valid(40))return 0;
    }
    if(wait_ms){
        DWORD value=MsgWaitForMultipleObjectsEx(0,NULL,wait_ms,QS_ALLINPUT,MWMO_INPUTAVAILABLE);
        if(value==WAIT_FAILED)return fail(41);
        if(value!=WAIT_OBJECT_0 && value!=WAIT_TIMEOUT)return fail_code(41,ERROR_INVALID_DATA);
    }
    return 1;
}
static int drain_cycle(void)
{
    ULONGLONG start=GetTickCount64();
    for(unsigned attempt=0;attempt<100 && GetTickCount64()-start<5000;++attempt){
        pear_s5_request request;request_init(&request,PEAR_S5_DRAIN);
        LONG status=bridge(&request,44);
        if((uint32_t)status==PEAR_STAGE5_PENDING){if(!pump(20))return 0;continue;}
        if(status)return fail_code(44,(DWORD)status);
        if(request.created!=1 || request.armed!=1 || request.triggered!=1 || request.cocoa_close!=1 ||
           request.dispatched!=1 || request.reentered!=1 || request.title_changed!=1 || request.callback_returned!=1 ||
           request.destroyed!=1 || request.cocoa_destroyed!=1 || request.discarded!=1 || request.deallocated!=1 ||
           request.completed!=1 || !request.barriers || request.barriers>100 || !request.drains || request.drains>100 ||
           request.late || request.errors || request.active || request.callback_result!=PEAR_STAGE5_REPLY(active.token))
            return fail_code(44,ERROR_INVALID_DATA);
        active.drain_complete=1;return 1;
    }
    return fail_code(44,WAIT_TIMEOUT);
}
static int cycle(unsigned index)
{
    memset(&active,0,sizeof(active));active.cycle=index;active.token=PEAR_STAGE5_TOKEN(index);
    HWND hwnd=CreateWindowExW(WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE,class_name,L"Pear Stage 5 window",
        WS_OVERLAPPEDWINDOW,64,64,320,180,NULL,NULL,module,&active);
    if(!hwnd)return fail(42);
    if(hwnd!=active.hwnd || active.nccreate!=1 || active.create!=1)return fail_code(42,ERROR_INVALID_DATA);
    DWORD pid=0;
    if(GetWindowThreadProcessId(hwnd,&pid)!=main_tid || pid!=main_pid)return fail_code(42,ERROR_INVALID_DATA);
    ShowWindow(hwnd,SW_SHOWNOACTIVATE);
    if(!IsWindow(hwnd))return fail_code(42,ERROR_INVALID_WINDOW_HANDLE);
    pear_s5_request request;
    if(!control_ok(PEAR_S5_ARM,43,&request) || request.armed!=1 || request.created!=1){
        fail_code(43,ERROR_INVALID_DATA);return 0;
    }
    if(!control_ok(PEAR_S5_FIRE,43,&request) || request.triggered!=1){fail_code(43,ERROR_INVALID_DATA);return 0;}
    ULONGLONG start=GetTickCount64();
    while(!active.ncdestroy && !error_step && GetTickCount64()-start<5000)
        if(!pump(20))break;
    if(error_step)return 0;
    if(!active.ncdestroy)return fail_code(43,WAIT_TIMEOUT);
    if(IsWindow(hwnd))return fail_code(44,ERROR_INVALID_DATA);
    active.hwnd_gone=1;
    if(!drain_cycle() || !pump(0))return 0;
    if(active.app_messages!=1 || active.reentries!=1 || active.sysclose!=1 || active.close!=1 ||
       active.destroy!=1 || active.ncdestroy!=1 || active.late_callbacks || active.title_checks!=1)
        return fail_code(45,ERROR_INVALID_DATA);
    static const char *const names[]={"cycle","hwnd","token","guest_teb","guest_tid","nccreate","create","app_messages",
        "reentries","sysclose","close","destroy","ncdestroy","late_callbacks","title_checks","hwnd_gone","drain_complete","callback_result"};
    uint64_t values[]={index,(uintptr_t)hwnd,active.token,main_teb,main_tid,active.nccreate,active.create,active.app_messages,
        active.reentries,active.sysclose,active.close,active.destroy,active.ncdestroy,active.late_callbacks,active.title_checks,
        active.hwnd_gone,active.drain_complete,active.callback_result};
    if(!emit("pear_window_cycle",names,values,18))return 0;
    ++cycles_done;return 1;
}
static int initialize(void)
{
    module=GetModuleHandleW(NULL);main_teb=current_teb();main_tid=GetCurrentThreadId();main_pid=GetCurrentProcessId();
    if(!module || !main_teb || !main_tid || !main_pid)return fail_code(1,ERROR_INVALID_DATA);
    /* The driver reference intentionally lasts until process exit. Its user
     * driver function table can remain registered after all windows close. */
    if(!(driver=LoadLibraryW(L"winemac.drv")))return fail(2);
    if(!(control=(window_control)(uintptr_t)GetProcAddress(driver,"PearStage5Control")))return fail(3);
    pear_s5_request request;
    if(!control_ok(PEAR_S5_INIT,4,&request) || !request.native_pid)return fail_code(4,ERROR_INVALID_DATA);
    native_pid=request.native_pid;
    static const char *const names[]={"module_base","wndproc","guest_teb","guest_tid","native_pid","driver_module","driver_control","cycles"};
    uint64_t values[]={(uintptr_t)module,(uintptr_t)PearWindowProc,main_teb,main_tid,native_pid,(uintptr_t)driver,(uintptr_t)control,PEAR_STAGE5_CYCLES};
    if(!emit("pear_window_identity",names,values,8))return 0;
    WNDCLASSW definition;memset(&definition,0,sizeof(definition));
    definition.lpfnWndProc=PearWindowProc;definition.hInstance=module;definition.lpszClassName=class_name;
    if(!RegisterClassW(&definition))return fail(5);
    class_registered=1;return 1;
}
static void cleanup(void)
{
    int ok=1;
    if(active.hwnd && IsWindow(active.hwnd)){
        if(!DestroyWindow(active.hwnd)){fail(70);ok=0;}
        if(IsWindow(active.hwnd)){fail_code(70,ERROR_INVALID_DATA);ok=0;}
    }
    if(class_registered && !class_unregistered){
        if(!UnregisterClassW(class_name,module)){fail(71);ok=0;}
        else class_unregistered=1;
    }
    cleanup_complete=ok;
}
void mainCRTStartup(void)
{
    if(initialize())for(unsigned index=1;index<=PEAR_STAGE5_CYCLES && !error_step;++index)if(!cycle(index))break;
    cleanup();
    if(!error_step && cycles_done==PEAR_STAGE5_CYCLES){
        pear_s5_request request;
        if(control_ok(PEAR_S5_FINAL,72,&request) && request.completed==PEAR_STAGE5_CYCLES &&
           request.created==PEAR_STAGE5_CYCLES && request.destroyed==PEAR_STAGE5_CYCLES &&
           request.deallocated==PEAR_STAGE5_CYCLES && !request.active)native_final=1;
        else fail_code(72,ERROR_INVALID_DATA);
    }
    unsigned passed=!error_step && cycles_done==PEAR_STAGE5_CYCLES && total_app==PEAR_STAGE5_CYCLES &&
        total_reentry==PEAR_STAGE5_CYCLES && total_close==PEAR_STAGE5_CYCLES && total_destroy==PEAR_STAGE5_CYCLES &&
        total_ncdestroy==PEAR_STAGE5_CYCLES && !total_late && class_registered && class_unregistered && native_final && cleanup_complete;
    static const char *const names[]={"passed","error_step","error_code","cycles","app_messages","reentries","closes","destroys",
        "ncdestroys","late_callbacks","class_registered","class_unregistered","native_final","cleanup_complete"};
    uint64_t values[]={passed,error_step,error_code,cycles_done,total_app,total_reentry,total_close,total_destroy,total_ncdestroy,
        total_late,class_registered,class_unregistered,native_final,cleanup_complete};
    if(!emit("pear_window_result",names,values,14))passed=0;
    ExitProcess(passed?0:1);
}
