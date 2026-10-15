/* Original Pear finite Stage 5 observer. SPDX-License-Identifier: MIT.
 * This opt-in fixture adds no persistent retain to a WineWindow or event queue.
 * It preserves Wine's Cocoa main thread, event queue and callback gateways. */
#import "config.h"
#import "macdrv.h"
#import "cocoa_event.h"
#import "cocoa_window.h"
#include "stage5_protocol.h"
#include "wine/pear_bootstrap.h"
#include <dlfcn.h>
#include <time.h>
#define PEAR_S5_CENSUS_IMPLEMENTATION
#include "stage5_census.h"
static struct pear_s5_census_state census={.lock=PTHREAD_MUTEX_INITIALIZER};

extern WINBOOL macdrv_ProcessEvents(DWORD mask);
NTSTATUS pear_stage5_window_control(void *opaque);
static pthread_mutex_t observer_lock = PTHREAD_MUTEX_INITIALIZER;
static pear_s5_request records[PEAR_STAGE5_CYCLES];
static unsigned lookup_live[PEAR_STAGE5_CYCLES],queue_empty[PEAR_STAGE5_CYCLES];
static unsigned wake_posted[PEAR_STAGE5_CYCLES],wake_consumed[PEAR_STAGE5_CYCLES];
static uint64_t consumed_barrier[PEAR_STAGE5_CYCLES];
static uint64_t diagnostic_close_hits[PEAR_STAGE5_CYCLES],diagnostic_first_ns[PEAR_STAGE5_CYCLES];
static unsigned initialized,created_count,completed_count,finalized,global_errors;
static uint64_t owner_teb,owner_tid,driver_base,driver_entry,event_sequence;
static pthread_t owner_thread;
static unsigned char (*mode_getter)(void);

static unsigned mode(void)
{
    unsigned value=mode_getter ? mode_getter() : 2;
    /* No foreign-mode Cocoa, pthread, logger or diagnostic call is permissible. */
    if(value) __builtin_trap();
    return value;
}
static int enabled(void) { return __atomic_load_n(&initialized,__ATOMIC_ACQUIRE)!=0; }
/* Diagnostic hooks receive identities only while their upstream caller owns the
 * C object. No census path sends a message to an observed window. */
void pear_stage5_census_object(unsigned kind,unsigned action,uintptr_t identity,uintptr_t target,unsigned type)
{
    if(!enabled())return;
    mode();pear_s5_census_object(&census,kind,action,identity,target,type);
}
void pear_stage5_census_draw(uintptr_t target,unsigned action,unsigned closing)
{
    if(!enabled())return;
    mode();pear_s5_census_draw(&census,target,action,closing);
}
static void census_snapshot(const pear_s5_request *record,unsigned attempt)
{
    struct pear_s5_census_snapshot snapshot;
    pear_s5_census_read(&census,record->cycle,record->window,WINDOW_GOT_FOCUS,&snapshot);
    const char *keys[]={"allocations","overflow","errors","events_live","events_target",
        "queries_live","queries_target","queries_unbound","details_truncated","ledger_complete",
        "draw_scheduled","draw_entered","draw_body_completed","draw_after_close",
        "marker_submitted","marker_completed","indirect_unobserved","epoch_only","direct_targets_only","draw_order_valid"};
    const uint64_t values[]={snapshot.allocations,snapshot.overflow,snapshot.errors,snapshot.events_live,
        snapshot.events_target,snapshot.queries_live,snapshot.queries_target,snapshot.queries_unbound,
        snapshot.details_truncated,snapshot.complete,snapshot.draw_scheduled,snapshot.draw_entered,
        snapshot.draw_completed,snapshot.draw_after_close,snapshot.marker_submitted,snapshot.marker_completed,
        snapshot.indirect_unobserved,1,1,snapshot.draw_completed<=snapshot.draw_entered && snapshot.draw_entered<=snapshot.draw_scheduled};
    for(unsigned part=0;part<5;part++){
        char line[512];
        int size=snprintf(line,sizeof(line),"{\"record_kind\":\"pear_stage5_census\",\"cycle\":%llu,\"attempt\":%u,\"part\":%u",record->cycle,attempt,part+1);
        if(size<0 || size>=sizeof(line))return;
        for(unsigned i=part*4;i<(part+1)*4;i++){
            int added=snprintf(line+size,sizeof(line)-size,",\"%s\":%llu",keys[i],values[i]);
            if(added<0 || added>=sizeof(line)-size)return;
            size+=added;
        }
        if(size+2>=sizeof(line))return;
        line[size++]='}';line[size++]='\n';
        ssize_t written;
        do {written=write(STDERR_FILENO,line,size);} while(written<0 && errno==EINTR);
    }
    for(unsigned i=0;i<snapshot.detail_count;i++){
        const struct pear_s5_census_detail *entry=snapshot.details+i;
        char line[256];
        int size=snprintf(line,sizeof(line),"{\"record_kind\":\"pear_stage5_census_live\",\"cycle\":%llu,\"attempt\":%u,\"ordinal\":%u,\"kind\":%u,\"type\":%u,\"target_match\":%u}\n",record->cycle,attempt,entry->ordinal,entry->kind,entry->type,entry->target_match);
        if(size>0 && size<sizeof(line)){
            ssize_t written;
            do {written=write(STDERR_FILENO,line,size);} while(written<0 && errno==EINTR);
        }
    }
}
static int owner(void)
{
    mode();
    return pthread_equal(pthread_self(),owner_thread) &&
        (uintptr_t)NtCurrentTeb()==owner_teb && GetCurrentThreadId()==owner_tid;
}
static void bad(pear_s5_request *record)
{
    ++global_errors;
    if(record) ++record->errors;
}
static pear_s5_request *by_window(const void *window)
{
    for(unsigned i=created_count;i;i--)
        if(lookup_live[i-1] && records[i-1].window==(uintptr_t)window) return records+i-1;
    return NULL;
}
static pear_s5_request *by_hwnd(const void *hwnd)
{
    for(unsigned i=created_count;i;i--)
        if(records[i-1].hwnd==(uintptr_t)hwnd) return records+i-1;
    return NULL;
}
static void emit_detail(const char *detail,int size)
{
    _Static_assert(PIPE_BUF>=512,"atomic fixture pipe records required");
    if(size<0 || size>220) __builtin_trap();
    pear_bootstrap_event("loader","stage5_window",detail);
}
/* Called with observer_lock held. All measured IDs and pointers stay private. */
static void event(pear_s5_request *record,unsigned phase,uint64_t value)
{
    char detail[221];
    uint64_t tid=0,seq=++event_sequence,cycle=record?record->cycle:0;
    unsigned main_thread=pthread_main_np(),current_mode=mode();
    if(pthread_threadid_np(NULL,&tid) || !tid || seq>16384) __builtin_trap();
    int n=snprintf(detail,sizeof(detail),",\"seq\":%llu,\"cycle\":%llu,\"phase\":%u,\"part\":1,\"hwnd\":%llu,\"window\":%llu,\"token\":%llu",
        seq,cycle,phase,record?record->hwnd:0,record?record->window:0,record?record->token:0);
    emit_detail(detail,n);
    n=snprintf(detail,sizeof(detail),",\"seq\":%llu,\"cycle\":%llu,\"phase\":%u,\"part\":2,\"thread_id\":%llu,\"main\":%u,\"mode\":%u,\"value\":%llu",
        seq,cycle,phase,tid,main_thread,current_mode,value);
    emit_detail(detail,n);
    if(phase==PEAR_S5_INITIALIZED){
        n=snprintf(detail,sizeof(detail),",\"seq\":%llu,\"cycle\":0,\"phase\":0,\"part\":3,\"driver_base\":%llu,\"driver_entry\":%llu,\"teb\":%llu,\"native_tid\":%llu",
            seq,driver_base,driver_entry,owner_teb,owner_tid);
        emit_detail(detail,n);
    }
}
static void common_response(pear_s5_request *request)
{
    request->host_entry=request->host_exit=mode();
    request->native_pid=getpid();request->native_tid=owner_tid;request->teb=owner_teb;
    request->driver_base=driver_base;request->driver_entry=driver_entry;
}
static void copy_response(pear_s5_request *request,const pear_s5_request *record)
{
    uint64_t *dst=&request->window;
    const uint64_t *src=&record->window;
    for(unsigned i=0;i<(sizeof(*record)-offsetof(pear_s5_request,window))/sizeof(uint64_t);i++)dst[i]=src[i];
    if(global_errors && !request->errors) request->errors=global_errors;
    common_response(request);
}

/* Runs on the owning Wine thread before invoking OnMainThread for creation. */
void pear_stage5_window_create_begin(void *hwnd)
{
    static const WCHAR fixture_class[]={'P','e','a','r','S','t','a','g','e','5','W','i','n','d','o','w',0};
    WCHAR name[32];
    UNICODE_STRING text={0,sizeof(name),name};
    if(!enabled())return;
    mode();
    if(NtUserGetClassName(hwnd,FALSE,&text)!=16 || memcmp(name,fixture_class,16*sizeof(WCHAR)))return;
    pthread_mutex_lock(&observer_lock);
    if(!owner() || finalized || created_count>=PEAR_STAGE5_CYCLES || created_count!=completed_count){bad(NULL);goto done;}
    pear_s5_request *record=records+created_count++;
    record->cycle=created_count;record->hwnd=(uintptr_t)hwnd;
    record->token=PEAR_STAGE5_TOKEN(record->cycle);record->active=1;
done:
    pthread_mutex_unlock(&observer_lock);
}
void pear_stage5_window_created(void *hwnd,void *window,void *queue)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    /* A newly allocated auxiliary window may reuse a retired address. Preserve
     * historical evidence, but stop treating that distinct object as our target. */
    for(unsigned i=0;i<created_count;i++){
        if(lookup_live[i] && records[i].window==(uintptr_t)window){
            if(records[i].deallocated)lookup_live[i]=0;
            else bad(records+i);
        }
    }
    pear_s5_request *record=by_hwnd(hwnd);
    if(record && !record->completed){
        if(!pthread_main_np() || !window || !queue || record->created){bad(record);goto done;}
        record->window=(uintptr_t)window;record->queue=(uintptr_t)queue;record->created=1;
        lookup_live[record->cycle-1]=1;
        pear_s5_census_register_window(&census,record->cycle,(uintptr_t)window);
        event(record,PEAR_S5_CREATED,record->queue);
    }
done:
    pthread_mutex_unlock(&observer_lock);
}
void pear_stage5_window_close_requested(void *window)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(record){
        if(!pthread_main_np() || !record->triggered || record->cocoa_close || record->destroyed){bad(record);goto done;}
        record->cocoa_close=1;event(record,PEAR_S5_CLOSE_REQUESTED,0);
    }
done:
    pthread_mutex_unlock(&observer_lock);
}
/* This hook calls the normal win32u/ntdll callback route; it never calls a PE
 * function pointer. The original WINDOW_CLOSE_REQUESTED handler then continues. */
void pear_stage5_window_dispatch(void *window,void *hwnd)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(!record){pthread_mutex_unlock(&observer_lock);return;}
    if(!owner() || !record->armed || record->hwnd!=(uintptr_t)hwnd || !record->cocoa_close || record->dispatched || record->destroyed){
        if(record->destroyed || record->completed)++record->late;
        bad(record);pthread_mutex_unlock(&observer_lock);return;
    }
    record->dispatched=1;event(record,PEAR_S5_DISPATCHED,PEAR_STAGE5_MESSAGE);
    uint64_t cycle=record->cycle,token=record->token;
    pthread_mutex_unlock(&observer_lock);
    LRESULT result=NtUserMessageCall(hwnd,PEAR_STAGE5_MESSAGE,cycle,token,NULL,NtUserSendMessage,FALSE);
    mode();pthread_mutex_lock(&observer_lock);
    record->callback_result=result;record->callback_returned++;
    if((uint64_t)result!=PEAR_STAGE5_REPLY(token) || record->reentered!=1 || record->title_changed!=1)bad(record);
    event(record,PEAR_S5_CALLBACK_RETURNED,(uint64_t)result);
    pthread_mutex_unlock(&observer_lock);
}
/* Count any dispatch after the target queue was purged, not only our message. */
void pear_stage5_window_any_event(void *window)
{
    if(!enabled() || !window)return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(record && record->discarded){++record->late;bad(record);}
    pthread_mutex_unlock(&observer_lock);
}
void pear_stage5_window_title_changed(void *window,const void *title)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(record && record->dispatched && !record->callback_returned){
        if(!pthread_main_np() || record->title_changed || record->cocoa_destroyed ||
           ![(NSString *)title isEqualToString:@"Pear Stage 5 callback"]){bad(record);goto done;}
        record->title_changed=1;event(record,PEAR_S5_TITLE_CHANGED,0);
    }else if(record && record->cocoa_destroyed){++record->late;bad(record);}
done:
    pthread_mutex_unlock(&observer_lock);
}
void pear_stage5_window_destroy_begin(void *window)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(record){
        if(!owner() || record->destroyed || record->callback_returned!=1)bad(record);
        record->destroyed++;event(record,PEAR_S5_DESTROYED,0);
    }
    pthread_mutex_unlock(&observer_lock);
}
void pear_stage5_window_cocoa_destroyed(void *window)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(record){
        if(!pthread_main_np() || record->destroyed!=1 || record->cocoa_destroyed)bad(record);
        record->cocoa_destroyed++;event(record,PEAR_S5_COCOA_DESTROYED,0);
    }
    pthread_mutex_unlock(&observer_lock);
}
void pear_stage5_window_discarded(void *window)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(record){
        if(!owner() || record->cocoa_destroyed!=1 || record->discarded)bad(record);
        record->discarded++;event(record,PEAR_S5_DISCARDED,0);
    }
    pthread_mutex_unlock(&observer_lock);
}
void pear_stage5_window_deallocated(void *window)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(record){
        if(record->cocoa_destroyed!=1 || record->deallocated)bad(record);
        record->deallocated++;event(record,PEAR_S5_DEALLOCATED,0);
    }
    pthread_mutex_unlock(&observer_lock);
}
/* Reuse ordinary AppKit dispatch. Payload binds the cycle and unique turn,
 * never a window reference or synthesized mouse/keyboard input. */
void pear_stage5_window_wake_consumed(unsigned subtype,intptr_t tag,intptr_t payload,intptr_t window_number)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    uint64_t cycle=(uint64_t)payload>>8,ordinal=(uint64_t)payload&255;
    if(subtype!=PEAR_STAGE5_WAKE_SUBTYPE || tag!=PEAR_STAGE5_WAKE_TAG || payload<=0 ||
       cycle<1 || cycle>created_count || ordinal<1 || ordinal>100 || window_number || !pthread_main_np()){
        bad(NULL);pthread_mutex_unlock(&observer_lock);return;
    }
    pear_s5_request *record=records+cycle-1;
    if(wake_posted[cycle-1]!=ordinal || wake_consumed[cycle-1]+1!=ordinal ||
       record->discarded!=1 || record->completed){
        bad(record);pthread_mutex_unlock(&observer_lock);return;
    }
    wake_consumed[cycle-1]=ordinal;consumed_barrier[cycle-1]=record->barriers;
    event(record,PEAR_S5_WAKE_CONSUMED,PEAR_STAGE5_WAKE_VALUE(cycle,ordinal));
    pthread_mutex_unlock(&observer_lock);
}
/* Called outside observer_lock on the owner Wine thread after ProcessEvents.
 * Each bit records a separate observed predicate; none promises future idleness. */
static unsigned queue_state(const pear_s5_request *record,unsigned fd_empty)
{
    struct macdrv_thread_data *data=macdrv_thread_data();
    struct pear_s5_diag_snapshot facts={0};
    unsigned flags=!!fd_empty,matches=1;
    if(!data || !data->queue)return 0;
    if(!data->current_event)flags|=4;
    pear_stage5_queue_snapshot(data->queue,record?record->window:0,&facts);
    if(!facts.queue_total)flags|=2;
    if(record)matches=(uintptr_t)data->queue==record->queue;
    else for(unsigned i=0;i<PEAR_STAGE5_CYCLES;i++)matches&=(uintptr_t)data->queue==records[i].queue;
    if(matches)flags|=8;
    return flags;
}
/* This counter observes the existing controller notification handler; it never
 * owns or dereferences the target object. */
void pear_stage5_window_diagnostic_closed(void *window)
{
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(record)++diagnostic_close_hits[record->cycle-1];
    pthread_mutex_unlock(&observer_lock);
}
/* This entry marker is distinct from the required post-super deallocation
 * event. It can diagnose a destructor that begins but never completes. */
void pear_stage5_window_diagnostic_deallocating(void *window)
{
    uint64_t cycle=0;
    if(!enabled())return;
    mode();pthread_mutex_lock(&observer_lock);
    pear_s5_request *record=by_window(window);
    if(record)cycle=record->cycle;
    pthread_mutex_unlock(&observer_lock);
    if(cycle){
        char line[128];
        int size=snprintf(line,sizeof(line),"{\"record_kind\":\"pear_stage5_dealloc_enter\",\"cycle\":%llu}\n",cycle);
        if(size>0 && size<sizeof(line)){
            ssize_t written;
            do {written=write(STDERR_FILENO,line,size);} while(written<0 && errno==EINTR);
        }
    }
}
/* A pending deallocation receives at most two private snapshots. The upstream
 * ProcessEvents BOOL describes its signal fd, not unconditional array emptiness.
 * Snapshot fields are diagnostics only and never authorize completion. */
static void ownership_snapshot(pear_s5_request *record,unsigned attempt,unsigned fd_empty)
{
    struct pear_s5_diag_snapshot facts={0},*out=&facts;
    struct macdrv_thread_data *data=macdrv_thread_data();
    const macdrv_event *current=data?data->current_event:NULL;
    uintptr_t identity=record->window;
    struct timespec stamp;
    unsigned clock_ok=clock_gettime(CLOCK_MONOTONIC,&stamp)==0;
    uint64_t elapsed_us=0;
    if(clock_ok){
        uint64_t now=(uint64_t)stamp.tv_sec*UINT64_C(1000000000)+(uint64_t)stamp.tv_nsec;
        uint64_t *first=&diagnostic_first_ns[record->cycle-1];
        if(!*first)*first=now;
        if(now<*first)clock_ok=0;
        else elapsed_us=(now-*first)/1000;
    }
    facts.fd_empty=fd_empty;
    facts.wine_event_present=!!current;
    if(current){
        facts.wine_event_type=current->type;
        facts.wine_event_target=(uintptr_t)current->window==identity;
        facts.wine_event_refs=__atomic_load_n(&current->refs,__ATOMIC_ACQUIRE);
    }
    facts.queue_matches=data && (uintptr_t)data->queue==record->queue;
    if(data)pear_stage5_queue_snapshot(data->queue,identity,&facts);
    OnMainThread(^{ mode();pear_stage5_diag_app(identity,out); });
    pthread_mutex_lock(&observer_lock);
    facts.close_observer_hits=diagnostic_close_hits[record->cycle-1];
    facts.deallocated=record->deallocated;
    pthread_mutex_unlock(&observer_lock);
    census_snapshot(record,attempt);
    static const char *const keys[]={
        "main_thread","app_windows","app_target","key_windows","key_target",
        "dragged_windows","dragged_target","capture_target","last_mouse_target",
        "app_event_type","app_event_target","close_observer_hits","pending_main_requests",
        "queue_total","queue_target","queue_target_event_refs","queue_target_query_refs",
        "wine_event_present","wine_event_type","wine_event_target","wine_event_refs",
        "queue_matches","deallocated","fd_empty"};
    const uint64_t values[]={facts.main_thread,facts.app_windows,facts.app_target,facts.key_windows,facts.key_target,
        facts.dragged_windows,facts.dragged_target,facts.capture_target,facts.last_mouse_target,
        facts.app_event_type,facts.app_event_target,facts.close_observer_hits,facts.pending_main_requests,
        facts.queue_total,facts.queue_target,facts.queue_target_event_refs,facts.queue_target_query_refs,
        facts.wine_event_present,facts.wine_event_type,facts.wine_event_target,facts.wine_event_refs,
        facts.queue_matches,facts.deallocated,facts.fd_empty};
    _Static_assert(sizeof(facts)==24*sizeof(uint64_t),"fixed diagnostic scalar layout required");
    for(unsigned part=0;part<3;part++){
        char line[512];
        int size=snprintf(line,sizeof(line),"{\"record_kind\":\"pear_stage5_ownership\",\"cycle\":%llu,\"attempt\":%u,\"part\":%u,\"clock_ok\":%u,\"elapsed_us\":%llu",
            record->cycle,attempt,part+1,clock_ok,elapsed_us);
        if(size<0 || size>=sizeof(line))return;
        for(unsigned i=part*8;i<(part+1)*8;i++){
            int added=snprintf(line+size,sizeof(line)-size,",\"%s\":%llu",keys[i],values[i]);
            if(added<0 || added>=sizeof(line)-size)return;
            size+=added;
        }
        if(size+2>=sizeof(line))return;
        line[size++]='}';line[size++]='\n';
        ssize_t written;
        do {written=write(STDERR_FILENO,line,size);} while(written<0 && errno==EINTR);
    }
}
static int complete(const pear_s5_request *r)
{
    return r->created==1 && r->armed==1 && r->triggered==1 && r->cocoa_close==1 &&
        r->dispatched==1 && r->reentered==1 && r->title_changed==1 && r->callback_returned==1 &&
        r->destroyed==1 && r->cocoa_destroyed==1 && r->discarded==1 && r->deallocated==1 &&
        r->barriers && r->drains && queue_empty[r->cycle-1] &&
        wake_posted[r->cycle-1]>0 && wake_posted[r->cycle-1]<=100 &&
        wake_posted[r->cycle-1]==wake_consumed[r->cycle-1] &&
        r->barriers>consumed_barrier[r->cycle-1] && !r->late && !r->errors && !global_errors;
}
NTSTATUS pear_stage5_window_control(void *opaque)
{
    pear_s5_request *request=opaque,*record=NULL;
    NTSTATUS status=STATUS_SUCCESS;
    if(!request || request->magic!=PEAR_STAGE5_MAGIC || request->version!=1)return STATUS_INVALID_PARAMETER;
    if(request->operation==PEAR_S5_INIT){
        const char *flag=getenv("PEAR_WINE_STAGE5_FIXTURE"),*nonce=getenv("PEAR_BOOTSTRAP_NONCE");
        Dl_info info;
        if(!flag || strcmp(flag,"1") || !nonce || strlen(nonce)!=32 || strspn(nonce,"0123456789abcdef")!=32)return STATUS_NOT_SUPPORTED;
        mode_getter=dlsym(RTLD_DEFAULT,"os_custom_x18_abi_enabled");
        if(!mode_getter)return STATUS_NOT_SUPPORTED;
        mode();
        if(enabled() || request->cycle || request->hwnd || request->token || pthread_main_np() ||
           request->guest_teb!=(uintptr_t)NtCurrentTeb() || request->guest_tid!=GetCurrentThreadId())return STATUS_INVALID_PARAMETER;
        if(!dladdr(pear_stage5_window_control,&info) || !info.dli_fbase)return STATUS_NOT_SUPPORTED;
        owner_thread=pthread_self();owner_teb=(uintptr_t)NtCurrentTeb();owner_tid=GetCurrentThreadId();
        driver_base=(uintptr_t)info.dli_fbase;driver_entry=(uintptr_t)pear_stage5_window_control;
        __atomic_store_n(&initialized,1,__ATOMIC_RELEASE);
        pthread_mutex_lock(&observer_lock);event(NULL,PEAR_S5_INITIALIZED,0);common_response(request);pthread_mutex_unlock(&observer_lock);
        pear_bootstrap_snapshot("loader","stage5_window_images");
        pear_bootstrap_images("loader");
        pear_s5_census_marker(&census,0);
        dispatch_async(dispatch_get_main_queue(), ^{ mode();pear_s5_census_marker(&census,1); });
        return STATUS_SUCCESS;
    }
    if(!enabled())return STATUS_NOT_SUPPORTED;
    if(!owner() || request->guest_teb!=owner_teb || request->guest_tid!=owner_tid)return STATUS_INVALID_PARAMETER;
    pthread_mutex_lock(&observer_lock);
    if(finalized){status=STATUS_INVALID_PARAMETER;goto done;}
    if(request->operation==PEAR_S5_FINAL){
        if(request->cycle || request->hwnd || request->token || completed_count!=PEAR_STAGE5_CYCLES || global_errors){status=STATUS_INVALID_PARAMETER;goto done;}
        pthread_mutex_unlock(&observer_lock);
        OnMainThread(^{ mode(); });
        WINBOOL drained=macdrv_ProcessEvents(QS_ALLINPUT);
        unsigned flags=queue_state(NULL,!!drained);
        pthread_mutex_lock(&observer_lock);
        event(NULL,PEAR_S5_FINAL_DRAIN,flags);
        if(flags!=15){status=STATUS_UNSUCCESSFUL;goto done;}
        memset(&request->window,0,sizeof(*request)-offsetof(pear_s5_request,window));
        for(unsigned i=0;i<PEAR_STAGE5_CYCLES;i++){
            if(!complete(records+i) || records[i].completed!=1){status=STATUS_INVALID_PARAMETER;break;}
            uint64_t *dst=&request->created,*src=&records[i].created;
            for(unsigned j=0;j<(sizeof(*request)-offsetof(pear_s5_request,created))/sizeof(uint64_t);j++)dst[j]+=src[j];
        }
        if(!status){finalized=1;event(NULL,PEAR_S5_FINALIZED,PEAR_STAGE5_CYCLES);}
        goto done;
    }
    if(!request->cycle || request->cycle>created_count){status=STATUS_INVALID_PARAMETER;goto done;}
    record=records+request->cycle-1;
    if(request->hwnd!=record->hwnd || request->token!=record->token || record->completed){status=STATUS_INVALID_PARAMETER;goto done;}
    switch(request->operation){
    case PEAR_S5_ARM:
        if(!record->created || record->armed || !record->window || !record->queue){status=STATUS_INVALID_PARAMETER;break;}
        record->armed=1;event(record,PEAR_S5_ARMED,0);break;
    case PEAR_S5_FIRE:{
        if(record->armed!=1 || record->triggered || record->destroyed){status=STATUS_INVALID_PARAMETER;break;}
        WineWindow *window=(WineWindow *)(uintptr_t)record->window;
        pthread_mutex_unlock(&observer_lock);
        OnMainThread(^{
            mode();pthread_mutex_lock(&observer_lock);
            if(!pthread_main_np() || record->triggered || record->destroyed)bad(record);
            record->triggered++;event(record,PEAR_S5_TRIGGERED,0);
            pthread_mutex_unlock(&observer_lock);
            [window performClose:nil];
        });
        pthread_mutex_lock(&observer_lock);
        if(record->cocoa_close!=1)status=STATUS_UNSUCCESSFUL;
        break;
    }
    case PEAR_S5_REENTRY:
        if(record->dispatched!=1 || record->callback_returned || record->reentered || record->destroyed){status=STATUS_INVALID_PARAMETER;break;}
        record->reentered=1;event(record,PEAR_S5_REENTERED,0);
        pthread_mutex_unlock(&observer_lock);
        OnMainThread(^{ mode(); }); /* Flush the ordinary SetWindowText async block. */
        pthread_mutex_lock(&observer_lock);
        if(record->title_changed!=1)status=STATUS_UNSUCCESSFUL;
        break;
    case PEAR_S5_DRAIN:{
        if(record->destroyed!=1 || record->discarded!=1 || record->drains>=100){status=STATUS_INVALID_PARAMETER;break;}
        unsigned diagnose=!record->deallocated && (record->drains==0 || record->drains==99);
        pthread_mutex_unlock(&observer_lock);
        /* Capture only the permanent fixed record, never the destroyed object. */
        OnMainThread(^{
            mode();
            /* At most one owned turn is pending. The first is mandatory;
             * later turns stop once actual post-super deallocation is observed. */
            unsigned index=record->cycle-1,ordinal=0;
            pthread_mutex_lock(&observer_lock);
            if(wake_posted[index]==wake_consumed[index] && wake_posted[index]<100 &&
               (!wake_posted[index] || !record->deallocated)) ordinal=wake_posted[index]+1;
            pthread_mutex_unlock(&observer_lock);
            if(ordinal){
                int posted=pear_stage5_post_wake(PEAR_STAGE5_WAKE_PAYLOAD(record->cycle,ordinal));
                pthread_mutex_lock(&observer_lock);
                /* A reentrant or concurrent deallocation during a later post
                 * is an explicit failed observation, never a relaxed ordering. */
                if(!posted || wake_posted[index]+1!=ordinal || wake_consumed[index]+1!=ordinal ||
                   (ordinal>1 && record->deallocated))bad(record);
                if(posted){wake_posted[index]=ordinal;event(record,PEAR_S5_WAKE_POSTED,PEAR_STAGE5_WAKE_VALUE(record->cycle,ordinal));}
                pthread_mutex_unlock(&observer_lock);
            }
            pthread_mutex_lock(&observer_lock);record->barriers++;
            event(record,PEAR_S5_BARRIER,record->barriers);pthread_mutex_unlock(&observer_lock);
        });
        WINBOOL drained=macdrv_ProcessEvents(QS_ALLINPUT);
        unsigned flags=queue_state(record,!!drained);
        if(diagnose)ownership_snapshot(record,record->drains+1,!!drained);
        pthread_mutex_lock(&observer_lock);
        queue_empty[record->cycle-1]=flags==15;
        record->drains++;
        /* Bits: fd empty, array empty, no current Wine event, queue identity. */
        event(record,PEAR_S5_DRAINED,(record->drains<<4)|flags);
        if(!(flags&8) || global_errors || record->errors || record->late)status=STATUS_UNSUCCESSFUL;
        else if(!complete(record))status=STATUS_PENDING;
        else {record->completed=1;record->active=0;completed_count++;event(record,PEAR_S5_COMPLETED,1);}
        break;
    }
    default:status=STATUS_INVALID_PARAMETER;break;
    }
    if(record){if(status && status!=STATUS_PENDING)bad(record);copy_response(request,record);}
done:
    if(!record)common_response(request);
    pthread_mutex_unlock(&observer_lock);
    return status;
}
