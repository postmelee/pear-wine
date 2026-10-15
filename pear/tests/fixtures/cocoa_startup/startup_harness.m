/* Original Pear test: Foundation/CF ownership bookkeeping, no AppKit windows. */
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static unsigned checks, failures, alloc_calls, fail_alloc, live_requests, live_envelopes, live_locks;
static unsigned app_creations, controller_calls, run_calls, source_calls, source_fail, lock_fail, date_fail;
static unsigned wait_mode, expected_run_requests, active_empty_checks, wait_calls, detach_calls;
static unsigned conditions_published, caller_done, main_identified, source_empty_after_return;
static unsigned post_timeout_locks, claim_races;
static _Thread_local unsigned timed_wait_failed;
static unsigned long long observed_tick;
static uint64_t observed_uptime;
static id fake_app;
static void *last_envelope;
static dispatch_semaphore_t entered, returned;
static void check(int value, const char *name)
{
    __atomic_add_fetch(&checks,1,__ATOMIC_RELAXED);
    if (!value) { __atomic_add_fetch(&failures,1,__ATOMIC_RELAXED); fprintf(stderr,"FAIL %s\n",name); }
}
static CFRunLoopSourceRef real_create(CFAllocatorRef a, CFIndex o, CFRunLoopSourceContext *c)
{ return CFRunLoopSourceCreate(a,o,c); }
static void *test_calloc(size_t count, size_t size);
static void test_free(void *pointer);
static CFRunLoopSourceRef test_create(CFAllocatorRef a, CFIndex o, CFRunLoopSourceContext *c);

@interface TestConditionLock : NSConditionLock @end
@interface TestDate : NSDate @end
@interface TestThread : NSObject
+ (void)detachNewThreadSelector:(SEL)s toTarget:(id)t withObject:(id)o;
@end
@interface WineApplication : NSObject
+ (id)sharedApplication;
- (void)setWineController:(id)controller;
- (void)run;
@end
@interface WineApplicationController : NSObject
+ (id)sharedController;
- (void)computeEventTimeAdjustmentFromTicks:(unsigned long long)ticks uptime:(uint64_t)uptime;
@end

/* Include the exact candidate, replacing only external allocation, clock-date,
   source-creation and AppKit/NSThread services with declared test boundaries. */
#define NSApp fake_app
#define NSConditionLock TestConditionLock
#define NSDate TestDate
#define NSThread TestThread
#define calloc test_calloc
#define free test_free
#define CFRunLoopSourceCreate test_create
#include "after/cocoa_main.m"
#undef CFRunLoopSourceCreate
#undef free
#undef calloc
#undef NSThread
#undef NSDate
#undef NSConditionLock
#undef NSApp

struct allocation { void *pointer; size_t bytes; unsigned kind, live; };
static struct allocation allocations[128];
static unsigned allocation_count;

static void *test_calloc(size_t count, size_t size)
{
    ++alloc_calls;
    if (fail_alloc && alloc_calls==fail_alloc) return NULL;
    if (allocation_count==128) { check(0,"bounded allocation ledger"); return NULL; }
    void *value=calloc(count,size);
    unsigned kind=size==sizeof(struct cocoa_app_startup_request)?1:2;
    check(count==1 && (size==sizeof(struct cocoa_app_startup_request)||size==sizeof(struct cocoa_app_startup_source)),"declared allocation");
    allocations[allocation_count++]=(struct allocation){value,count*size,kind,1};
    if(kind==1)++live_requests;else {++live_envelopes;last_envelope=value;}
    return value;
}
static void test_free(void *pointer)
{
    if(!pointer)return;
    for(unsigned i=allocation_count;i>0;--i){struct allocation *a=&allocations[i-1];
        if(a->live && a->pointer==pointer){a->live=0;if(a->kind==1)--live_requests;else --live_envelopes;free(pointer);return;}}
    check(0,"release only a currently owned allocation");
}
static CFRunLoopSourceRef test_create(CFAllocatorRef a, CFIndex o, CFRunLoopSourceContext *c)
{
    source_calls++;
    check(c->retain==retain_startup_source && c->release==release_startup_source && c->perform==run_cocoa_app,"actual source callbacks");
    if(source_fail)return NULL;
    return real_create(a,o,c);
}
@implementation TestDate
+ (instancetype)dateWithTimeIntervalSinceNow:(NSTimeInterval)seconds
{
    check(seconds==5,"unchanged five-second deadline");
    return date_fail ? nil : (id)[NSDate dateWithTimeIntervalSinceNow:seconds];
}
@end
@implementation TestThread
+ (void)detachNewThreadSelector:(SEL)s toTarget:(id)t withObject:(id)o
{ (void)s;(void)t;(void)o;detach_calls++; }
@end
@implementation TestConditionLock
- (id)initWithCondition:(NSInteger)condition
{
    if(lock_fail){[self release];return nil;}
    self=[super initWithCondition:condition];if(self)live_locks++;return self;
}
- (void)dealloc
{
    /* A failed init never increments the live ledger. */
    if(!lock_fail)live_locks--;
    [super dealloc];
}
- (void)unlockWithCondition:(NSInteger)condition
{ conditions_published++;[super unlockWithCondition:condition]; }
- (void)lock
{
    if(timed_wait_failed)__atomic_add_fetch(&post_timeout_locks,1,__ATOMIC_RELAXED);
    [super lock];
}
- (BOOL)lockWhenCondition:(NSInteger)condition beforeDate:(NSDate *)date
{
    wait_calls++;
    check(condition==COCOA_APP_RUNNING,"original result condition");
    if(wait_mode==0){timed_wait_failed=1;return NO;} /* Expired wait; no CF dispatch. */
    if(wait_mode==3){
        check(dispatch_semaphore_wait(entered,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC))==0,"callback entered before timeout");
        timed_wait_failed=1;return NO;
    }
    check(pthread_main_np(),"deterministic CF dispatch main thread");
    CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.05,true);
    if(wait_mode==2){timed_wait_failed=1;return NO;} /* Completion occurred, but timed wait reports failure. */
    return [super lockWhenCondition:condition beforeDate:date];
}
@end
@implementation WineApplication
+ (id)sharedApplication
{ app_creations++;fake_app=[[self alloc]init];return fake_app; }
- (void)setWineController:(id)controller { check(controller!=nil,"mock controller available"); }
- (void)run
{
    run_calls++;
    check(live_requests==expected_run_requests,"callback request ownership released before simulated run");
    check(live_locks==expected_run_requests,"callback lock ownership released before simulated run");
    if(expected_run_requests==1){
        unsigned found=0;
        for(unsigned i=0;i<allocation_count;i++)if(allocations[i].live && allocations[i].kind==1){
            struct cocoa_app_startup_request *request=allocations[i].pointer;
            check(__atomic_load_n(&request->refs,__ATOMIC_ACQUIRE)==1,"only caller request reference remains during synchronous run");found++;
        }
        check(found==1,"live caller request identified before refcount read");
    }
    check(live_envelopes==1,"active CF callback retains source envelope");
    if(live_envelopes==1){
        struct cocoa_app_startup_source *envelope=last_envelope;
        check(__atomic_load_n(&envelope->request,__ATOMIC_ACQUIRE)==NULL,"active envelope has no request payload");
        active_empty_checks++;
    }
    if(wait_mode==3)check(__atomic_load_n(&caller_done,__ATOMIC_ACQUIRE)==1,"timed-out caller returned before simulated run");
}
@end
@implementation WineApplicationController
+ (id)sharedController
{
    static id controller; if(!controller)controller=[[self alloc]init];controller_calls++;
    if(wait_mode==3){
        main_identified=pthread_main_np();
        dispatch_semaphore_signal(entered);
        check(dispatch_semaphore_wait(returned,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC))==0,"caller cleanup does not join active callback");
        check(live_requests==1 && live_locks==1,"active callback owns request after caller timeout");
    }
    return controller;
}
- (void)computeEventTimeAdjustmentFromTicks:(unsigned long long)ticks uptime:(uint64_t)uptime
{ observed_tick=ticks;observed_uptime=uptime; }
@end

static void reset(void)
{
    check(live_requests==0 && live_envelopes==0 && live_locks==0,"previous case released all request resources");
    [fake_app release];fake_app=nil;last_envelope=NULL;
    alloc_calls=fail_alloc=source_calls=source_fail=lock_fail=date_fail=0;
    app_creations=controller_calls=run_calls=wait_calls=detach_calls=0;
    conditions_published=caller_done=main_identified=0;
    timed_wait_failed=0;
    wait_mode=1;expected_run_requests=1;observed_tick=0;observed_uptime=0;
}
static void released(void)
{
    check(live_requests==0,"request released");check(live_locks==0,"condition released");check(live_envelopes==0,"envelope released after callback return");
    unsigned before=app_creations;
    CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.001,true);
    check(app_creations==before,"cleanup invalidated pending source");
    check(post_timeout_locks==0,"timeout cleanup does not reacquire condition");
    source_empty_after_return++;
}
static void *timed_caller(void *unused)
{
    (void)unused;
    @autoreleasepool {
        int result=macdrv_start_cocoa_app(333);
        check(result==-1,"in-flight timeout remains failure");
        __atomic_store_n(&caller_done,1,__ATOMIC_RELEASE);
        dispatch_semaphore_signal(returned);
    }
    return NULL;
}

struct claim_worker {
    struct cocoa_app_startup_source *envelope;
    struct cocoa_app_startup_request *claim;
    dispatch_semaphore_t ready, start;
};
static void *race_claim(void *data)
{
    struct claim_worker *worker=data;
    dispatch_semaphore_signal(worker->ready);
    if(dispatch_semaphore_wait(worker->start,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC)))return (void*)1;
    /* Only the pointer transfer races. The caller retains payload and envelope
       until both joins; allocation ledgers are touched on the main thread. */
    worker->claim=claim_startup_request(worker->envelope);
    return NULL;
}

int main(void)
{
@autoreleasepool {
    reset();check(macdrv_start_cocoa_app(111)==0,"completed success");
    check(app_creations==1 && run_calls==1 && conditions_published==1,"one initialization and publication");
    check(observed_tick==111 && observed_uptime>0,"request timing preserved");released();

    reset();fake_app=[[NSObject alloc]init];
    check(macdrv_start_cocoa_app(111)==1,"completed incompatible application failure");
    check(run_calls==0 && app_creations==0 && conditions_published==1,"failure does not enter run");released();

    reset();fake_app=[[WineApplication alloc]init];
    check(macdrv_start_cocoa_app(111)==0,"existing compatible app success");
    check(run_calls==0 && app_creations==0,"existing app run behavior preserved");released();

    for(unsigned failure=1;failure<=5;failure++){
        reset();if(failure==1)fail_alloc=1;if(failure==2)lock_fail=1;if(failure==3)date_fail=1;if(failure==4)fail_alloc=2;if(failure==5)source_fail=1;
        check(macdrv_start_cocoa_app(111)==-1,"partial allocation/source failure remains unavailable");
        check(app_creations==0 && wait_calls==0,"failed preparation schedules no initialization");released();
    }

    reset();wait_mode=0;check(macdrv_start_cocoa_app(222)==-1,"pending timeout");
    check(app_creations==0 && conditions_published==0,"pending cancellation does not initialize");released();

    reset();wait_mode=2;check(macdrv_start_cocoa_app(222)==-1,"completion cannot upgrade unsuccessful timed wait");
    check(conditions_published==1 && run_calls==1,"completion/timeout race retained");released();

    reset();wait_mode=3;expected_run_requests=0;
    entered=dispatch_semaphore_create(0);returned=dispatch_semaphore_create(0);
    pthread_t thread;int created=pthread_create(&thread,NULL,timed_caller,NULL);
    check(created==0,"owned caller thread created");if(created)return 2;
    CFAbsoluteTime deadline=CFAbsoluteTimeGetCurrent()+3;
    while(!__atomic_load_n(&caller_done,__ATOMIC_ACQUIRE) && CFAbsoluteTimeGetCurrent()<deadline)
        CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.02,true);
    check(__atomic_load_n(&caller_done,__ATOMIC_ACQUIRE)==1,"owned caller finished within bound");
    if(!caller_done)return 2;
    check(pthread_join(thread,NULL)==0,"owned caller joined");
    check(main_identified==1 && run_calls==1 && conditions_published==1,"late callback preserves local run decision on main");
    check(observed_tick==333,"late callback timing survives caller return");
    dispatch_release(entered);dispatch_release(returned);released();

    reset();struct cocoa_app_startup_request *request=test_calloc(1,sizeof(*request));request->refs=1;
    struct cocoa_app_startup_source *envelope=test_calloc(1,sizeof(*envelope));envelope->refs=1;envelope->request=retain_startup_request(request);
    struct cocoa_app_startup_request *claim=claim_startup_request(envelope);
    check(claim==request && claim_startup_request(envelope)==NULL,"request claim transfers once");
    unsigned creations=app_creations;
    run_cocoa_app(envelope);
    check(app_creations==creations,"callback that loses claim performs no initialization");
    check(request->refs==2,"claim does not invent or drop reference");
    release_startup_source(envelope);check(live_requests==1,"claim independently owns payload");
    release_startup_request(request);check(live_requests==1,"callback owner survives caller release");
    release_startup_request(claim);released();

    for(unsigned iteration=0;iteration<16;iteration++){
        reset();request=test_calloc(1,sizeof(*request));request->refs=1;
        envelope=test_calloc(1,sizeof(*envelope));envelope->refs=1;envelope->request=retain_startup_request(request);
        dispatch_semaphore_t ready=dispatch_semaphore_create(0),start=dispatch_semaphore_create(0);
        struct claim_worker workers[2]={{envelope,NULL,ready,start},{envelope,NULL,ready,start}};
        pthread_t threads[2];
        for(unsigned i=0;i<2;i++){
            created=pthread_create(&threads[i],NULL,race_claim,&workers[i]);
            check(created==0,"claim/cancel contender created");
            if(created){
                for(unsigned j=0;j<i;j++)dispatch_semaphore_signal(start);
                for(unsigned j=0;j<i;j++)pthread_join(threads[j],NULL);
                return 2;
            }
        }
        for(unsigned i=0;i<2;i++)check(dispatch_semaphore_wait(ready,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC))==0,"both claim contenders ready");
        dispatch_semaphore_signal(start);dispatch_semaphore_signal(start);
        for(unsigned i=0;i<2;i++){void *status=NULL;check(pthread_join(threads[i],&status)==0 && status==NULL,"claim contender reaped");}
        check((workers[0].claim!=NULL)+(workers[1].claim!=NULL)==1,"one owner wins concurrent claim/cancel");
        claim=workers[0].claim?workers[0].claim:workers[1].claim;
        check(claim==request && request->refs==2,"concurrent transfer preserves caller and winner ownership");
        release_startup_source(envelope);release_startup_request(request);release_startup_request(claim);
        dispatch_release(start);dispatch_release(ready);claim_races++;released();
    }
    [fake_app release];fake_app=nil;
    printf("{\"checks\":%u,\"failures\":%u,\"active_empty_checks\":%u,\"clean_cases\":%u,\"claim_races\":%u,\"post_timeout_locks\":%u,\"live_requests\":%u,\"live_envelopes\":%u,\"live_locks\":%u,\"appkit_executed\":false}\n",checks,failures,active_empty_checks,source_empty_after_return,claim_races,post_timeout_locks,live_requests,live_envelopes,live_locks);
    return failures?1:0;
}
}
