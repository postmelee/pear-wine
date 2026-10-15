/*
 * MACDRV Cocoa initialization code
 *
 * Copyright 2011, 2012, 2013 Ken Thomases for CodeWeavers Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#import "config.h"
#import "macdrv.h"

#import <AppKit/AppKit.h>
#include <mach/mach.h>
#include <mach/mach_time.h>

#import "cocoa_app.h"

#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"


/* Condition values for an NSConditionLock. Used to signal between run_cocoa_app
   and macdrv_start_cocoa_app so the latter knows when the former is running
   the application event loop. */
enum {
    COCOA_APP_NOT_RUNNING,
    COCOA_APP_RUNNING,
};


/* The caller and an entered callback own independent references.  The
   condition protects success; it is never held during AppKit
   initialization or while running the application event loop. */
struct cocoa_app_startup_request {
    unsigned int       refs;
    NSConditionLock*    lock;
    unsigned long long  tickcount;
    uint64_t            uptime_ns;
    BOOL                success;
};

/* CF may retain a selected source until its perform callback returns, even
   after invalidation.  Transfer the request out before entering NSApp.run so
   that only this empty envelope can remain owned by the active CF frame. */
struct cocoa_app_startup_source {
    unsigned int refs;
    struct cocoa_app_startup_request* request;
};

static struct cocoa_app_startup_request* retain_startup_request(struct cocoa_app_startup_request* request)
{
    __atomic_add_fetch(&request->refs, 1, __ATOMIC_RELAXED);
    return request;
}

static void release_startup_request(struct cocoa_app_startup_request* request)
{
    if (request && !__atomic_sub_fetch(&request->refs, 1, __ATOMIC_ACQ_REL))
    {
        [request->lock release];
        free(request);
    }
}

static struct cocoa_app_startup_request* claim_startup_request(struct cocoa_app_startup_source* source)
{
    return __atomic_exchange_n(&source->request, NULL, __ATOMIC_ACQ_REL);
}

static const void* retain_startup_source(const void* info)
{
    struct cocoa_app_startup_source* source = (void*)info;
    __atomic_add_fetch(&source->refs, 1, __ATOMIC_RELAXED);
    return source;
}

static void release_startup_source(const void* info)
{
    struct cocoa_app_startup_source* source = (void*)info;
    if (!__atomic_sub_fetch(&source->refs, 1, __ATOMIC_ACQ_REL))
    {
        release_startup_request(claim_startup_request(source));
        free(source);
    }
}


/***********************************************************************
 *              run_cocoa_app
 *
 * Transforms the main thread from merely idling in its run loop to
 * being a Cocoa application running its event loop.
 *
 * This will be the perform callback of a custom run loop source that
 * will be scheduled in the main thread's run loop from a secondary
 * thread by macdrv_start_cocoa_app.  This function communicates that
 * it has successfully started the application by changing the condition
 * of a shared NSConditionLock, passed in via the info parameter.
 *
 * This function never returns.  It's the new permanent home of the
 * main thread.
 */
static void run_cocoa_app(void* info)
{
    struct cocoa_app_startup_request* request = claim_startup_request(info);
    BOOL created_app = FALSE, success = FALSE;

    /* A timed-out caller may have detached the unclaimed request. */
    if (!request) return;

    @autoreleasepool
    {
        if (!NSApp)
        {
            [WineApplication sharedApplication];
            created_app = TRUE;
        }

        if ([NSApp respondsToSelector:@selector(setWineController:)])
        {
            WineApplicationController* controller = [WineApplicationController sharedController];
            [NSApp setWineController:controller];
            [controller computeEventTimeAdjustmentFromTicks:request->tickcount uptime:request->uptime_ns];
            success = TRUE;
        }

        [request->lock lock];
        request->success = success;
        [request->lock unlockWithCondition:COCOA_APP_RUNNING];
        release_startup_request(request);
    }

    /* Preserve the existing local run decision even if the caller timed out
       while AppKit initialization was in flight.  No caller storage is used. */
    if (created_app && success)
    {
        @autoreleasepool
        {
            /* Never returns */
            [NSApp run];
        }
    }
}


/***********************************************************************
 *              macdrv_start_cocoa_app
 *
 * Tells the main thread to transform itself into a Cocoa application.
 *
 * Returns 0 on success, non-zero on failure.
 */
int macdrv_start_cocoa_app(unsigned long long tickcount)
{
@autoreleasepool
{
    int ret = -1;
    CFRunLoopSourceRef source = NULL;
    struct cocoa_app_startup_request* request = NULL;
    struct cocoa_app_startup_source* envelope = NULL;
    uint64_t uptime_mach = mach_absolute_time();
    mach_timebase_info_data_t mach_timebase;
    NSDate* timeLimit;
    CFRunLoopSourceContext source_context = { 0 };

    /* Make sure Cocoa is in multi-threading mode by detaching a
       do-nothing thread. */
    [NSThread detachNewThreadSelector:@selector(self)
                             toTarget:[NSThread class]
                           withObject:nil];

    if (!(request = calloc(1, sizeof(*request)))) goto done;
    request->refs = 1;
    if (!(request->lock = [[NSConditionLock alloc] initWithCondition:COCOA_APP_NOT_RUNNING])) goto done;
    request->tickcount = tickcount;

    mach_timebase_info(&mach_timebase);
    request->uptime_ns = uptime_mach * mach_timebase.numer / mach_timebase.denom;
    if (!(timeLimit = [NSDate dateWithTimeIntervalSinceNow:5])) goto done;

    if (!(envelope = calloc(1, sizeof(*envelope)))) goto done;
    envelope->refs = 1;
    envelope->request = retain_startup_request(request);
    source_context.info = envelope;
    source_context.retain = retain_startup_source;
    source_context.release = release_startup_source;
    source_context.perform = run_cocoa_app;
    if (!(source = CFRunLoopSourceCreate(NULL, 0, &source_context))) goto done;

    CFRunLoopAddSource(CFRunLoopGetMain(), source, kCFRunLoopCommonModes);
    CFRunLoopSourceSignal(source);
    CFRunLoopWakeUp(CFRunLoopGetMain());

    if ([request->lock lockWhenCondition:COCOA_APP_RUNNING beforeDate:timeLimit])
    {
        ret = !request->success;
        [request->lock unlock];
    }
    /* A failed timed wait leaves ret at -1.  An entered callback may still
       publish to its independently owned request, but cannot upgrade this
       caller.  Do not acquire the condition again or join the callback. */

done:
    if (source) CFRunLoopSourceInvalidate(source);
    if (envelope) release_startup_request(claim_startup_request(envelope));
    if (source) CFRelease(source);
    if (envelope) release_startup_source(envelope);
    release_startup_request(request);
    return ret;
}
}
