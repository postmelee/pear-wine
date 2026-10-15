/* Original Pear graphics integration. SPDX-License-Identifier: LGPL-2.1-or-later.
 * Private source-matched ABI; no private Wine layout is exported. */
#import "config.h"
#import "macdrv.h"
#import "cocoa_event.h"
#import "cocoa_app.h"
#import "cocoa_window.h"
#import "pear_macdrv_metal_v2.h"
extern int32_t pear_macdrv_surface_take(uint64_t,uint64_t *);
extern void pear_macdrv_surface_drop(uint64_t);
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
static void pear_present_counts(const char *action,int32_t status)
{
    const char *flag=getenv("PEAR_PRESENT_OBSERVE");
    uint64_t leases=0,attachments=0;
    if(!flag || strcmp(flag,"1")) return;
    pear_macdrv_metal_counts(&leases,&attachments);
    fprintf(stderr,"PEAR_PRESENT_REGISTRY action=%s status=%d leases=%llu attachments=%llu\n",action,status,(unsigned long long)leases,(unsigned long long)attachments);
}
struct pear_binding {
    uint64_t hwnd, generation;
    WineContentView *client;
    WineMetalView *view;
    CAMetalLayer *layer;
    id<MTLDevice> device;
    unsigned count;
};
struct pear_lease { uint64_t token, managed_owner; struct pear_binding *binding; unsigned invalid; };
static struct pear_binding bindings[PEAR_METAL_CAPACITY];
static struct pear_lease leases[PEAR_METAL_CAPACITY];
static uint64_t next_token;
static unsigned operation_depth;
/* All registry and object accesses below run on the Cocoa main thread. */
static void run_main(dispatch_block_t block)
{
    if(pthread_main_np()) block();
    else OnMainThread(block);
}
static struct pear_lease *find_lease(uint64_t token)
{
    unsigned i;
    for(i=0;i<PEAR_METAL_CAPACITY;i++) if(token && leases[i].token==token) return leases+i;
    return NULL;
}
static void invalidate_binding(struct pear_binding *binding)
{
    unsigned i;
    for(i=0;i<PEAR_METAL_CAPACITY;i++) if(leases[i].token && leases[i].binding==binding) leases[i].invalid=1;
}
void pear_macdrv_metal_changed(uint64_t hwnd,uint64_t generation)
{
    /* May be called with win_data_mutex held. Only enqueue: never wait, retain,
     * release or call back into window.c from this lifecycle notification. */
    OnMainThreadAsync(^{
        unsigned i;
        for(i=0;i<PEAR_METAL_CAPACITY;i++) if(bindings[i].count && bindings[i].hwnd==hwnd && bindings[i].generation<generation) invalidate_binding(bindings+i);
    });
}
static int32_t valid_lease(struct pear_lease *lease)
{
    WineContentView *client=NULL;
    uint64_t generation=0;
    int32_t status;
    if(!lease || lease->invalid) return PEAR_METAL_STALE;
    status=pear_macdrv_metal_snapshot(lease->binding->hwnd,&generation,&client);
    if(client) [(id)client release];
    if(status || generation!=lease->binding->generation || client!=lease->binding->client) {
        invalidate_binding(lease->binding);
        return PEAR_METAL_STALE;
    }
    return PEAR_METAL_OK;
}
static int32_t acquire(uint64_t hwnd,uint64_t device_value,uint64_t *out)
{
    __block int32_t status=PEAR_METAL_OK;
    if(!out) return PEAR_METAL_ARGUMENT;
    *out=0;
    if(!device_value) return PEAR_METAL_DEVICE;
    run_main(^{ @autoreleasepool {
        WineContentView *client=NULL,*check=NULL;
        WineMetalView *view=NULL;
        CAMetalLayer *layer=NULL;
        id<MTLDevice> device_hold=nil;
        struct pear_binding *binding=NULL;
        struct pear_lease *lease=NULL;
        uint64_t generation=0,check_generation=0;
        id<MTLDevice> device=(id<MTLDevice>)(uintptr_t)device_value;
        unsigned i,fresh=0,view_lease_held=0,layer_lease_held=0;
        if(operation_depth) { status=PEAR_METAL_OWNER_CONFLICT; return; }
        @try {
            if(![device conformsToProtocol:@protocol(MTLDevice)]) { status=PEAR_METAL_DEVICE; goto done; }
            status=pear_macdrv_metal_snapshot(hwnd,&generation,&client);
            if(status) goto done;
            if(!generation) { status=PEAR_METAL_STALE; goto done; }
            for(i=0;i<PEAR_METAL_CAPACITY;i++) if(!leases[i].token) { lease=leases+i; break; }
            if(!lease || next_token==UINT64_MAX) { status=PEAR_METAL_CAPACITY_ERROR; goto done; }
            for(i=0;i<PEAR_METAL_CAPACITY;i++) {
                struct pear_binding *candidate=bindings+i;
                if(candidate->count && candidate->client==client && candidate->generation==generation) {
                    if(candidate->device!=device) { status=PEAR_METAL_DEVICE; goto done; }
                    binding=candidate;break;
                }
            }
            if(binding) { view=binding->view;layer=binding->layer; }
            else {
                for(i=0;i<PEAR_METAL_CAPACITY;i++) if(!bindings[i].count) { binding=bindings+i;break; }
                if(!binding) { status=PEAR_METAL_CAPACITY_ERROR;goto done; }
                status=macdrv_pear_metal_open(client,device,&view,&layer);
                if(status) goto done;
                fresh=1;
                status=pear_macdrv_metal_snapshot(hwnd,&check_generation,&check);
                if(status || check!=client || check_generation!=generation) { status=PEAR_METAL_STALE;goto done; }
                { id held=(id)check;check=NULL;[held release]; }
                device_hold=[device retain];
            }
            [(id)view retain];view_lease_held=1;
            [layer retain];layer_lease_held=1;
            if(!fresh) { id held=(id)client;client=NULL;[held release]; }
            if(fresh) {
                binding->hwnd=hwnd;binding->generation=generation;
                binding->client=client;client=NULL;
                binding->view=view;binding->layer=layer;binding->device=device_hold;device_hold=nil;
                fresh=0;
            }
            binding->count++;
            lease->binding=binding;lease->invalid=0;lease->token=++next_token;
            view_lease_held=layer_lease_held=0;*out=lease->token;
        } @catch(NSException *exception) { (void)exception;status=PEAR_METAL_NATIVE_EXCEPTION; }
    done:
        @try {
            if(check) [(id)check release];
            if(layer_lease_held) [layer release];
            if(view_lease_held) [(id)view release];
            if(fresh) { macdrv_pear_metal_close(client,view);[layer release]; }
            if(device_hold) [device_hold release];
            if(client) [(id)client release];
        } @catch(NSException *exception) { (void)exception;status=PEAR_METAL_NATIVE_EXCEPTION; }
    }});
    pear_present_counts("acquire",status);
    return status;
}
static int32_t query(uint64_t token,struct pear_metal_query_v1 *out)
{
    __block int32_t status=PEAR_METAL_OK;
    if(!out) return PEAR_METAL_ARGUMENT;
    memset(out,0,sizeof(*out));
    if(!token) return PEAR_METAL_ARGUMENT;
    run_main(^{ @autoreleasepool {
        struct pear_lease *lease=find_lease(token);
        if(operation_depth) { status=PEAR_METAL_OWNER_CONFLICT; return; }
        @try {
            if((status=valid_lease(lease))) return;
            out->bytes=sizeof(*out); out->state=1; out->generation=lease->binding->generation;
            out->drawable_width=lease->binding->layer.drawableSize.width;
            out->drawable_height=lease->binding->layer.drawableSize.height;
        } @catch(NSException *exception) {
            (void)exception; memset(out,0,sizeof(*out)); status=PEAR_METAL_NATIVE_EXCEPTION;
        }
    }});
    return status;
}
static int32_t release_lease(uint64_t token)
{
    __block int32_t status=PEAR_METAL_OK;
    __block uint64_t managed_owner=0;
    if(!token) return PEAR_METAL_ARGUMENT;
    run_main(^{ @autoreleasepool {
        struct pear_lease *lease=find_lease(token);
        struct pear_binding *binding;
        if(operation_depth) { status=PEAR_METAL_OWNER_CONFLICT; return; }
        if(!lease) { status=PEAR_METAL_STALE; return; }
        binding=lease->binding;
        @try {
            managed_owner=lease->managed_owner;
            [binding->layer release]; [(id)binding->view release];
            memset(lease,0,sizeof(*lease));
            if(!--binding->count) {
                macdrv_pear_metal_close(binding->client,binding->view);
                [binding->layer release]; [binding->device release]; [(id)binding->client release];
                memset(binding,0,sizeof(*binding));
            }
        } @catch(NSException *exception) { (void)exception; status=PEAR_METAL_NATIVE_EXCEPTION; }
    }});
    if(managed_owner && !status) pear_macdrv_surface_drop(managed_owner);
    pear_present_counts("release",status);
    return status;
}
static int32_t with_layer(uint64_t token,pear_metal_layer_operation operation,void *context)
{
    __block int32_t status=PEAR_METAL_OK;
    if(!token || !operation) return PEAR_METAL_ARGUMENT;
    run_main(^{ @autoreleasepool {
        struct pear_lease *lease=find_lease(token);
        CAMetalLayer *layer=NULL;
        if(operation_depth) { status=PEAR_METAL_OWNER_CONFLICT; return; }
        @try {
            if((status=valid_lease(lease))) return;
            layer=[lease->binding->layer retain]; operation_depth++;
            operation(context,(uint64_t)(uintptr_t)layer);
        } @catch(NSException *exception) { (void)exception; status=PEAR_METAL_NATIVE_EXCEPTION; }
        @finally { if(layer) { operation_depth--; [layer release]; } }
    }});
    return status;
}
static const struct pear_macdrv_metal_v1 interface={PEAR_METAL_VERSION,sizeof(interface),PEAR_METAL_FEATURES,acquire,query,release_lease,with_layer};
__attribute__((visibility("default"))) int32_t pear_macdrv_metal_v1_get_interface(
    uint32_t version,uint32_t bytes,uint64_t features,const struct pear_macdrv_metal_v1 **out)
{
    if(!out) return PEAR_METAL_ARGUMENT;
    *out=NULL;
    if(version!=PEAR_METAL_VERSION) return PEAR_METAL_VERSION_ERROR;
    if(bytes!=sizeof(interface)) return PEAR_METAL_SIZE;
    if(features & ~PEAR_METAL_FEATURES) return PEAR_METAL_FEATURE_ERROR;
    *out=&interface; return PEAR_METAL_OK;
}
void pear_macdrv_metal_counts(uint64_t *lease_count,uint64_t *attachment_count)
{
    *lease_count=*attachment_count=0;
    run_main(^{
        unsigned i;
        for(i=0;i<PEAR_METAL_CAPACITY;i++) {
            if(leases[i].token) (*lease_count)++;
            if(bindings[i].count) (*attachment_count)++;
        }
    });
}

static int32_t acquire_window(uint64_t hwnd,uint64_t device,uint64_t *out)
{
    uint64_t owner=0,token=0;
    __block int32_t status;
    if(!out) return PEAR_METAL_ARGUMENT;
    *out=0;
    if(!device) return PEAR_METAL_DEVICE;
    if((status=pear_macdrv_surface_take(hwnd,&owner))) return status;
    if((status=acquire(hwnd,device,&token))) { pear_macdrv_surface_drop(owner);return status; }
    run_main(^{
        struct pear_lease *lease=find_lease(token);
        status=valid_lease(lease);
        if(!status) lease->managed_owner=owner;
    });
    if(status) { release_lease(token);pear_macdrv_surface_drop(owner);return status; }
    *out=token;return PEAR_METAL_OK;
}
static const struct pear_macdrv_metal_v2 interface_v2={PEAR_METAL_V2_VERSION,sizeof(interface_v2),PEAR_METAL_V2_FEATURES,acquire,query,release_lease,with_layer,acquire_window};
__attribute__((visibility("default"))) int32_t pear_macdrv_metal_v2_get_interface(
    uint32_t version,uint32_t bytes,uint64_t features,const struct pear_macdrv_metal_v2 **out)
{
    if(!out) return PEAR_METAL_ARGUMENT;
    *out=NULL;
    if(version!=PEAR_METAL_V2_VERSION) return PEAR_METAL_VERSION_ERROR;
    if(bytes!=sizeof(interface_v2)) return PEAR_METAL_SIZE;
    if(features & ~PEAR_METAL_V2_FEATURES) return PEAR_METAL_FEATURE_ERROR;
    *out=&interface_v2;return PEAR_METAL_OK;
}
