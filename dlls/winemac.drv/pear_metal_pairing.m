/* Original Pear finite native bridge fixture. SPDX-License-Identifier: MIT.
 * Actual Wine client surfaces/native DXMT Unix entry table; no hybrid dispatch. */
#import "config.h"
#import "macdrv.h"
#import "cocoa_event.h"
#import "cocoa_window.h"
#import "pear_macdrv_metal_v2.h"
extern int pear_macdrv_surface_test_failure(unsigned);
static NTSTATUS (*legacy_create)(void *);
#import "pear_metal_protocol.h"
#import <Metal/Metal.h>
#import <QuartzCore/CAMetalLayer.h>
#include "wine/pear_bootstrap.h"
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#import <objc/runtime.h>
/* Wine server handles are u32; pinned DXMT Objective-C handles are u64.
 * Rename only the typedef in this inclusion, retaining the upstream bytes. */
#define obj_handle_t pear_dxmt_obj_handle_t
#define WINEMETAL_API
#include "pear_dxmt/winemetal_thunks.h"
#undef obj_handle_t
/* ObjC macdrv.h omits these C driver declarations because BOOL differs. */
extern struct client_surface *macdrv_CreateClientSurface(HWND hwnd,int pixel_format,WINBOOL raw);
extern WINBOOL macdrv_ProcessEvents(DWORD mask);
static pthread_t owner;
static uint64_t owner_teb,owner_tid,cases,failures,callback_main,callback_mode,delegate_state;
static int initialized,finalized;
static unsigned phase;
static bool (*mode_getter)(void);
static const struct pear_macdrv_metal_v1 *api;
static struct client_surface *surface;
static id<MTLDevice> device;
static uint64_t lease_a,lease_b;
static void *dxmt_module;
static NTSTATUS (**native_calls)(void *);
static uint64_t life_created[3],life_deallocated[3];
static char view_witness_key,layer_witness_key,proxy_witness_key;
@interface PearPairingLifetimeWitness : NSObject { unsigned kind; }
- (id)initWithKind:(unsigned)value;
@end
@implementation PearPairingLifetimeWitness
- (id)initWithKind:(unsigned)value
{
    self=[super init];if(self) { kind=value;__atomic_add_fetch(life_created+kind,1,__ATOMIC_RELAXED); }
    return self;
}
- (void)dealloc { __atomic_add_fetch(life_deallocated+kind,1,__ATOMIC_RELAXED);[super dealloc]; }
@end
static int witness(id object,const void *key,unsigned kind)
{
    if(!object || kind>=3) return 0;
    if(!objc_getAssociatedObject(object,key)) {
        PearPairingLifetimeWitness *value=[[PearPairingLifetimeWitness alloc] initWithKind:kind];
        if(!value) return 0;
        objc_setAssociatedObject(object,key,value,OBJC_ASSOCIATION_RETAIN_NONATOMIC);
        [value release]; /* only the actual object's association owns this witness */
    }
    return objc_getAssociatedObject(object,key)!=nil;
}
static int lifetimes_complete(void)
{
    unsigned i;
    for(i=0;i<3;i++) if(__atomic_load_n(life_created+i,__ATOMIC_ACQUIRE)!=__atomic_load_n(life_deallocated+i,__ATOMIC_ACQUIRE)) return 0;
    return __atomic_load_n(life_created,__ATOMIC_ACQUIRE)==3 &&
        __atomic_load_n(life_created+1,__ATOMIC_ACQUIRE)==3 &&
        __atomic_load_n(life_created+2,__ATOMIC_ACQUIRE)==1;
}
static void observe_layer(void *context,uint64_t value)
{
    CAMetalLayer *layer=(CAMetalLayer*)(uintptr_t)value;
    callback_main=pthread_main_np();callback_mode=mode_getter?mode_getter():UINT64_MAX;
    unsigned observed=0;
    if(![layer isKindOfClass:[CAMetalLayer class]]) delegate_state=4;
    else {
        id view=layer.delegate;
        if(!view) delegate_state=2;
        else if(![view isKindOfClass:NSClassFromString(@"WineMetalView")]) delegate_state=3;
        else if(!witness(view,&view_witness_key,0) || !witness(layer,&layer_witness_key,1)) delegate_state=5;
        else { delegate_state=1;observed=layer.device!=nil; }
    }
    if(context) *(unsigned*)context=observed;
}
static void throw_layer(void *context,uint64_t value)
{
    (void)context;(void)value;
    [NSException raise:@"PearOwnedLayerControl" format:@"finite exception refusal"];
}
static void reentry_layer(void *context,uint64_t value)
{
    struct pear_metal_query_v1 q;
    (void)value;
    *(int32_t*)context=api->query(lease_a,&q);
}
static void row(const char *name,int32_t status,int32_t expected,unsigned facts)
{
    uint64_t leases=0,attachments=0;
    char line[768];int size;
    pear_macdrv_metal_counts(&leases,&attachments);cases++;
    if(status!=expected || !facts) failures++;
    size=snprintf(line,sizeof(line),"{\"record_kind\":\"pear_metal_pairing\",\"version\":1,\"case_id\":%llu,\"case\":\"%s\",\"status\":%d,\"expected_status\":%d,\"facts\":%u,\"lease_count\":%llu,\"attachment_count\":%llu,\"main_thread\":%llu,\"x18_mode\":%llu,\"delegate_state\":%llu,\"created_views\":%llu,\"deallocated_views\":%llu,\"created_layers\":%llu,\"deallocated_layers\":%llu,\"created_proxies\":%llu,\"deallocated_proxies\":%llu}\n",(unsigned long long)cases,name,status,expected,facts,(unsigned long long)leases,(unsigned long long)attachments,(unsigned long long)callback_main,(unsigned long long)callback_mode,(unsigned long long)delegate_state,(unsigned long long)__atomic_load_n(life_created,__ATOMIC_ACQUIRE),(unsigned long long)__atomic_load_n(life_deallocated,__ATOMIC_ACQUIRE),(unsigned long long)__atomic_load_n(life_created+1,__ATOMIC_ACQUIRE),(unsigned long long)__atomic_load_n(life_deallocated+1,__ATOMIC_ACQUIRE),(unsigned long long)__atomic_load_n(life_created+2,__ATOMIC_ACQUIRE),(unsigned long long)__atomic_load_n(life_deallocated+2,__ATOMIC_ACQUIRE));
    if(size<=0 || size>=(int)sizeof(line) || write(STDERR_FILENO,line,size)!=size) failures++;
}
static void response(struct pear_pairing_request *r)
{
    r->native_tid=GetCurrentThreadId();r->x18_entry=mode_getter?mode_getter():UINT64_MAX;
    pear_macdrv_metal_counts(&r->lease_count,&r->attachment_count);
    r->case_count=cases;r->flags=failures?0:1;r->status=failures?PEAR_METAL_NATIVE_EXCEPTION:PEAR_METAL_OK;
    r->x18_exit=mode_getter?mode_getter():UINT64_MAX;
}
static int open_dxmt(void)
{
    const char *path=getenv("PEAR_DXMT_PAIRING_UNIXLIB");Dl_info array_info,entry_info;
    if(!path || path[0]!='/') return 0;
    dxmt_module=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if(!dxmt_module) return 0;
    native_calls=dlsym(dxmt_module,"__wine_unix_call_funcs");
    if(!native_calls || !dladdr(native_calls,&array_info) || !dladdr(native_calls[72],&entry_info) || array_info.dli_fbase!=entry_info.dli_fbase) return 0;
    pear_bootstrap_snapshot("loader","metal_pairing_images");pear_bootstrap_images("loader");
    return 1;
}
static void dxmt_cases(HWND hwnd)
{
    struct unixcall_create_metal_view_from_hwnd create={(uintptr_t)hwnd,(uintptr_t)device,0,0};
    struct unixcall_generic_obj_noret close={0};
    struct WMTLayerProps props={0};
    struct unixcall_generic_obj_ptr_noret get={0};
    struct unixcall_generic_obj_constptr_noret set={0};
    struct unixcall_generic_obj_obj_ret drawable={0};
    struct unixcall_generic_obj_uint64_uint64_ret color={0};
    struct WMTEDRValue edr={0};
    struct WMTHDRMetadata metadata={0};
    struct unixcall_query_display_setting_for_layer display={0};
    NTSTATUS status;
    if(!open_dxmt()) { row("dxmt_loaded",PEAR_METAL_VIEW,0,0); return; }
    /* Keep the v1 consumer regression explicit. The actual swapchain table
     * entry now uses v2; it must refuse our manually owned v1 test surface. */
    legacy_create=dlsym(dxmt_module,"pear_dxmt_v1_fixture_create");
    status=legacy_create ? legacy_create(&create) : STATUS_NOT_SUPPORTED;
    row("dxmt_acquire",status,0,create.ret_view && create.ret_layer && create.ret_view==create.ret_layer);
    if(status || !create.ret_view) return;
    if(!witness((id)(uintptr_t)create.ret_view,&proxy_witness_key,2)) failures++;
    get.handle=create.ret_layer;get.arg.ptr=&props;
    status=native_calls[71](&get);row("dxmt_get_props",status,0,props.device==(uintptr_t)device);
    props.drawable_width=256;props.drawable_height=128;props.contents_scale=1;
    props.pixel_format=WMTPixelFormatBGRA8Unorm;props.opaque=true;props.framebuffer_only=true;props.display_sync_enabled=true;
    set.handle=create.ret_layer;set.arg.ptr=&props;
    status=native_calls[70](&set);row("dxmt_set_props",status,0,1);
    drawable.handle=create.ret_layer;status=native_calls[67](&drawable);
    row("dxmt_next_drawable",status,0,drawable.ret!=0);
    color.handle=create.ret_layer;color.arg=WMTColorSpaceSRGB;
    status=native_calls[93](&color);row("dxmt_colorspace",status,0,color.ret!=0);
    get.arg.ptr=&edr;status=native_calls[97](&get);row("dxmt_edr",status,0,edr.maximum_edr_color_component_value>=1);
    display.layer=create.ret_layer;display.hdr_metadata.ptr=&metadata;
    status=native_calls[101](&display);row("dxmt_display",status,0,1);
    close.handle=create.ret_view;status=native_calls[73](&close);row("dxmt_release",status,0,1);
}
static void v2row(const char *name,int32_t status,int32_t expected,unsigned facts)
{
    if(status!=expected || !facts) failures++;
    fprintf(stderr,"PEAR_SURFACE_CONTROL name=%s status=%d expected=%d facts=%u\n",name,status,expected,facts);
}
static void surface_v2_cases(uint64_t hwnd)
{
    pear_metal_v2_get_interface get=dlsym(RTLD_DEFAULT,"pear_macdrv_metal_v2_get_interface");
    const struct pear_macdrv_metal_v2 *v=NULL;
    uint64_t a=0,b=0,l=0,n=0;
    struct pear_metal_query_v1 q;
    struct client_surface *foreign;
    int32_t s;
    v2row("getter_present",get?0:PEAR_METAL_VIEW,0,get!=NULL);if(!get)return;
    s=get(1,56,15,&v);v2row("version",s,PEAR_METAL_VERSION_ERROR,!v);
    s=get(2,48,15,&v);v2row("size",s,PEAR_METAL_SIZE,!v);
    s=get(2,56,16,&v);v2row("features",s,PEAR_METAL_FEATURE_ERROR,!v);
    s=get(2,56,15,NULL);v2row("null_output",s,PEAR_METAL_ARGUMENT,1);
    s=get(2,56,15,&v);v2row("valid_table",s,0,v && v->version==2 && v->bytes==56 && v->features==15);if(s || !v)return;
    s=v->acquire_window(0,(uintptr_t)device,&a);v2row("invalid_window",s,PEAR_METAL_WINDOW,!a);
    s=v->acquire_window(hwnd,0,&a);v2row("null_device",s,PEAR_METAL_DEVICE,!a);
    __block int32_t main_status=0;__block uint64_t main_token=0;
    OnMainThread(^{main_status=v->acquire_window(hwnd,(uintptr_t)device,&main_token);});
    v2row("wrong_context",main_status,PEAR_METAL_OWNER_CONFLICT,!main_token);
    for(unsigned phase=1;phase<=2;phase++) {
        unsigned armed=pear_macdrv_surface_test_failure(phase);
        s=v->acquire_window(hwnd,(uintptr_t)device,&a);
        pear_macdrv_metal_counts(&l,&n);
        v2row(phase==1?"allocation_rollback":"registration_rollback",s,PEAR_METAL_VIEW,armed && !a && !l && !n);
        s=api->acquire(hwnd,(uintptr_t)device,&a);
        v2row(phase==1?"allocation_no_client":"registration_no_client",s,PEAR_METAL_NO_CLIENT,!a);
    }
    s=v->acquire_window(hwnd,(uintptr_t)device,&a);v2row("create_missing",s,0,a!=0);
    if(s)return;
    s=v->acquire_window(hwnd,(uintptr_t)device,&b);pear_macdrv_metal_counts(&l,&n);
    v2row("share_owned",s,0,b && b!=a && l==2 && n==1);
    s=v->release(a);v2row("release_first",s,0,1);
    s=v->query(b,&q);v2row("remaining_live",s,0,q.bytes==32 && q.state==1);
    s=v->release(b);pear_macdrv_metal_counts(&l,&n);v2row("release_last",s,0,!l && !n);
    s=v->acquire_window(hwnd,(uintptr_t)device,&b);v2row("recreate_missing",s,0,b!=0);
    /* Invoke the same win32u surface-detach operation used by window destruction,
     * while a v2 lease remains live, then release that invalidated owned surface. */
    detach_client_surfaces((HWND)(UINT_PTR)hwnd);
    s=v->query(b,&q);v2row("detached_stale",s,PEAR_METAL_STALE,!q.bytes);
    s=v->release(b);pear_macdrv_metal_counts(&l,&n);v2row("detached_release",s,0,!l && !n);
    s=api->acquire(hwnd,(uintptr_t)device,&a);v2row("final_no_client",s,PEAR_METAL_NO_CLIENT,!a);
    foreign=macdrv_CreateClientSurface((HWND)(UINT_PTR)hwnd,0,FALSE);
    s=v->acquire_window(hwnd,(uintptr_t)device,&a);
    v2row("foreign_surface",s,PEAR_METAL_OWNER_CONFLICT,foreign && !a);
    if(foreign)client_surface_release(foreign);
}

NTSTATUS pear_metal_pairing_control(void *opaque)
{
    struct pear_pairing_request *r=opaque;
    struct pear_metal_query_v1 q={0};
    int32_t status;
    if(!r || r->magic!=PEAR_PAIRING_MAGIC || r->version!=1 || r->bytes!=sizeof(*r) || r->cycle!=1 || r->operation!=phase+1 || r->status || r->expected_status || r->native_tid || r->lease_count || r->attachment_count || r->case_count || r->width || r->height || r->flags || r->x18_entry!=UINT64_MAX || r->x18_exit!=UINT64_MAX) return STATUS_INVALID_PARAMETER;
    if(r->operation==PEAR_PAIRING_INIT) {
        const char *flag=getenv("PEAR_DXMT_PAIRING_FIXTURE"),*nonce=getenv("PEAR_BOOTSTRAP_NONCE");
        pear_metal_get_interface getter=dlsym(RTLD_DEFAULT,"pear_macdrv_metal_v1_get_interface");
        if(initialized || !flag || strcmp(flag,"1") || !nonce || strlen(nonce)!=32 || strspn(nonce,"0123456789abcdef")!=32 || !getter) return STATUS_NOT_SUPPORTED;
        mode_getter=dlsym(RTLD_DEFAULT,"os_custom_x18_abi_enabled");
        if(!mode_getter || mode_getter() || pthread_main_np() || r->guest_teb!=(uintptr_t)NtCurrentTeb() || r->guest_tid!=GetCurrentThreadId()) return STATUS_NOT_SUPPORTED;
        owner=pthread_self();owner_teb=r->guest_teb;owner_tid=r->guest_tid;initialized=1;phase=1;
        status=getter(2,48,7,&api);row("getter_version",status,PEAR_METAL_VERSION_ERROR,!api);
        status=getter(1,40,7,&api);row("getter_size",status,PEAR_METAL_SIZE,!api);
        status=getter(1,48,8,&api);row("getter_features",status,PEAR_METAL_FEATURE_ERROR,!api);
        status=getter(1,48,7,NULL);row("getter_null",status,PEAR_METAL_ARGUMENT,1);
        status=getter(1,48,7,&api);row("getter_valid",status,0,api!=NULL);
        response(r);return failures?STATUS_UNSUCCESSFUL:STATUS_SUCCESS;
    }
    if(!initialized || finalized || !pthread_equal(owner,pthread_self()) || r->guest_teb!=owner_teb || r->guest_tid!=owner_tid || (uintptr_t)NtCurrentTeb()!=owner_teb || GetCurrentThreadId()!=owner_tid || mode_getter()) return STATUS_INVALID_PARAMETER;
    @autoreleasepool {
    if(r->operation==PEAR_PAIRING_RUN) {
        WineMetalView *foreign;unsigned observed=0;
        if(surface || device || !r->hwnd) return STATUS_INVALID_PARAMETER;
        device=macdrv_create_metal_device();if(!device) return STATUS_NOT_SUPPORTED;
        surface_v2_cases(r->hwnd);
        status=api->acquire(r->hwnd,0,&lease_a);row("null_device",status,PEAR_METAL_DEVICE,!lease_a);
        status=api->acquire(0,(uintptr_t)device,&lease_a);row("invalid_window",status,PEAR_METAL_WINDOW,!lease_a);
        status=api->acquire(r->hwnd,(uintptr_t)device,&lease_a);row("no_client",status,PEAR_METAL_NO_CLIENT,!lease_a);
        status=api->query(UINT64_MAX,&q);row("unknown_lease",status,PEAR_METAL_STALE,!q.bytes);
        surface=macdrv_CreateClientSurface((HWND)(UINT_PTR)r->hwnd,0,FALSE);if(!surface) return STATUS_NO_MEMORY;
        foreign=macdrv_view_create_metal_view(impl_from_client_surface(surface)->cocoa_view,device);
        status=api->acquire(r->hwnd,(uintptr_t)device,&lease_a);row("foreign_owner",status,PEAR_METAL_OWNER_CONFLICT,foreign && !lease_a);
        if(foreign) macdrv_view_release_metal_view(foreign);
        status=api->acquire(r->hwnd,(uintptr_t)device,&lease_a);row("acquire_a",status,0,lease_a!=0);
        status=api->acquire(r->hwnd,(uintptr_t)device,&lease_b);row("acquire_b",status,0,lease_b && lease_a!=lease_b);
        status=api->query(lease_a,&q);row("query_live",status,0,q.bytes==32 && q.state==1);
        status=api->with_layer(lease_a,observe_layer,&observed);row("layer_callback",status,0,observed && callback_main && !callback_mode);
        status=api->with_layer(lease_a,throw_layer,NULL);row("layer_exception",status,PEAR_METAL_NATIVE_EXCEPTION,1);
        int32_t nested=0;status=api->with_layer(lease_a,reentry_layer,&nested);row("layer_reentry",status,0,nested==PEAR_METAL_OWNER_CONFLICT);
        status=api->release(lease_b);row("release_b",status,0,1);
        status=api->release(lease_b);row("double_release_b",status,PEAR_METAL_STALE,1);lease_b=0;
        dxmt_cases((HWND)(UINT_PTR)r->hwnd);
    } else if(r->operation==PEAR_PAIRING_RESIZE) {
        if(!surface || !lease_a) return STATUS_INVALID_PARAMETER;
        client_surface_present(surface);OnMainThread(^{});
        status=api->query(lease_a,&q);r->width=(uint64_t)q.drawable_width;r->height=(uint64_t)q.drawable_height;
        row("resize_live",status,0,q.state==1 && q.drawable_width>0 && q.drawable_height>0);
    } else if(r->operation==PEAR_PAIRING_DETACH) {
        struct client_surface *replacement;
        if(!surface || !lease_a) return STATUS_INVALID_PARAMETER;
        replacement=macdrv_CreateClientSurface((HWND)(UINT_PTR)r->hwnd,0,FALSE);
        if(!replacement) return STATUS_NO_MEMORY;
        status=api->query(lease_a,&q);row("replacement_stale",status,PEAR_METAL_STALE,!q.bytes);
        status=api->release(lease_a);row("release_invalid",status,0,1);lease_a=0;
        client_surface_release(surface);surface=replacement;
        status=api->acquire(r->hwnd,(uintptr_t)device,&lease_a);
        unsigned observed=0;if(!status) status=api->with_layer(lease_a,observe_layer,&observed);
        row("replacement_acquire",status,0,lease_a!=0 && observed);
        client_surface_release(surface);surface=NULL;
        status=api->query(lease_a,&q);row("detach_stale",status,PEAR_METAL_STALE,!q.bytes);
        status=api->release(lease_a);row("detach_release",status,0,1);lease_a=0;
        surface=macdrv_CreateClientSurface((HWND)(UINT_PTR)r->hwnd,0,FALSE);
        if(!surface) return STATUS_NO_MEMORY;
        status=api->acquire(r->hwnd,(uintptr_t)device,&lease_a);
        unsigned observed_again=0;if(!status) status=api->with_layer(lease_a,observe_layer,&observed_again);
        row("destroy_acquire",status,0,lease_a!=0 && observed_again);
    } else if(r->operation==PEAR_PAIRING_DESTROYED) {
        if(!surface || !lease_a) return STATUS_INVALID_PARAMETER;
        status=api->query(lease_a,&q);row("destroy_stale",status,PEAR_METAL_STALE,!q.bytes);
        status=api->acquire(r->hwnd,(uintptr_t)device,&lease_b);row("destroy_missing",status,PEAR_METAL_WINDOW,!lease_b);
        status=api->release(lease_a);row("destroy_release",status,0,1);lease_a=0;
        client_surface_release(surface);surface=NULL;macdrv_release_metal_device(device);device=nil;
    } else if(r->operation==PEAR_PAIRING_FINAL) {
        uint64_t leases=0,attachments=0;
        if(surface || device || lease_a || lease_b) return STATUS_INVALID_PARAMETER;
        OnMainThread(^{});pear_macdrv_metal_counts(&leases,&attachments);
        row("cleanup",0,0,!leases && !attachments);
        int closed=dxmt_module?dlclose(dxmt_module):-1;
        row("dxmt_dlclose",closed,0,dxmt_module!=NULL);dxmt_module=NULL;native_calls=NULL;
        finalized=1;
    } else return STATUS_INVALID_PARAMETER;
    }
    if(r->operation==PEAR_PAIRING_FINAL) {
        struct timespec started,now;unsigned drains=0;
        int clock_ok=!clock_gettime(CLOCK_MONOTONIC,&started);
        do {
            OnMainThread(^{ @autoreleasepool { [CATransaction flush]; } });
            macdrv_ProcessEvents(QS_ALLINPUT);drains++;
            if(lifetimes_complete()) break;
            if(!clock_ok || clock_gettime(CLOCK_MONOTONIC,&now)) { clock_ok=0;break; }
            uint64_t elapsed=(uint64_t)(now.tv_sec-started.tv_sec)*UINT64_C(1000000000)+(now.tv_nsec-started.tv_nsec);
            if(elapsed>=UINT64_C(2000000000)) break;
            usleep(10000);
        } while(drains<32);
        row("lifetime",0,0,clock_ok && lifetimes_complete());
    }
    if(!failures) phase=r->operation;
    response(r);return failures?STATUS_UNSUCCESSFUL:STATUS_SUCCESS;
}
