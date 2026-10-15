/* Original Pear surface ownership adapter. SPDX-License-Identifier: LGPL-2.1-or-later.
 * Included in window.c. Private pointers never cross the exported native ABI.
 * The small reservation mutex is NEVER held across Wine or Cocoa operations. */
/* Source-matched Wine internal export; never part of the Pear native ABI. */
extern void use_window_client_surface(struct client_surface *, BOOL);
struct pear_surface_owner {
    uint64_t token, hwnd;
    struct client_surface *surface;
    WineContentView *view; /* Identity only; never dereferenced here. */
    unsigned refs, ready;
};
static pthread_mutex_t pear_surface_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct pear_surface_owner pear_surface_owners[PEAR_METAL_CAPACITY];
static uint64_t pear_surface_sequence;
static _Thread_local unsigned pear_surface_failure;
/* Finite fixture-only refusal injection. It exercises real rollback, not an
 * alternative allocator or a success override. No public getter exposes it. */
int pear_macdrv_surface_test_failure(unsigned phase)
{
    const char *flag=getenv("PEAR_DXMT_PAIRING_FIXTURE");
    const char *nonce=getenv("PEAR_BOOTSTRAP_NONCE");
    if(!flag || strcmp(flag,"1") || !nonce || strlen(nonce)!=32 ||
       strspn(nonce,"0123456789abcdef")!=32 || !macdrv_thread_data() || pthread_main_np() ||
       phase>2 || pear_surface_failure) return 0;
    pear_surface_failure=phase;return 1;
}

void pear_macdrv_surface_drop(uint64_t token)
{
    struct pear_surface_owner *owner = NULL;
    struct client_surface *surface = NULL;
    unsigned i;
    pthread_mutex_lock(&pear_surface_mutex);
    for (i=0;i<PEAR_METAL_CAPACITY;i++)
        if (pear_surface_owners[i].token==token && token) { owner=pear_surface_owners+i;break; }
    if (owner && owner->refs && !--owner->refs) { owner->ready=0;surface=owner->surface; }
    pthread_mutex_unlock(&pear_surface_mutex);
    if (!surface) return;
    /* The final upstream reference removes an active surface from its list,
     * detaches it and destroys it. Do not use use_window_client_surface(FALSE):
     * that would deliberately add an unused-cache reference, which we do not own. */
    client_surface_release(surface);
    pthread_mutex_lock(&pear_surface_mutex);
    memset(owner,0,sizeof(*owner));
    pthread_mutex_unlock(&pear_surface_mutex);
}

int32_t pear_macdrv_surface_take(uint64_t hwnd, uint64_t *out)
{
    struct pear_surface_owner *owner=NULL;
    struct macdrv_client_surface *surface=NULL;
    struct macdrv_win_data *data;
    uint64_t generation=0,token=0;
    unsigned i,shared=0;
    int32_t status=PEAR_METAL_OK;
    *out=0;
    /* A native Cocoa callback is not an initialized Wine execution context. */
    if (pthread_main_np() || !macdrv_thread_data()) return PEAR_METAL_OWNER_CONFLICT;
    pthread_mutex_lock(&pear_surface_mutex);
    for(i=0;i<PEAR_METAL_CAPACITY;i++)
        if(pear_surface_owners[i].token && pear_surface_owners[i].hwnd==hwnd) {
            owner=pear_surface_owners+i;shared=1;break;
        }
    if(shared) {
        if(!owner->ready || !owner->refs || owner->refs==UINT_MAX) status=PEAR_METAL_OWNER_CONFLICT;
        else { owner->refs++;token=owner->token; }
    } else {
        for(i=0;i<PEAR_METAL_CAPACITY;i++)
            if(!pear_surface_owners[i].token) { owner=pear_surface_owners+i;break; }
        if(!owner || pear_surface_sequence==UINT64_MAX) status=PEAR_METAL_CAPACITY_ERROR;
        else { owner->token=token=++pear_surface_sequence;owner->hwnd=hwnd;owner->refs=1; }
    }
    pthread_mutex_unlock(&pear_surface_mutex);
    if(status) return status;
    if(!(data=get_win_data((HWND)(UINT_PTR)hwnd))) { status=PEAR_METAL_WINDOW;goto failed; }
    generation=data->pear_metal_generation;
    if(shared) {
        if(!data->client_view || data->client_view!=owner->view) status=PEAR_METAL_STALE;
    } else if(data->client_view) status=PEAR_METAL_OWNER_CONFLICT;
    release_win_data(data);
    if(status) goto failed;
    if(shared) { *out=token;return PEAR_METAL_OK; }

    if(pear_surface_failure==1) { pear_surface_failure=0;status=PEAR_METAL_VIEW;goto failed; }
    surface=client_surface_create(&macdrv_client_surface_funcs,(HWND)(UINT_PTR)hwnd,0,FALSE);
    if(!surface) { status=PEAR_METAL_VIEW;goto failed; }
    owner->surface=&surface->client;
    surface->cocoa_view=macdrv_create_view(cgrect_from_rect(surface->client.monitor_rect));
    if(!surface->cocoa_view) { status=PEAR_METAL_VIEW;goto failed; }
    owner->view=surface->cocoa_view;
    macdrv_set_view_hidden(surface->cocoa_view,TRUE);
    use_window_client_surface(&surface->client,TRUE);
    if(pear_surface_failure==2) { pear_surface_failure=0;status=PEAR_METAL_VIEW;goto failed; }
    /* Recheck after allocation/registration. Window destruction or a foreign
     * renderer winning the race must never be overwritten by this adapter. */
    if(!(data=get_win_data((HWND)(UINT_PTR)hwnd))) { status=PEAR_METAL_WINDOW;goto failed; }
    if(data->pear_metal_generation!=generation || data->client_view) status=PEAR_METAL_STALE;
    else {
        data->client_view=surface->cocoa_view;
        data->pear_metal_generation=pear_metal_next_epoch();
        macdrv_set_view_hidden(surface->cocoa_view,FALSE);
        pear_macdrv_metal_changed(hwnd,data->pear_metal_generation);
    }
    release_win_data(data);
    if(status) goto failed;
    pthread_mutex_lock(&pear_surface_mutex);owner->ready=1;pthread_mutex_unlock(&pear_surface_mutex);
    *out=token;return PEAR_METAL_OK;
failed:
    if(shared || owner->surface) pear_macdrv_surface_drop(token);
    else {
        pthread_mutex_lock(&pear_surface_mutex);memset(owner,0,sizeof(*owner));pthread_mutex_unlock(&pear_surface_mutex);
    }
    return status;
}
