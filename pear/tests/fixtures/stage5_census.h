/* Private original Pear ownership diagnostic. SPDX-License-Identifier: MIT.
 * This ledger owns no observed object and is never a qualification predicate.
 * It records allocations and terminal release paths, not retainCount guesses.
 * The opt-in INIT epoch cannot account for earlier untouched live objects.
 * Direct target identities do not enumerate indirect container ownership. */
#ifndef PEAR_STAGE5_CENSUS_H
#define PEAR_STAGE5_CENSUS_H
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#define PEAR_S5_CENSUS_CAPACITY 2048u
#define PEAR_S5_CENSUS_DETAIL 32u
#define PEAR_S5_CENSUS_WINDOWS 20u
enum { PEAR_S5_CENSUS_EVENT=1, PEAR_S5_CENSUS_QUERY=2 };
enum { PEAR_S5_CENSUS_ALLOC=1, PEAR_S5_CENSUS_BIND=2, PEAR_S5_CENSUS_FREE=3 };
enum { PEAR_S5_DRAW_SCHEDULED=1, PEAR_S5_DRAW_ENTERED=2, PEAR_S5_DRAW_COMPLETED=3 };
struct pear_s5_census_object {
    uintptr_t identity,target;
    unsigned kind,type,bound,live;
};
struct pear_s5_census_window {
    uintptr_t target;
    uint64_t scheduled,entered,completed,after_close;
};
struct pear_s5_census_state {
    pthread_mutex_t lock;
    struct pear_s5_census_object objects[PEAR_S5_CENSUS_CAPACITY];
    struct pear_s5_census_window windows[PEAR_S5_CENSUS_WINDOWS];
    unsigned used,overflow,errors;
    uint64_t marker_submitted,marker_completed;
};
struct pear_s5_census_detail { unsigned ordinal,kind,type,target_match; };
struct pear_s5_census_snapshot {
    uint64_t allocations,overflow,errors,events_live,events_target;
    uint64_t queries_live,queries_target,queries_unbound,details_truncated,complete;
    uint64_t draw_scheduled,draw_entered,draw_completed,draw_after_close;
    uint64_t marker_submitted,marker_completed,detail_count,indirect_unobserved;
    struct pear_s5_census_detail details[PEAR_S5_CENSUS_DETAIL];
};
void pear_stage5_census_object(unsigned,unsigned,uintptr_t,uintptr_t,unsigned);
void pear_stage5_census_draw(uintptr_t,unsigned,unsigned);
#ifdef PEAR_S5_CENSUS_IMPLEMENTATION
static void pear_s5_census_object(struct pear_s5_census_state *state,unsigned kind,
                                unsigned action,uintptr_t identity,uintptr_t target,unsigned type)
{
    struct pear_s5_census_object *entry=NULL;
    pthread_mutex_lock(&state->lock);
    if(!identity || kind<PEAR_S5_CENSUS_EVENT || kind>PEAR_S5_CENSUS_QUERY ||
       action<PEAR_S5_CENSUS_ALLOC || action>PEAR_S5_CENSUS_FREE){state->errors++;goto done;}
    for(unsigned i=state->used;i;i--){
        struct pear_s5_census_object *candidate=state->objects+i-1;
        if(candidate->live && candidate->kind==kind && candidate->identity==identity){entry=candidate;break;}
    }
    if(action==PEAR_S5_CENSUS_ALLOC){
        if(entry){state->errors++;goto done;}
        if(state->used==PEAR_S5_CENSUS_CAPACITY){state->overflow++;goto done;}
        entry=state->objects+state->used++;
        entry->identity=identity;entry->target=target;entry->kind=kind;entry->type=type;
        entry->bound=kind==PEAR_S5_CENSUS_EVENT;entry->live=1;
    }else if(!entry){
        /* A prior capacity failure may explain a missing identity; still unknown. */
        state->errors++;
    }else if(action==PEAR_S5_CENSUS_BIND){
        if(entry->bound && (entry->target!=target || (kind==PEAR_S5_CENSUS_QUERY && entry->type!=type)))state->errors++;
        else {entry->target=target;entry->type=type;entry->bound=1;}
    }else{
        if(entry->bound && (entry->target!=target || (kind==PEAR_S5_CENSUS_QUERY && entry->type!=type)))state->errors++;
        entry->target=target;entry->type=type;entry->bound=1;entry->live=0;
    }
done:
    pthread_mutex_unlock(&state->lock);
}
static void pear_s5_census_register_window(struct pear_s5_census_state *state,unsigned cycle,uintptr_t target)
{
    pthread_mutex_lock(&state->lock);
    if(!cycle || cycle>PEAR_S5_CENSUS_WINDOWS || !target || state->windows[cycle-1].target)state->errors++;
    else state->windows[cycle-1].target=target;
    pthread_mutex_unlock(&state->lock);
}
static void pear_s5_census_draw(struct pear_s5_census_state *state,uintptr_t target,unsigned action,unsigned closing)
{
    pthread_mutex_lock(&state->lock);
    for(unsigned i=PEAR_S5_CENSUS_WINDOWS;i;i--){
        struct pear_s5_census_window *window=state->windows+i-1;
        if(!target || window->target!=target)continue;
        if(action==PEAR_S5_DRAW_SCHEDULED)window->scheduled++;
        else if(action==PEAR_S5_DRAW_ENTERED){window->entered++;window->after_close+=!!closing;}
        else if(action==PEAR_S5_DRAW_COMPLETED)window->completed++;
        else state->errors++;
        break;
    }
    pthread_mutex_unlock(&state->lock);
}
static void pear_s5_census_marker(struct pear_s5_census_state *state,unsigned completed)
{
    pthread_mutex_lock(&state->lock);
    if(completed)state->marker_completed++;
    else state->marker_submitted++;
    pthread_mutex_unlock(&state->lock);
}
static void pear_s5_census_read(struct pear_s5_census_state *state,unsigned cycle,uintptr_t target,
                               unsigned indirect_event_type,struct pear_s5_census_snapshot *out)
{
    memset(out,0,sizeof(*out));
    pthread_mutex_lock(&state->lock);
    out->allocations=state->used;out->overflow=state->overflow;out->errors=state->errors;
    for(unsigned i=0;i<state->used;i++){
        const struct pear_s5_census_object *entry=state->objects+i;
        if(!entry->live)continue;
        if(entry->kind==PEAR_S5_CENSUS_EVENT){
            out->events_live++;out->events_target+=entry->target==target;
            out->indirect_unobserved+=entry->type==indirect_event_type;
        }
        else {out->queries_live++;out->queries_target+=entry->bound && entry->target==target;out->queries_unbound+=!entry->bound;}
        if((entry->bound && entry->target==target) || !entry->bound){
            if(out->detail_count==PEAR_S5_CENSUS_DETAIL)out->details_truncated++;
            else {
                struct pear_s5_census_detail *detail=out->details+out->detail_count++;
                detail->ordinal=i+1;detail->kind=entry->kind;detail->type=entry->type;
                detail->target_match=entry->bound && entry->target==target;
            }
        }
    }
    if(!cycle || cycle>PEAR_S5_CENSUS_WINDOWS || state->windows[cycle-1].target!=target)out->errors++;
    else {
        const struct pear_s5_census_window *window=state->windows+cycle-1;
        out->draw_scheduled=window->scheduled;out->draw_entered=window->entered;
        out->draw_completed=window->completed;out->draw_after_close=window->after_close;
    }
    out->marker_submitted=state->marker_submitted;out->marker_completed=state->marker_completed;
    out->complete=!out->overflow && !out->errors && !out->queries_unbound && !out->details_truncated && !out->indirect_unobserved;
    pthread_mutex_unlock(&state->lock);
}
#endif /* PEAR_S5_CENSUS_IMPLEMENTATION */
#endif
