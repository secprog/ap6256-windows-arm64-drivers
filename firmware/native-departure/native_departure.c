/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "native_departure.h"
#include "native_departure_api.h"

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int i32;

#define W(p,o) (*(u32*)((u8*)(p)+(o)))
#define B(p,o) (*((u8*)(p)+(o)))
#define FN(a,t,...) ((t (*)(__VA_ARGS__))((a)|1u))

struct iovar {const char* name;u16 id,flags,type,minimum;};
struct state {
    u32 abi,wlc,bss,peer,key;
    AP6256_NATIVE_DEPARTURE_CONTROL receipt;
};
#define S ((struct state*)R9_ND_STATE)

_Static_assert(sizeof(AP6256_NATIVE_DEPARTURE_CONTROL)==48,"departure ABI");
_Static_assert(sizeof(struct state)<=256,"departure state reservation");

static void copy(void* d,const void* s,u32 n) {u8* a=d;const u8* b=s;while(n--)*a++=*b++;}
static void zero(void* d,u32 n) {u8* a=d;while(n--)*a++=0;}
static i32 equal(const void* a,const void* b,u32 n) {
    const u8* x=a;const u8* y=b;while(n--)if(*x++!=*y++)return 0;return 1;
}
static u32 enter(void) {u32 m;__asm__ volatile("mrs %0,cpsr\n\tcpsid if":"=r"(m)::"memory");return m;}
static void leave(u32 m) {__asm__ volatile("msr cpsr_c,%0"::"r"(m):"memory");}

static u32 policy(void* wlc,void* bss,void** found) {
    void* peer;u8 session[64];
    *found=0;
    if(!wlc || !bss || W(bss,0)!=(u32)wlc || B(bss,6) || !B(bss,5) ||
        !B(bss,8) || !B(bss,0x10) || !W(wlc,0x26c) ||
        W((void*)W(wlc,0x26c),0)!=(u32)bss ||
        FN(R9_ND_HC_SNAPSHOT,i32,void*,void*,void*)(wlc,bss,session))return 0;
    if(!(W(bss,0x50)&0x600u))return 0;
    peer=FN(0x9def0,void*,void*,void*,const u8*)(wlc,bss,(u8*)bss+0xd8);
    if(!peer || W(peer,0x10)!=(u32)bss || W(peer,4)&0x400000u ||
        !equal((u8*)peer+0x14,(u8*)bss+0xd8,6))return AP6256_ND_PMF;
    *found=peer;
    if(!(W(peer,8)&0x200u) || !W(peer,0xc) || B((void*)W(peer,0xc),8)!=4 ||
        !(W(bss,0x50)&4u))return AP6256_ND_PMF;
    return AP6256_ND_PMF|AP6256_ND_ELIGIBLE;
}

static i32 bound(void* wlc) {
    void* peer;
    return S->abi==AP6256_ND_ABI && S->wlc==(u32)wlc &&
        W(wlc,0x26c) && W((void*)W(wlc,0x26c),0)==S->bss &&
        policy(wlc,(void*)S->bss,&peer)==(AP6256_ND_PMF|AP6256_ND_ELIGIBLE) &&
        (u32)peer==S->peer && W(peer,0xc)==S->key &&
        equal((u8*)peer+0x14,S->receipt.Peer,6);
}

void r9_nd_done(void* wlc,u32 status,u32 token) {
    u32 mask=enter();
    if(S->abi!=AP6256_ND_ABI || S->wlc!=(u32)wlc || S->receipt.Token!=token ||
        S->receipt.State!=AP6256_ND_PENDING)goto done;
    S->receipt.TxStatus=status;
    if(!bound(wlc)) {S->receipt.NativeStatus=-16;S->receipt.State=AP6256_ND_FAILED;}
    else if(status&2u) {S->receipt.NativeStatus=0;S->receipt.State=AP6256_ND_ACKED;}
    else {S->receipt.NativeStatus=-12;S->receipt.State=AP6256_ND_FAILED;}
done:leave(mask);
}

static i32 callback_space(void* wlc) {
    void* pcb=(void*)W(wlc,0x49c);u32 i,count;u8* table;
    if(!pcb || W(pcb,0)!=(u32)wlc || !(count=W(pcb,4)) || count>255 || !W(pcb,8))return 0;
    table=(u8*)W(pcb,8);
    for(i=1;i<=count;i++)if(!W(table+12*i,0))return 1;
    return 0;
}

static i32 control(void* wlc,void* bss,u32 action,const u8* p,u32 plen,void* arg,u32 alen) {
    AP6256_NATIVE_DEPARTURE_CONTROL a;
    void* peer;void* packet;u32 mask,flags;
    if(!p || plen!=sizeof(a) || (!(action&1) && (!arg || alen<sizeof(a))))return -2;
    copy(&a,p,sizeof(a));
    if(a.Abi!=AP6256_ND_ABI || a.Bytes!=sizeof(a) || a.Reserved[0] || a.Reserved[1] ||
        a.State || a.NativeStatus || a.TxStatus || a.Attempts || a.Flags)return -2;
    mask=enter();
    if(S->abi && (S->abi!=AP6256_ND_ABI || S->wlc!=(u32)wlc)){leave(mask);return -16;}
    if(!S->abi) {zero(S,sizeof(*S));S->abi=AP6256_ND_ABI;S->wlc=(u32)wlc;}
    if(!(action&1)) {
        if(a.Operation || a.Reason || !equal(a.Peer,"\0\0\0\0\0\0",6) ||
            (a.Token && a.Token!=S->receipt.Token)){leave(mask);return -2;}
        if(a.Token)copy(&a,&S->receipt,sizeof(a));
        a.Abi=AP6256_ND_ABI;a.Bytes=sizeof(a);
        a.Flags=policy(wlc,bss,&peer);
        if(!a.Token && peer)copy(a.Peer,(u8*)peer+0x14,6);
        copy(arg,&a,sizeof(a));leave(mask);return 0;
    }
    if(!a.Token || !a.Reason || a.Reason>65535 || (a.Peer[0]&1) ||
        (a.Operation!=AP6256_ND_START && a.Operation!=AP6256_ND_COMMIT)){leave(mask);return -2;}
    if(a.Token==S->receipt.Token) {
        if(a.Reason!=S->receipt.Reason || !equal(a.Peer,S->receipt.Peer,6) ||
            S->bss!=(u32)bss){leave(mask);return -16;}
        if(a.Operation==AP6256_ND_START || S->receipt.State==AP6256_ND_COMMITTED){leave(mask);return 0;}
        if(S->receipt.State!=AP6256_ND_ACKED || !bound(wlc)){leave(mask);return -16;}
        S->receipt.Operation=AP6256_ND_COMMIT;
        S->receipt.State=AP6256_ND_COMMITTING;
        if(FN(0x9dc20,i32,void*,u32,u32,u32)(bss,0,0,0)) {
            S->receipt.State=AP6256_ND_FAILED;S->receipt.NativeStatus=-16;
            leave(mask);return 0;
        }
        FN(0x4c818,i32,void*,void*)(wlc,bss);
        if(B(bss,5) || B(bss,8)) {
            S->receipt.State=AP6256_ND_FAILED;S->receipt.NativeStatus=-16;
            leave(mask);return 0;
        }
        S->receipt.State=AP6256_ND_COMMITTED;
        leave(mask);return 0;
    }
    if(a.Operation!=AP6256_ND_START || S->receipt.State==AP6256_ND_PENDING ||
        S->receipt.State==AP6256_ND_ACKED || S->receipt.State==AP6256_ND_COMMITTING){leave(mask);return -16;}
    flags=policy(wlc,bss,&peer);
    if(flags!=(AP6256_ND_PMF|AP6256_ND_ELIGIBLE) ||
        !equal(a.Peer,(u8*)bss+0xd8,6)){leave(mask);return -16;}
    S->bss=(u32)bss;S->peer=(u32)peer;S->key=W(peer,0xc);
    copy(&S->receipt,&a,sizeof(a));S->receipt.State=AP6256_ND_PENDING;S->receipt.Attempts=1;
    if(!callback_space(wlc))goto failed;
    packet=FN(0x323f0,void*,void*,void*,void*,const u8*,const u8*,const u8*,u32)
        (wlc,bss,peer,a.Peer,a.Peer,(u8*)bss+0xde,a.Reason);
    if(!packet)goto failed;
    if(FN(0x6eb08,i32,void*,void*,u32,void*)((void*)W(wlc,0x49c),
        (void*)r9_nd_done,a.Token,packet))goto failed;
    leave(mask);return 0;
failed:
    S->receipt.State=AP6256_ND_FAILED;S->receipt.NativeStatus=-1;
    leave(mask);return 0;
}

__attribute__((used))
const struct iovar r9_nd_iovars[]={R9_ND_PREVIOUS_IOVARS
    {"wdi_native_departure",0x8140,0,8,48},{0,0,0,0,0}};

i32 r9_nd_control(void* wlc,const struct iovar* vi,u32 action,const char* name,
    const u8* p,u32 plen,void* arg,u32 alen,u32 value_size,void* interface) {
    const struct iovar* old;
    void* bss;
    if(vi<r9_nd_iovars || vi>=r9_nd_iovars+R9_ND_PREVIOUS_COUNT+1)return -23;
    if(vi->id!=0x8140) {
        old=(const struct iovar*)R9_ND_PREVIOUS_TABLE+(vi-r9_nd_iovars);
        return FN(R9_ND_PREVIOUS_CONTROL,i32,void*,const struct iovar*,u32,const char*,
            const u8*,u32,void*,u32,u32,void*)(wlc,old,action,name,p,plen,arg,alen,value_size,interface);
    }
    if(!wlc || !W(wlc,0))return -2;
    bss=FN(0x1b5bf0,void*,void*,void*)(wlc,interface);
    if(!bss || W(bss,0)!=(u32)wlc || B(bss,6))return -2;
    return control(wlc,bss,action,p,plen,arg,alen);
}
