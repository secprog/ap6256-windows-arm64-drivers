/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#define AP6256_HOST_CIPHER_STORE_USER_TEST
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <assert.h>
#include <stdlib.h>
#include "../src/common/host_crypto_cng.h"

typedef UCHAR KIRQL;
typedef SRWLOCK TEST_KSPIN_LOCK;
#define KSPIN_LOCK TEST_KSPIN_LOCK
typedef CRITICAL_SECTION KMUTEX;
typedef struct _EX_RUNDOWN_REF {
    SRWLOCK Lock;
    CONDITION_VARIABLE Cv;
    ULONG References;
    BOOLEAN Closing;
} EX_RUNDOWN_REF;
#define PASSIVE_LEVEL 0
#define DISPATCH_LEVEL 2
#define Executive 0
#define KernelMode 0
#define POOL_FLAG_NON_PAGED 1
#define MAXULONG 0xffffffffUL
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

static __declspec(thread) KIRQL TestIrql;
static volatile LONG TestAllocations, TestFailAllocation, TestPauseCrypto;
static volatile LONG64 TestInterruptTime;
static HANDLE TestEntered, TestRelease, TestWaiting;

static KIRQL KeGetCurrentIrql(void) { return TestIrql; }
static ULONGLONG KeQueryInterruptTime(void) { return (ULONGLONG)InterlockedCompareExchange64(&TestInterruptTime, 0, 0); }
static void KeInitializeSpinLock(KSPIN_LOCK* p) { InitializeSRWLock(p); }
static void KeAcquireSpinLock(KSPIN_LOCK* p, KIRQL* Old)
{ *Old = TestIrql; AcquireSRWLockExclusive(p); TestIrql = DISPATCH_LEVEL; }
static void KeReleaseSpinLock(KSPIN_LOCK* p, KIRQL Old)
{ TestIrql = Old; ReleaseSRWLockExclusive(p); }
static void KeAcquireSpinLockAtDpcLevel(KSPIN_LOCK* p)
{ assert(TestIrql == DISPATCH_LEVEL); AcquireSRWLockExclusive(p); }
static void KeReleaseSpinLockFromDpcLevel(KSPIN_LOCK* p)
{ assert(TestIrql == DISPATCH_LEVEL); ReleaseSRWLockExclusive(p); }
static void KeInitializeMutex(KMUTEX* p, ULONG Level)
{ (void)Level; InitializeCriticalSection(p); }
static NTSTATUS KeWaitForSingleObject(KMUTEX* p, int Reason, int Mode,
    BOOLEAN Alertable, void* Timeout)
{
    (void)Reason; (void)Mode; assert(!Alertable && !Timeout && TestIrql == PASSIVE_LEVEL);
    EnterCriticalSection(p); return STATUS_SUCCESS;
}
static LONG KeReleaseMutex(KMUTEX* p, BOOLEAN Wait)
{ assert(!Wait && TestIrql == PASSIVE_LEVEL); LeaveCriticalSection(p); return 0; }
static void ExInitializeRundownProtection(EX_RUNDOWN_REF* p)
{ InitializeSRWLock(&p->Lock); InitializeConditionVariable(&p->Cv); p->References = 0; p->Closing = FALSE; }
static BOOLEAN ExAcquireRundownProtection(EX_RUNDOWN_REF* p)
{
    BOOLEAN ok;
    AcquireSRWLockExclusive(&p->Lock); ok = !p->Closing;
    if (ok) ++p->References;
    ReleaseSRWLockExclusive(&p->Lock); return ok;
}
static void ExReleaseRundownProtection(EX_RUNDOWN_REF* p)
{
    AcquireSRWLockExclusive(&p->Lock); assert(p->References); --p->References;
    if (!p->References) WakeAllConditionVariable(&p->Cv);
    ReleaseSRWLockExclusive(&p->Lock);
}
static void ExWaitForRundownProtectionRelease(EX_RUNDOWN_REF* p)
{
    assert(TestIrql == PASSIVE_LEVEL);
    AcquireSRWLockExclusive(&p->Lock); p->Closing = TRUE;
    while (p->References) {
        if (TestWaiting) SetEvent(TestWaiting);
        assert(SleepConditionVariableSRW(&p->Cv, &p->Lock, 10000, 0));
    }
    ReleaseSRWLockExclusive(&p->Lock);
}
static void* ExAllocatePool2(ULONG Flags, size_t Bytes, ULONG Tag)
{
    size_t* allocation;
    (void)Tag; assert(Flags == POOL_FLAG_NON_PAGED && TestIrql <= DISPATCH_LEVEL);
    if (InterlockedExchange(&TestFailAllocation, 0)) return NULL;
    allocation = calloc(1, sizeof(size_t) + Bytes);
    if (!allocation) return NULL;
    *allocation = Bytes; InterlockedIncrement(&TestAllocations);
    return allocation + 1;
}
static void ExFreePoolWithTag(void* p, ULONG Tag)
{
    size_t i, *allocation = (size_t*)p - 1;
    (void)Tag; assert(p);
    for (i = 0; i < *allocation; ++i) assert(((UCHAR*)p)[i] == 0);
    InterlockedDecrement(&TestAllocations); free(allocation);
}

static int TestCryptProxy(void* Context, int Encrypt,
    const AP6256_HC_U8 Nonce[12], const AP6256_HC_U8* Aad, AP6256_HC_U32 AadLength,
    const AP6256_HC_U8* Input, AP6256_HC_U32 InputLength,
    AP6256_HC_U8* Output, AP6256_HC_U8 Tag[16])
{
    assert(TestIrql == DISPATCH_LEVEL);
    if (InterlockedCompareExchange(&TestPauseCrypto, 0, 0)) {
        SetEvent(TestEntered);


        assert(WaitForSingleObject(TestRelease, 10000) == WAIT_OBJECT_0);
    }
    return Ap6256HostCryptoCrypt(Context, Encrypt, Nonce, Aad, AadLength,
        Input, InputLength, Output, Tag);
}
#define Ap6256HostCryptoCrypt TestCryptProxy
#include "../src/common/host_cipher_store.c"
#undef Ap6256HostCryptoCrypt

void* TestCreate(void)
{
    AP6256_HC_STORE* store = calloc(1, sizeof(*store));
    if (!store) return NULL;
    if (!NT_SUCCESS(Ap6256HostCipherStoreInit(store))) { free(store); return NULL; }
    if (!TestEntered) {
        TestEntered = CreateEventW(NULL, TRUE, FALSE, NULL);
        TestRelease = CreateEventW(NULL, TRUE, FALSE, NULL);
        TestWaiting = CreateEventW(NULL, TRUE, FALSE, NULL);
        assert(TestEntered && TestRelease && TestWaiting);
    }
    return store;
}
void TestDestroy(AP6256_HC_STORE* Store)
{
    Ap6256HostCipherStoreClose(Store); DeleteCriticalSection(&Store->Mutation); free(Store);
}
LONG TestPoolCount(void) { return InterlockedCompareExchange(&TestAllocations, 0, 0); }
ULONG TestKeyCount(AP6256_HC_STORE* Store)
{
    ULONG i, slot, count = 0;
    for (i = 0; i < AP6256_HC_INTERFACES; ++i)
        for (slot = 0; slot < AP6256_HC_SLOTS; ++slot)
            if (Store->Ports[i].Keys[slot]) ++count;
    return count;
}
ULONG TestFragmentCount(AP6256_HC_STORE* Store)
{
    ULONG i, slot, count = 0;
    for (i = 0; i < AP6256_HC_INTERFACES; ++i)
        if (Store->RxFragments[i])
            for (slot = 0; slot < AP6256_HC_RX_FRAGMENT_CACHE; ++slot)
                if (Store->RxFragments[i]->Entries[slot].Length) ++count;
    return count;
}
void TestSetPn(AP6256_HC_STORE* Store, ULONGLONG Pn)
{

    assert(TestIrql == PASSIVE_LEVEL && Pn >= Store->NextTransmitPn);
    Store->NextTransmitPn = Pn;
}
void TestFailAlloc(void) { InterlockedExchange(&TestFailAllocation, 1); }
void TestSetClock(ULONGLONG Time) { InterlockedExchange64(&TestInterruptTime, (LONG64)Time); }
void TestPause(void)
{
    ResetEvent(TestEntered); ResetEvent(TestRelease); ResetEvent(TestWaiting);
    InterlockedExchange(&TestPauseCrypto, 1);
}
int TestWaitEntered(void) { return WaitForSingleObject(TestEntered, 5000) == WAIT_OBJECT_0; }
int TestWaitRundown(void) { return WaitForSingleObject(TestWaiting, 5000) == WAIT_OBJECT_0; }
void TestUnpause(void) { InterlockedExchange(&TestPauseCrypto, 0); SetEvent(TestRelease); }
