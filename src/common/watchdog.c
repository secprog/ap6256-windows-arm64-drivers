/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "datapath.h"
#include "sdio.h"

static volatile LONG Ap6256WatchdogNextId;
static AP6256_WORKITEM_ROUTINE Ap6256WatchdogTick;

static BOOLEAN Ap6256WatchdogAwake(PAP6256_DEVICE_CONTEXT Ctx)
{
    return (BOOLEAN)(Ctx->DatapathRunning && !Ctx->Sdio.Sleeping &&
        Ctx->Sdio.ClockOn && Ctx->Sdio.BusInterface != NULL &&
        Ctx->Chip.SdiodCore != NULL && Ctx->FirmwareState == Ap6256FwRunning &&
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) == 0);
}

static VOID Ap6256WatchdogEvent(PAP6256_DEVICE_CONTEXT Ctx, ULONG Reason,
                              NTSTATUS Status, UCHAR Pending)
{
    AP6256_WATCHDOG* w = &Ctx->Watchdog;
    Ap6256TraceWatchdog(w->DeviceId, Reason, Status, Pending,
        (ULONG)InterlockedCompareExchange(&Ctx->Sdio.IsrCount, 0, 0),
        (ULONGLONG)InterlockedCompareExchange64(&w->Polls, 0, 0),
        (ULONGLONG)InterlockedCompareExchange64(&w->Recoveries, 0, 0),
        (ULONGLONG)InterlockedCompareExchange64(&w->ReadFailures, 0, 0));
}

_Use_decl_annotations_
NTSTATUS Ap6256WatchdogCreate(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WATCHDOG* w = &Ctx->Watchdog;
    if (Ap6256TimerValid(&w->Timer)) return STATUS_SUCCESS;
    KeInitializeSpinLock(&w->Lock);
    if (w->DeviceId == 0)
        w->DeviceId = (ULONG)InterlockedIncrement(&Ap6256WatchdogNextId);
    return Ap6256TimerCreate(&w->Timer, Ctx->Fdo, Ap6256WatchdogTick, Ctx);
}

_Use_decl_annotations_
VOID Ap6256WatchdogStart(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WATCHDOG* w = &Ctx->Watchdog;
    KIRQL irql;
    if (!Ap6256TimerValid(&w->Timer)) return;
    KeAcquireSpinLock(&w->Lock, &irql);
    w->LastIsr = InterlockedCompareExchange(&Ctx->Sdio.IsrCount, 0, 0);
    InterlockedExchange64(&w->LastRecovery, 0);
    w->Enabled = TRUE;
    Ap6256TimerStart(&w->Timer, AP6256_WATCHDOG_IDLE_MS);
    KeReleaseSpinLock(&w->Lock, irql);
    Ap6256WatchdogEvent(Ctx, 0, STATUS_SUCCESS, 0);
}

_Use_decl_annotations_
VOID Ap6256WatchdogStop(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WATCHDOG* w = &Ctx->Watchdog;
    KIRQL irql;
    BOOLEAN enabled;
    if (!Ap6256TimerValid(&w->Timer)) return;
    KeAcquireSpinLock(&w->Lock, &irql);
    enabled = w->Enabled;
    w->Enabled = FALSE;
    Ap6256TimerStop(&w->Timer, FALSE);
    KeReleaseSpinLock(&w->Lock, irql);

    Ap6256TimerStop(&w->Timer, TRUE);
    InterlockedExchange(&w->PollRequested, 0);
    if (enabled) Ap6256WatchdogEvent(Ctx, 1, STATUS_SUCCESS, 0);
}

_Use_decl_annotations_
VOID Ap6256WatchdogDestroy(PAP6256_DEVICE_CONTEXT Ctx)
{
    Ap6256WatchdogStop(Ctx);
    Ap6256TimerDestroy(&Ctx->Watchdog.Timer);
}

_Use_decl_annotations_
static VOID Ap6256WatchdogTick(PVOID Context)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)Context;
    AP6256_WATCHDOG* w = &ctx->Watchdog;
    KIRQL irql;
    LONG count;
    ULONG due = AP6256_WATCHDOG_IDLE_MS;
    ULONGLONG now = KeQueryInterruptTime();
    LONGLONG recovered;

    KeAcquireSpinLock(&w->Lock, &irql);
    if (!w->Enabled) goto done;
    if (!Ap6256WatchdogAwake(ctx)) {
        w->Enabled = FALSE;
        goto done;
    }
    count = InterlockedCompareExchange(&ctx->Sdio.IsrCount, 0, 0);
    if (count != w->LastIsr) {
        w->LastIsr = count;
        InterlockedExchange64(&w->LastRecovery, 0);
    } else if (InterlockedCompareExchange(&ctx->FrameWorker.Outstanding, 0, 0) == 0 &&
               InterlockedCompareExchange(&ctx->FrameDraining, 0, 0) == 0) {
        InterlockedExchange(&w->PollIsr, count);
        InterlockedExchange(&w->PollRequested, 1);
        Ap6256WorkItemEnqueue(&ctx->FrameWorker);
    }
    recovered = InterlockedCompareExchange64(&w->LastRecovery, 0, 0);
    if (recovered != 0 && now >= (ULONGLONG)recovered &&
        now - (ULONGLONG)recovered < AP6256_WATCHDOG_ACTIVE_WINDOW)
        due = AP6256_WATCHDOG_ACTIVE_MS;
    Ap6256TimerStart(&w->Timer, due);
done:
    KeReleaseSpinLock(&w->Lock, irql);
}

_Use_decl_annotations_
BOOLEAN Ap6256WatchdogCheckPending(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WATCHDOG* w = &Ctx->Watchdog;
    UCHAR pending = 0;
    NTSTATUS status;
    ULONG reason;
    if (!Ap6256WatchdogAwake(Ctx)) return FALSE;
    InterlockedIncrement64(&w->Polls);
    status = Ap6256SdioReadF0(Ctx, 0x05  , &pending);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement64(&w->ReadFailures);
        if (w->ConsecutiveFailures != MAXULONG) ++w->ConsecutiveFailures;
        if (w->ConsecutiveFailures == 1 || (w->ConsecutiveFailures % 64u) == 0)
            Ap6256WatchdogEvent(Ctx, 4, status, 0);
        return FALSE;
    }
    w->ConsecutiveFailures = 0;
    if ((pending & (SDIO_CCCR_IEN_FUNC1 | SDIO_CCCR_IEN_FUNC2)) != 0) {
        reason = 2;
    } else if (Ctx->RxSkip &&
               KeQueryInterruptTime() - Ctx->RxSkipSince >= 2000ull * 10000ull) {
        reason = 3;
    } else {
        return FALSE;
    }
    InterlockedIncrement64(&w->Recoveries);
    InterlockedExchange64(&w->LastRecovery, (LONGLONG)KeQueryInterruptTime());
    Ap6256WatchdogEvent(Ctx, reason, STATUS_SUCCESS, pending);
    return TRUE;
}
