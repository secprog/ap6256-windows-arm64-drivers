/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include <ntddk.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <TraceLoggingProvider.h>
#include "trace.h"

TRACELOGGING_DEFINE_PROVIDER(Ap6256EtwProvider, "AP6256.Driver",
    (0x05c68da4, 0x3816, 0x40b7, 0x9d, 0x55, 0xaa, 0xae, 0x16, 0x44, 0xe8, 0x41));
static volatile LONG Ap6256EtwRegistered;
static volatile LONG Ap6256DebugLogLevel;

_Use_decl_annotations_
VOID Ap6256TraceSetDebugLevel(ULONG Level)
{
    if (Level > AP6256_DEBUG_LOG_VERBOSE) Level = AP6256_DEBUG_LOG_DISABLED;
    InterlockedExchange(&Ap6256DebugLogLevel, (LONG)Level);
}

static BOOLEAN Ap6256TraceDebugEnabled(UCHAR Level)
{
    return (BOOLEAN)(Level >= 2 && Level <= 5 &&
        (ULONG)InterlockedCompareExchange(&Ap6256DebugLogLevel, 0, 0) >= (ULONG)(Level - 1));
}

_Use_decl_annotations_
BOOLEAN Ap6256TraceInformationEnabled(ULONG Category)
{
    return (BOOLEAN)(Ap6256TraceDebugEnabled(4) ||
        (KeGetCurrentIrql() <= DISPATCH_LEVEL &&
         InterlockedCompareExchange(&Ap6256EtwRegistered, 0, 0) != 0 &&
         TraceLoggingProviderEnabled(Ap6256EtwProvider, 4, Category)));
}

static ULONG Ap6256TraceDebugImportance(ULONG DebugLevel)
{

    return DPFLTR_MASK | 1u | (DebugLevel < 32 ? (1u << DebugLevel) : DebugLevel);
}

_Use_decl_annotations_
NTSTATUS Ap6256TraceInitialize(VOID)
{
    Ap6256TraceSetDebugLevel(AP6256_DEBUG_LOG_DISABLED);
    NTSTATUS status = TraceLoggingRegister(Ap6256EtwProvider);
    InterlockedExchange(&Ap6256EtwRegistered, NT_SUCCESS(status) ? 1 : 0);
    return status;
}

_Use_decl_annotations_
VOID Ap6256TraceCleanup(VOID)
{
    Ap6256TraceSetDebugLevel(AP6256_DEBUG_LOG_DISABLED);

    if (InterlockedExchange(&Ap6256EtwRegistered, 0) != 0)
        TraceLoggingUnregister(Ap6256EtwProvider);
}

#define AP6256_ETW_MESSAGE(L, K) \
    TraceLoggingWrite(Ap6256EtwProvider, "DriverMessage", \
        TraceLoggingLevel(L), TraceLoggingKeyword(K), \
        TraceLoggingUInt32(Category, "Category"), \
        TraceLoggingString(Message, "Message"), \
        TraceLoggingBoolean(Truncated, "Truncated"))
#define AP6256_ETW_LEVELS(K) \
    switch (Level) { \
    case 2: AP6256_ETW_MESSAGE(2, K); break; \
    case 3: AP6256_ETW_MESSAGE(3, K); break; \
    case 5: AP6256_ETW_MESSAGE(5, K); break; \
    default: AP6256_ETW_MESSAGE(4, K); break; \
    }

static VOID Ap6256TraceWriteMessage(ULONG Category, UCHAR Level,
                                  PCSTR Message, BOOLEAN Truncated)
{
    switch (Category) {
    case TRACE_DEVICE: AP6256_ETW_LEVELS(TRACE_DEVICE); break;
    case TRACE_SDIO: AP6256_ETW_LEVELS(TRACE_SDIO); break;
    case TRACE_CHIP: AP6256_ETW_LEVELS(TRACE_CHIP); break;
    case TRACE_FIRMWARE: AP6256_ETW_LEVELS(TRACE_FIRMWARE); break;
    case TRACE_BCDC: AP6256_ETW_LEVELS(TRACE_BCDC); break;
    case TRACE_NETADAPTER: AP6256_ETW_LEVELS(TRACE_NETADAPTER); break;
    case TRACE_POWER: AP6256_ETW_LEVELS(TRACE_POWER); break;
    default: AP6256_ETW_LEVELS(TRACE_DRIVER); break;
    }
}

_Use_decl_annotations_
VOID Ap6256TraceMessage(ULONG Category, UCHAR Level, ULONG DebugLevel,
                       PCSTR Prefix, PCSTR Format, ...)
{
    va_list arguments;

    if (KeGetCurrentIrql() <= DISPATCH_LEVEL &&
        InterlockedCompareExchange(&Ap6256EtwRegistered, 0, 0) != 0 &&
        TraceLoggingProviderEnabled(Ap6256EtwProvider, Level, Category)) {
        CHAR message[AP6256_TRACE_MESSAGE_BYTES];
        NTSTATUS status;
        va_start(arguments, Format);
        status = RtlStringCbVPrintfA(message, sizeof(message), Format, arguments);
        va_end(arguments);
        message[sizeof(message) - 1] = '\0';
        if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW)
            Ap6256TraceWriteMessage(Category, Level, message,
                (BOOLEAN)(status == STATUS_BUFFER_OVERFLOW));
    }

    if (Ap6256TraceDebugEnabled(Level)) {
        va_start(arguments, Format);
        (VOID)vDbgPrintExWithPrefix(Prefix, AP6256_DPFLTR,
            Ap6256TraceDebugImportance(DebugLevel), Format, arguments);
        va_end(arguments);
    }
}

_Use_decl_annotations_
VOID Ap6256TracePacketMessage(PCSTR Format, ...)
{
    va_list arguments;
    if (!Ap6256TraceDebugEnabled(5)) return;
    va_start(arguments, Format);
    (VOID)vDbgPrintExWithPrefix("ap6256: DATA ", AP6256_DPFLTR,
        Ap6256TraceDebugImportance(AP6256_DEBUG_VERBOSE), Format, arguments);
    va_end(arguments);
}

#define AP6256_WATCHDOG_FIELDS \
    TraceLoggingUInt32(DeviceId, "DeviceId"), \
    TraceLoggingUInt32(Reason, "Reason"), \
    TraceLoggingNTStatus(Status, "Status"), \
    TraceLoggingUInt32(Pending, "Pending"), \
    TraceLoggingUInt32(Interrupts, "Interrupts"), \
    TraceLoggingUInt64(Polls, "Polls"), \
    TraceLoggingUInt64(Recoveries, "Recoveries"), \
    TraceLoggingUInt64(Failures, "ReadFailures")

_Use_decl_annotations_
VOID Ap6256TraceWatchdog(ULONG DeviceId, ULONG Reason, NTSTATUS Status,
                       ULONG Pending, ULONG Interrupts, ULONGLONG Polls,
                       ULONGLONG Recoveries, ULONGLONG Failures)
{
    if (InterlockedCompareExchange(&Ap6256EtwRegistered, 0, 0) == 0) return;
    if (Reason == 4) {
        TraceLoggingWrite(Ap6256EtwProvider, "WatchdogReadFailure",
            TraceLoggingLevel(3), TraceLoggingKeyword(TRACE_WATCHDOG),
            AP6256_WATCHDOG_FIELDS);
    } else if (Reason == 2 || Reason == 3) {
        TraceLoggingWrite(Ap6256EtwProvider, "WatchdogRecovery",
            TraceLoggingLevel(3), TraceLoggingKeyword(TRACE_WATCHDOG),
            AP6256_WATCHDOG_FIELDS);
    } else {
        TraceLoggingWrite(Ap6256EtwProvider, "WatchdogState",
            TraceLoggingLevel(4), TraceLoggingKeyword(TRACE_WATCHDOG),
            AP6256_WATCHDOG_FIELDS);
    }
}
