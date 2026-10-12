/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include <ntddk.h>

#define AP6256_DPFLTR  DPFLTR_IHVDRIVER_ID

#define TRACE_DRIVER    0x0001
#define TRACE_DEVICE    0x0002
#define TRACE_SDIO      0x0004
#define TRACE_CHIP      0x0008
#define TRACE_FIRMWARE  0x0010
#define TRACE_BCDC      0x0020
#define TRACE_NETADAPTER 0x0040
#define TRACE_POWER     0x0080
#define TRACE_WATCHDOG  0x0100

#define AP6256_TRACE_MESSAGE_BYTES 512u
#define AP6256_DEBUG_LOG_DISABLED 0u
#define AP6256_DEBUG_LOG_ERRORS 1u
#define AP6256_DEBUG_LOG_WARNINGS 2u
#define AP6256_DEBUG_LOG_INFORMATION 3u
#define AP6256_DEBUG_LOG_VERBOSE 4u

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256TraceLoadDebugSettings(_In_opt_ PDEVICE_OBJECT Pdo);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256TraceSetDebugLevel(_In_ ULONG Level);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256TracePacketMessage(_In_ _Printf_format_string_ PCSTR Format, ...);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256TraceInitialize(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256TraceCleanup(VOID);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256TraceMessage(_In_ ULONG Category, _In_ UCHAR Level,
    _In_ ULONG DebugLevel, _In_ PCSTR Prefix,
    _In_ _Printf_format_string_ PCSTR Format, ...);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256TraceWatchdog(_In_ ULONG DeviceId, _In_ ULONG Reason,
    _In_ NTSTATUS Status, _In_ ULONG Pending, _In_ ULONG Interrupts,
    _In_ ULONGLONG Polls, _In_ ULONGLONG Recoveries, _In_ ULONGLONG Failures);

#define AP6256_DEBUG_VERBOSE 4

#define TraceError(Category, ...) \
    Ap6256TraceMessage(Category, 2, DPFLTR_ERROR_LEVEL, "ap6256: ERR  ", __VA_ARGS__)
#define TraceWarn(Category, ...) \
    Ap6256TraceMessage(Category, 3, DPFLTR_WARNING_LEVEL, "ap6256: WARN ", __VA_ARGS__)
#define TraceInfo(Category, ...) \
    Ap6256TraceMessage(Category, 4, DPFLTR_INFO_LEVEL, "ap6256: INFO ", __VA_ARGS__)
#define TraceVerbose(Category, ...) \
    Ap6256TraceMessage(Category, 5, AP6256_DEBUG_VERBOSE, "ap6256: VERB ", __VA_ARGS__)

#define TraceDiag(...) \
    Ap6256TraceMessage(TRACE_DRIVER, 4, DPFLTR_ERROR_LEVEL, "ap6256: DIAG ", __VA_ARGS__)

#ifndef AP6256_TRACE_DATAPATH
#define AP6256_TRACE_DATAPATH 0
#endif

#if AP6256_TRACE_DATAPATH
#define TraceData(...) \
    Ap6256TracePacketMessage(__VA_ARGS__)
#else
#define TraceData(...) __noop(__VA_ARGS__)
#endif

#define TraceEntry() \
    TraceVerbose(TRACE_DRIVER, "--> %s\n", __FUNCTION__)
#define TraceExit(Status) \
    TraceVerbose(TRACE_DRIVER, "<-- %s = 0x%08X\n", __FUNCTION__, (Status))
