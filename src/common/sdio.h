/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include "ap6256.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusAcquireInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdBusReleaseInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdBusCmd52(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                          _In_ BOOLEAN Write, _In_ UCHAR Function,
                          _In_ ULONG Address, _Inout_ PUCHAR Data);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdBusCmd53(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                          _In_ BOOLEAN Write, _In_ UCHAR Function,
                          _In_ ULONG Address, _In_ BOOLEAN Incrementing,
                          _Inout_updates_bytes_(Length) PUCHAR Buffer,
                          _In_ ULONG Length);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdBusCmd53Mode(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_ BOOLEAN Write, _In_ UCHAR Function,
                              _In_ ULONG Address, _In_ BOOLEAN Incrementing,
                              _Inout_updates_bytes_(Length) PUCHAR Buffer,
                              _In_ ULONG Length,
                              _In_ BOOLEAN ByteMode);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusSetBlockSize(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ UCHAR Function, _In_ ULONG BlockSize);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusGetHostBlockSize(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                     _Out_ PUSHORT BlockSize);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioSetCardBlockSize(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ UCHAR Function,
                                    _In_ ULONG BlockSize);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusGetBusClock(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ PULONG Clock);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusSetBusClock(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Clock);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusGetBusWidth(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ PUCHAR Width);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusSetBusWidth(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Width);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusEnableFunction(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ UCHAR Function);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdBusAbortFunction(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Function);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusDisableFunction(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ UCHAR Function);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusRegisterInterrupt(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256SdBusAckInterrupt(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdioReadF0(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Address, _Out_ PUCHAR Value);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdioWriteF0(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Address, _In_ UCHAR Value);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdioReadF1(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Address, _Out_ PUCHAR Value);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdioWriteF1(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Address, _In_ UCHAR Value);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioSetBackplaneWindow(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioReadBackplane32(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address, _Out_ PUINT32 Value);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioWriteBackplane32(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address, _In_ UINT32 Value);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioRamRW(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Write,
                         _In_ UINT32 Address,
                         _Inout_updates_bytes_(Length) PUCHAR Buffer,
                         _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioFrameRW(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Write,
                           _Inout_updates_bytes_(Length) PUCHAR Buffer,
                           _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioFrameReadHeader(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _Out_writes_bytes_(Length) PUCHAR Buffer,
                                   _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
PUCHAR Ap6256SdioMapHostRegisters(VOID);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdioUnmapHostRegisters(_In_opt_ PUCHAR Regs);
_IRQL_requires_max_(APC_LEVEL)
VOID Ap6256SdioDumpTransferFailure(_In_opt_ PUCHAR Regs, _In_ PCSTR Label);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioBusFallback(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioEnableBackplaneClock(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN WantHt);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioDisableBackplaneClock(_In_ PAP6256_DEVICE_CONTEXT Ctx);

#define AP6256_SDIO_FUNC_BACKPLANE  1u
#define AP6256_SDIO_FUNC_DATA       2u

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdioRxFail(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                      _In_ BOOLEAN Abort,
                      _In_ BOOLEAN RequestRetransmit);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdioTxFail(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdioTraceBusStats(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(APC_LEVEL)
VOID Ap6256SdioDumpCardState(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Label);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioInitializeRetention(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioSetSleep(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Sleep);
