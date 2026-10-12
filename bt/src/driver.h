/*
 * SPDX-License-Identifier: MS-PL
 * Copyright (c) Microsoft Corporation All Rights Reserved
 * See bt/LICENSE-MS-PL.txt for the license text.
 */

#ifndef DRIVER_H
#define DRIVER_H

#include <ntddk.h>
#include <wdf.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#define INITGUID
#include <guiddef.h>
#include <wdmguid.h>
#include <ntddser.h>

#include <BthXDDI.h>

#include "device.h"
#include "io.h"
#include "debugdef.h"
#include "public.h"

#ifdef DEFINE_GUID

DEFINE_GUID(GUID_CONTAINERID_INTERNALLY_CONNECTED_DEVICE,
        0x00000000, 0x0000, 0x0000, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

#endif

#ifndef CommandComplete
#define CommandComplete 0x0e
#endif
#ifndef CommandStatus
#define CommandStatus   0x0f
#endif

#define POOLTAG_AP6256BT           'T625'
#define AP6256BT_MAX_GPIO_RESOURCES 4

#define BLUETOOTH_FUNC_IDS  0x1001

typedef enum _IDLE_CAP_STATE {
    IdleCapActiveOnly   = 1,
    IdleCapCanWake      = 2,
    IdleCapCanTurnOff   = 3
} IDLE_CAP_STATE;

typedef enum _RESET_RECOVERY_SUPPORT_TYPE {
    ResetRecoveryTypeNone                       = 0,

    ResetRecoveryTypeParentResetInterface       = 1,

    ResetRecoveryTypeDriverImplemented          = 2,

} RESET_RECOVERY_TYPE;

#define SUPPORTED_RESET_RECOVERY_TYPE ResetRecoveryTypeDriverImplemented

#ifdef DYNAMIC_ENUM

typedef struct _PDO_IDENTIFICATION_DESCRIPTION
{
    WDF_CHILD_IDENTIFICATION_DESCRIPTION_HEADER Header;

    ULONG SerialNo;

    size_t CchHardwareIds;

    _Field_size_bytes_(CchHardwareIds) PWCHAR HardwareIds;

} PDO_IDENTIFICATION_DESCRIPTION, *PPDO_IDENTIFICATION_DESCRIPTION;
#endif

typedef struct _UART_READ_CONTEXT *PUART_READ_CONTEXT;

typedef struct _FDO_EXTENSION
{
    WDFWAITLOCK ChildLock;

    BOOLEAN IsRadioEnabled;

    WDFDEVICE WdfDevice;

    WDFIOTARGET IoTargetSerial;

    WDFIOTARGET IoTargetRegOn;
    WDFIOTARGET IoTargetDevWake;

    WDFINTERRUPT HostWakeInterrupt;
    WDFWORKITEM DevWakeReleaseWorkItem;
    WDFWAITLOCK PowerLock;
    BOOLEAN HostWakeOperational;
    BOOLEAN SuspendedForIdle;
    LONG WakeArmed;
    LONG TxWakeReferences;
    LONG ResetInProgress;
    LONG PowerTransitionInProgress;
    LONG HostWakeCount;

    BTHX_CAPABILITIES  BthXCaps;

    BOOLEAN DeviceInitialized;

    LARGE_INTEGER UARTConnectionId;

    LARGE_INTEGER I2CConnectionId;

    LARGE_INTEGER GPIOConnectionIds[AP6256BT_MAX_GPIO_RESOURCES];
    ULONG GPIOConnectionCount;

    WDFREQUEST  RequestIoctlSync;

    WDFREQUEST  RequestWaitOnError;

    ULONG   SerErrorMask;

    WDFMEMORY   WaitMaskMemory;

    BOOLEAN    HardwareErrorDetected;

    BOOLEAN     ReadPumpRunning;

    ULONG   OutOfSyncErrorCount;

    WDFSPINLOCK  QueueAccessLock;

    WDFQUEUE DefaultQueue;

    UART_READ_CONTEXT ReadContext;

    WDFREQUEST  ReadRequest;
    WDFMEMORY   ReadMemory;
    UCHAR       ReadBuffer[MAX_H4_HCI_PACKET_SIZE];

#if DBG

    UCHAR       LastPacket[MAX_H4_HCI_PACKET_SIZE];
    ULONG       LastPacketLength;
#endif

    WDFQUEUE    ReadEventQueue;
    LONG        EventQueueCount;

    LIST_ENTRY  ReadEventList;
    LONG        EventListCount;

    WDFQUEUE    ReadDataQueue;
    LONG        DataQueueCount;

    LIST_ENTRY  ReadDataList;
    LONG        DataListCount;

    ULONG       PrefetchedPacketBytes;

    LONG       CntCommandReq;
    LONG       CntCommandCompleted;

    LONG       CntEventReq;
    LONG       CntEventCompleted;

    LONG       CntWriteDataReq;
    LONG       CntWriteDataCompleted;

    LONG       CntReadDataReq;
    LONG       CntReadDataCompleted;
} FDO_EXTENSION, *PFDO_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(FDO_EXTENSION, FdoGetExtension)

#define IsDeviceInitialized(FdoExtension) (FdoExtension->DeviceInitialized)

#define ValidConnectionID(ConnectionId) (ConnectionId.QuadPart != 0)

typedef struct _PDO_EXTENSION
{

    PFDO_EXTENSION FdoExtension;

    ULONG SerialNo;

    RESET_RECOVERY_TYPE ResetRecoveryType;

} PDO_EXTENSION, *PPDO_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(PDO_EXTENSION, PdoGetExtension)

EVT_WDF_OBJECT_CONTEXT_CLEANUP DriverCleanup;

VOID
DriverSetDeviceCallbackEvents(
    _In_  PWDFDEVICE_INIT  _DeviceInit
    );

EVT_WDF_DRIVER_DEVICE_ADD DriverDeviceAdd;

DRIVER_INITIALIZE DriverEntry;

NTSTATUS
HlpInitializeFdoExtension(WDFDEVICE   _Device);

NTSTATUS
FdoWriteDeviceIO(_In_ WDFREQUEST        _RequestFromBthport,
                 _In_ WDFDEVICE         _Device,
                 _In_ PFDO_EXTENSION    _FdoExtension,
                 _In_ PBTHX_HCI_READ_WRITE_CONTEXT _HCIContext);

NTSTATUS
FdoWriteToDeviceSync(_In_ WDFIOTARGET  _IoTargetSerial,
                     _In_ WDFREQUEST   _RequestWriteSync,
                     _In_ ULONG        _IoControlCode,
                     _In_opt_ ULONG    _InBufferSize,
                     _In_opt_ PVOID    _InBuffer,
                     _Out_ PULONG_PTR  _BytesWritten);

NTSTATUS
DeviceConfigWaitOnError(_In_ WDFIOTARGET    _IoTargetSerial,
                        _In_ WDFREQUEST     _RequestWaitOnError,
                        _In_ WDFMEMORY      _WaitMaskMemory,
                        _In_ PULONG         _ErrorResult,
                        _In_ PFDO_EXTENSION _FdoExtension);

NTSTATUS
HCIContextValidate(ULONG Index,
                   PBTHX_HCI_READ_WRITE_CONTEXT _HCIContext);

EVT_WDF_DEVICE_ARM_WAKE_FROM_S0     FdoEvtDeviceArmWake;
EVT_WDF_DEVICE_DISARM_WAKE_FROM_S0  FdoEvtDeviceDisarmWake;

EVT_WDF_DEVICE_ARM_WAKE_FROM_SX     FdoEvtDeviceArmWake;
EVT_WDF_DEVICE_DISARM_WAKE_FROM_SX  FdoEvtDeviceDisarmWake;

EVT_WDF_INTERRUPT_ISR FdoEvtHostWakeIsr;

EVT_WDF_DEVICE_PREPARE_HARDWARE  FdoDevPrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE  FdoDevReleaseHardware;

EVT_WDF_DEVICE_D0_ENTRY          FdoDevD0Entry;
EVT_WDF_DEVICE_D0_EXIT           FdoDevD0Exit;

EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT  FdoDevSelfManagedIoInit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_CLEANUP  FdoDevSelfManagedIoCleanup;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT  PdoDevSelfManagedIoInit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_CLEANUP  PdoDevSelfManagedIoCleanup;

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL FdoIoQuDeviceControl;

#ifdef DYNAMIC_ENUM

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PdoResetHandlerDynamic(_In_ PVOID              _InterfaceContext,
                       _In_ DEVICE_RESET_TYPE  _ResetType,
                       _In_ ULONG              _Flags,
                       _In_opt_ PVOID          _ResetParameters);

EVT_WDF_CHILD_LIST_CREATE_DEVICE FdoEvtDeviceListCreatePdo;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PdoCreateDynamic(_In_ WDFDEVICE       Device,
                 _In_ PWDFDEVICE_INIT DeviceInit,
                 _In_ PWCHAR          HardwareIds,
                 _In_ ULONG           SerialNo);

NTSTATUS
FdoCreateOneChildDeviceDynamic(_In_ WDFDEVICE  _Device,
                               _In_ PWCHAR     _HardwareIds,
                               _In_ size_t     _CchHardwareIds,
                               _In_ ULONG      _SerialNo);
#endif

EVT_WDF_DEVICE_DISABLE_WAKE_AT_BUS PdoDevDisableWakeAtBus;
EVT_WDF_DEVICE_ENABLE_WAKE_AT_BUS  PdoDevEnableWakeAtBus;

NTSTATUS
FdoCreateOneChildDevice(_In_ WDFDEVICE  _Device,
                        _In_ PWCHAR     _HardwareIds,
                        _In_ ULONG      _SerialNo);

NTSTATUS
FdoCreateAllChildren(_In_ WDFDEVICE _Device);

NTSTATUS
FdoRemoveOneChildDevice(WDFDEVICE   _Device,
                        ULONG       _SerialNo);

NTSTATUS
FdoFindConnectResources(_In_ WDFDEVICE    _Device,
                        _In_ WDFCMRESLIST _ResourcesRaw,
                        _In_ WDFCMRESLIST _ResourcesTranslated);

EVT_WDF_DEVICE_PREPARE_HARDWARE  PdoDevPrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE  PdoDevReleaseHardware;

EVT_WDF_DEVICE_D0_ENTRY         PdoDevD0Entry;
EVT_WDF_DEVICE_D0_EXIT          PdoDevD0Exit;

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL PdoIoQuDeviceControl;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
PdoResetHandler(_In_ PVOID              _InterfaceContext,
                _In_ DEVICE_RESET_TYPE  _ResetType,
                _In_ ULONG              _Flags,
                _In_opt_ PVOID          _ResetParameters);

NTSTATUS
PdoCreate(_In_ WDFDEVICE  _Device,
          _In_ PWSTR      _HardwareIds,
          _In_ ULONG      _SerialNo);

VOID
PdoDevDisableWakeAtBus(_In_ WDFDEVICE _Device);

NTSTATUS
PdoDevEnableWakeAtBus(_In_ WDFDEVICE          _Device,
                      _In_ SYSTEM_POWER_STATE _PowerState);

NTSTATUS ReadResourcesAllocate(_In_ WDFDEVICE _Device);
VOID ReadResourcesFree(_In_ WDFDEVICE _Device);
VOID ReadResourcesReset(_In_ WDFDEVICE _Device);
VOID ReadPacketListsPurge(_In_ PFDO_EXTENSION _FdoExtension);

NTSTATUS
HLP_AllocateResourceForWrite(_In_ WDFDEVICE   _Device,
                             _In_ WDFIOTARGET _IoTargetSerial,
                             _Out_ WDFREQUEST *_pRequest);

VOID
HLP_FreeResourceForWrite(PUART_WRITE_CONTEXT _TransferContext);

EVT_WDF_REQUEST_CANCEL CB_RequestFromBthportCancel;

EVT_WDF_REQUEST_COMPLETION_ROUTINE CR_WriteDeviceIO;

NTSTATUS
ReadRequestComplete(_In_ PFDO_EXTENSION    _FdoExtension,
                    _In_ UCHAR             _Type,
                    _In_ ULONG             _PacketLength,
                    _In_reads_bytes_opt_(_PacketLength) PUCHAR _Packet,
                    _Inout_  WDFQUEUE      _Queue,
                    _Inout_  PLONG         _QueueCount,
                    _Inout_  PLIST_ENTRY   _ListHead,
                    _Inout_  PLONG         _ListCount);

EVT_WDF_REQUEST_COMPLETION_ROUTINE ReadH4PacketCompletionRoutine;

NTSTATUS
ReadH4Packet(_In_ PUART_READ_CONTEXT _ReadContext,
             _In_  WDFREQUEST        _WdfRequest,
             _In_  WDFMEMORY         _WdfMemory,
             _Pre_notnull_ _Pre_writable_byte_size_(_BufferCapacity) PVOID _Buffer,
             _In_  ULONG             _BufferCapacity,
             _In_  ULONG             _BufferLen);

VOID
DeviceQueryDeviceParameters(_In_ WDFDRIVER  _Driver);

BOOLEAN
DeviceInitialize(_In_ PFDO_EXTENSION _FdoExtension,
                 _In_ WDFIOTARGET    _IoTargetSerial,
                 _In_ WDFREQUEST     _RequestSync,
                 _In_ BOOLEAN        _ResetUart);

NTSTATUS
DeviceEnableWakeControl(_In_ WDFDEVICE          _Device,
                        _In_ SYSTEM_POWER_STATE _PowerState);
void
DeviceDisableWakeControl(WDFDEVICE _Device);

BOOLEAN
DeviceSleepModeRequested(VOID);

NTSTATUS
DeviceAcquireTxWake(_In_ PFDO_EXTENSION _FdoExtension,
                    _Out_ PBOOLEAN _WakeReferenceHeld);

VOID
DeviceReleaseTxWake(_In_ PFDO_EXTENSION _FdoExtension);

VOID
DeviceScheduleSleep(_In_ PFDO_EXTENSION _FdoExtension);

EVT_WDF_WORKITEM DeviceDevWakeReleaseWorker;

NTSTATUS
DeviceEnable(_In_ WDFDEVICE _Device,
             _In_ BOOLEAN   _Enabled);

NTSTATUS
DevicePowerOn(_In_ WDFDEVICE _Device);

NTSTATUS
DevicePowerOff(_In_ WDFDEVICE _Device);

NTSTATUS
DeviceDoPLDR(_In_ WDFDEVICE _Fdo);

#endif
