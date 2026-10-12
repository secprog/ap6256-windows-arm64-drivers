/*
 * SPDX-License-Identifier: MS-PL
 * Copyright (c) Microsoft Corporation All Rights Reserved
 * See bt/LICENSE-MS-PL.txt for the license text.
 */

#include "driver.h"
#include "pdo.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, PdoCreate)
#pragma alloc_text(PAGE, PdoDevD0Exit)
#pragma alloc_text(PAGE, PdoDevD0Entry)
#pragma alloc_text(PAGE, PdoDevPrepareHardware)
#pragma alloc_text(PAGE, PdoDevReleaseHardware)
#pragma alloc_text(PAGE, PdoResetHandler)
#pragma alloc_text(PAGE, PdoDevSelfManagedIoInit)
#pragma alloc_text(PAGE, PdoDevSelfManagedIoCleanup)
#ifdef DYNAMIC_ENUM
#pragma alloc_text(PAGE, PdoCreateDynamic)
#pragma alloc_text(PAGE, PdoResetHandlerDynamic)
#endif
#endif

#define MAX_ID_LEN 80

#ifdef DYNAMIC_ENUM

_Use_decl_annotations_
NTSTATUS
PdoResetHandlerDynamic(
    PVOID               _InterfaceContext,
    DEVICE_RESET_TYPE   _ResetType,
    ULONG               _Flags,
    PVOID               _ResetParameters
    )

{
    PPDO_EXTENSION PdoExtension = (PPDO_EXTENSION) _InterfaceContext;
    NTSTATUS Status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(_Flags);
    UNREFERENCED_PARAMETER(_ResetParameters);

    if (_ResetType != PlatformLevelDeviceReset) {
        return STATUS_NOT_SUPPORTED;
    }

    Status = DeviceDoPLDR(PdoExtension->FdoExtension->WdfDevice);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    WdfDeviceSetFailed((WDFDEVICE) WdfObjectContextGetObject(PdoExtension), WdfDeviceFailedAttemptRestart);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PdoCreateDynamic(
    WDFDEVICE       _Device,
    PWDFDEVICE_INIT _DeviceInit,
    PWCHAR          _HardwareIds,
    ULONG           _SerialNo
    )

{
    NTSTATUS                        Status;
    PPDO_EXTENSION                  PdoExtension = NULL;
    WDFDEVICE                       ChildDevice = NULL;
    WDF_OBJECT_ATTRIBUTES           PdoAttributes;
    WDF_DEVICE_PNP_CAPABILITIES     PnpCaps;
    WDF_DEVICE_POWER_CAPABILITIES   PowerCaps;
    DECLARE_CONST_UNICODE_STRING(   CompatId, BT_PDO_COMPATIBLE_IDS);
    DECLARE_CONST_UNICODE_STRING(   DeviceLocation, L"Serial HCI Bus - Bluetooth Function");
    DECLARE_UNICODE_STRING_SIZE(    Buffer, MAX_ID_LEN);
    DECLARE_UNICODE_STRING_SIZE(    DeviceId, MAX_ID_LEN);
    WDF_IO_QUEUE_CONFIG             QueueConfig;
    WDFQUEUE                        Queue;
    WDF_QUERY_INTERFACE_CONFIG      DeviceResetInterfaceConfig;
    DEVICE_RESET_INTERFACE_STANDARD ResetInterface;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(_Device);

    KdPrint(("Entered PdoCreateDynamic\n"));

    WdfDeviceInitSetDeviceType(_DeviceInit, FILE_DEVICE_BUS_EXTENDER);

    RtlInitUnicodeString(&DeviceId, _HardwareIds);

    Status = WdfPdoInitAssignDeviceID(_DeviceInit, &DeviceId);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = WdfPdoInitAddHardwareID(_DeviceInit, &DeviceId);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = WdfPdoInitAddCompatibleID(_DeviceInit, &CompatId );
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status =  RtlUnicodeStringPrintf(&Buffer, L"%02d", _SerialNo);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = WdfPdoInitAssignInstanceID(_DeviceInit, &Buffer);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = RtlUnicodeStringPrintf( &Buffer,
                                     L"SerialHciBus_%02d",
                                     _SerialNo );
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = WdfPdoInitAddDeviceText(_DeviceInit,
                                    &Buffer,
                                    &DeviceLocation,
                                     0x409 );
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    WdfPdoInitSetDefaultLocale(_DeviceInit, 0x409);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&PdoAttributes, PDO_EXTENSION);

    WdfPdoInitAllowForwardingRequestToParent(_DeviceInit);

    Status = WdfDeviceCreate(&_DeviceInit,
                             &PdoAttributes,
                             &ChildDevice);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    PdoExtension = PdoGetExtension(ChildDevice);

    RtlZeroMemory(PdoExtension, sizeof(PDO_EXTENSION));

    PdoExtension->FdoExtension = FdoGetExtension(_Device);

    PdoExtension->SerialNo = _SerialNo;

    PdoExtension->ResetRecoveryType = SUPPORTED_RESET_RECOVERY_TYPE;

    WDF_DEVICE_PNP_CAPABILITIES_INIT(&PnpCaps);

    PnpCaps.Removable         = WdfFalse;

    PnpCaps.SurpriseRemovalOK = WdfTrue;

    PnpCaps.Address  = _SerialNo;
    PnpCaps.UINumber = _SerialNo;

    WdfDeviceSetPnpCapabilities(ChildDevice, &PnpCaps);

    WDF_DEVICE_POWER_CAPABILITIES_INIT(&PowerCaps);

    PowerCaps.DeviceD1 = WdfFalse;
    PowerCaps.DeviceD2 =
        PdoExtension->FdoExtension->HostWakeOperational ?
            WdfTrue : WdfFalse;
    PowerCaps.WakeFromD0 = WdfFalse;
    PowerCaps.WakeFromD1 = WdfFalse;
    PowerCaps.WakeFromD2 =
        PdoExtension->FdoExtension->HostWakeOperational ?
            WdfTrue : WdfFalse;

    PowerCaps.WakeFromD3 =
        PdoExtension->FdoExtension->HostWakeOperational ?
            WdfTrue : WdfFalse;
    PowerCaps.DeviceWake =
        PdoExtension->FdoExtension->HostWakeOperational ?
            PowerDeviceD2 : PowerDeviceUnspecified;

    PowerCaps.DeviceState[PowerSystemWorking]   = PowerDeviceD0;
    PowerCaps.DeviceState[PowerSystemSleeping1] =
        PdoExtension->FdoExtension->HostWakeOperational ?
            PowerDeviceD2 : PowerDeviceD3;
    PowerCaps.DeviceState[PowerSystemSleeping2] =
        PdoExtension->FdoExtension->HostWakeOperational ?
            PowerDeviceD2 : PowerDeviceD3;
    PowerCaps.DeviceState[PowerSystemSleeping3] =
        PdoExtension->FdoExtension->HostWakeOperational ?
            PowerDeviceD2 : PowerDeviceD3;
    PowerCaps.DeviceState[PowerSystemHibernate] = PowerDeviceD3;
    PowerCaps.DeviceState[PowerSystemShutdown]  = PowerDeviceD3;

    WdfDeviceSetPowerCapabilities(ChildDevice, &PowerCaps);

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&QueueConfig, WdfIoQueueDispatchParallel);

    QueueConfig.PowerManaged = WdfFalse;

    QueueConfig.EvtIoDeviceControl = PdoIoQuDeviceControl;

    Status = WdfIoQueueCreate(ChildDevice,
                              &QueueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &Queue);
    DoTrace(LEVEL_INFO, TFLAG_PNP, (" WdfIoQueueCreate (%!STATUS!)", Status));
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (PdoExtension->ResetRecoveryType == ResetRecoveryTypeParentResetInterface) {

        WDF_QUERY_INTERFACE_CONFIG_INIT(&DeviceResetInterfaceConfig, NULL, &GUID_DEVICE_RESET_INTERFACE_STANDARD, NULL);
        DeviceResetInterfaceConfig.SendQueryToParentStack = TRUE;

        Status = WdfDeviceAddQueryInterface(ChildDevice, &DeviceResetInterfaceConfig);
        if (!NT_SUCCESS(Status)) {
            DoTrace(LEVEL_ERROR, TFLAG_PNP, ("WdfDeviceAddQueryInterface failed, %!STATUS!", Status));
            goto Cleanup;
        }

    } else if (PdoExtension->ResetRecoveryType == ResetRecoveryTypeDriverImplemented) {

        RtlZeroMemory(&ResetInterface, sizeof(ResetInterface));
        ResetInterface.Size = sizeof(ResetInterface);
        ResetInterface.Version = DEVICE_RESET_INTERFACE_VERSION;
        ResetInterface.Context = PdoExtension;

        ResetInterface.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
        ResetInterface.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;

        ResetInterface.SupportedResetTypes = (1 << PlatformLevelDeviceReset);
        ResetInterface.DeviceReset = PdoResetHandlerDynamic;

        WDF_QUERY_INTERFACE_CONFIG_INIT(&DeviceResetInterfaceConfig, (PINTERFACE) &ResetInterface, &GUID_DEVICE_RESET_INTERFACE_STANDARD, NULL);
        Status = WdfDeviceAddQueryInterface(ChildDevice, &DeviceResetInterfaceConfig);
        if (!NT_SUCCESS(Status))
        {
            DoTrace(LEVEL_ERROR, TFLAG_PNP, ("WdfDeviceAddQueryInterface failed, %!STATUS!", Status));
            goto Cleanup;
        }
    }

Cleanup:

    if (!NT_SUCCESS(Status)) {

        DoTrace(LEVEL_ERROR, TFLAG_PNP, (" -PdoCreateDynamic: exit %!STATUS!", Status));

        if(ChildDevice) {
            WdfObjectDelete(ChildDevice);
        }
    }
    else
    {
        DoTrace(LEVEL_INFO, TFLAG_PNP, (" -PdoCreateDynamic: exit %!STATUS!", Status));
    }

    return Status;
}

#endif

_Use_decl_annotations_
NTSTATUS
PdoResetHandler(
    PVOID               _InterfaceContext,
    DEVICE_RESET_TYPE   _ResetType,
    ULONG               _Flags,
    PVOID               _ResetParameters
)

{
    PPDO_EXTENSION  PdoExtension = (PPDO_EXTENSION) _InterfaceContext;
    WDFDEVICE       Fdo = PdoExtension->FdoExtension->WdfDevice;
    NTSTATUS        Status;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(_Flags);
    UNREFERENCED_PARAMETER(_ResetParameters);

    if (_ResetType != PlatformLevelDeviceReset) {
        return STATUS_NOT_SUPPORTED;
    }

    Status = DeviceDoPLDR(Fdo);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = FdoRemoveOneChildDevice(Fdo, BLUETOOTH_FUNC_IDS);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    return FdoCreateOneChildDevice(
        Fdo,
        BT_PDO_HARDWARE_IDS,
        BLUETOOTH_FUNC_IDS);
}

NTSTATUS
PdoCreate(
    _In_ WDFDEVICE  _Device,
    _In_ PWSTR      _HardwareIds,
    _In_ ULONG      _SerialNo
)

{
    NTSTATUS                            Status;
    PWDFDEVICE_INIT                     DeviceInit = NULL;
    WDF_PNPPOWER_EVENT_CALLBACKS        PnpPowerCallbacks;
    PPDO_EXTENSION                      PdoExtension = NULL;
    WDFDEVICE                           ChildDevice = NULL;
    WDF_OBJECT_ATTRIBUTES               Attributes;
    WDF_DEVICE_PNP_CAPABILITIES         PnpCaps;
    WDF_DEVICE_POWER_CAPABILITIES       PowerCaps;
    UNICODE_STRING                      StaticString = {0};
    UNICODE_STRING                      DeviceId;
    DECLARE_UNICODE_STRING_SIZE(        Buffer, MAX_ID_LEN);
    UNICODE_STRING ContainerID =        {0};
    WDF_PDO_EVENT_CALLBACKS             Callbacks;
    WDF_IO_QUEUE_CONFIG                 QueueConfig;
    WDFQUEUE                            Queue;
    WDF_QUERY_INTERFACE_CONFIG          DeviceResetInterfaceConfig;
    DEVICE_RESET_INTERFACE_STANDARD     ResetInterface;

    DoTrace(LEVEL_INFO, TFLAG_PNP, (" +PdoCreate: HWID(%S), compatID(%S)", _HardwareIds, BT_PDO_COMPATIBLE_IDS));

    PAGED_CODE();

    DeviceInit = WdfPdoInitAllocate(_Device);
    if (DeviceInit == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_BUS_EXTENDER);

    RtlInitUnicodeString(&DeviceId, _HardwareIds);
    Status = WdfPdoInitAssignDeviceID(DeviceInit, &DeviceId);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = WdfPdoInitAddHardwareID(DeviceInit, &DeviceId);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    RtlInitUnicodeString(&StaticString, BT_PDO_COMPATIBLE_IDS);
    Status = WdfPdoInitAddCompatibleID(DeviceInit, &StaticString);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status =  RtlUnicodeStringPrintf(&Buffer, L"%02d", _SerialNo);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }
    Status = WdfPdoInitAssignInstanceID(DeviceInit, &Buffer);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    Status = RtlStringFromGUID(&GUID_CONTAINERID_INTERNALLY_CONNECTED_DEVICE, &ContainerID);
    if (!NT_SUCCESS(Status)) {
        DoTrace(LEVEL_ERROR, TFLAG_PNP, ("Failed to generate the ContainerID, %!STATUS!", Status));;
        goto Cleanup;
    }

    Status = WdfPdoInitAssignContainerID(DeviceInit, &ContainerID);
    if (!NT_SUCCESS(Status)) {
        DoTrace(LEVEL_ERROR, TFLAG_PNP, ("Failed to assign the ContainerID, %!STATUS!", Status));
        goto Cleanup;
    }

    Status = RtlUnicodeStringPrintf(&Buffer, L"SerialHciBus_%02d", _SerialNo );
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    RtlInitUnicodeString(&StaticString, BT_PDO_DEVICE_LOCATION);
    Status = WdfPdoInitAddDeviceText(DeviceInit,
                                     &Buffer,
                                     &StaticString,
                                     0x409);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    WdfPdoInitSetDefaultLocale(DeviceInit, 0x409);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attributes, PDO_EXTENSION);

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&PnpPowerCallbacks);

    PnpPowerCallbacks.EvtDevicePrepareHardware = PdoDevPrepareHardware;
    PnpPowerCallbacks.EvtDeviceReleaseHardware = PdoDevReleaseHardware;

    PnpPowerCallbacks.EvtDeviceD0Entry = PdoDevD0Entry;
    PnpPowerCallbacks.EvtDeviceD0Exit  = PdoDevD0Exit;

    PnpPowerCallbacks.EvtDeviceSelfManagedIoInit = PdoDevSelfManagedIoInit;
    PnpPowerCallbacks.EvtDeviceSelfManagedIoCleanup = PdoDevSelfManagedIoCleanup;

    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit,
                                           &PnpPowerCallbacks);

    WdfPdoInitAllowForwardingRequestToParent(DeviceInit);

    WDF_PDO_EVENT_CALLBACKS_INIT(&Callbacks);

    Callbacks.EvtDeviceEnableWakeAtBus  = PdoDevEnableWakeAtBus;

    Callbacks.EvtDeviceDisableWakeAtBus = PdoDevDisableWakeAtBus;

    WdfPdoInitSetEventCallbacks(DeviceInit, &Callbacks);

    Status = WdfDeviceCreate(&DeviceInit,
                             &Attributes,
                             &ChildDevice);
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    PdoExtension = PdoGetExtension(ChildDevice);

    RtlZeroMemory(PdoExtension, sizeof(PDO_EXTENSION));

    PdoExtension->FdoExtension = FdoGetExtension(_Device);

    PdoExtension->SerialNo = _SerialNo;

    PdoExtension->ResetRecoveryType = SUPPORTED_RESET_RECOVERY_TYPE;

    WDF_DEVICE_PNP_CAPABILITIES_INIT(&PnpCaps);

    PnpCaps.Removable         = WdfFalse;

    PnpCaps.SurpriseRemovalOK = WdfTrue;

    PnpCaps.Address  = _SerialNo;
    PnpCaps.UINumber = _SerialNo;

    WdfDeviceSetPnpCapabilities(ChildDevice, &PnpCaps);

    WDF_DEVICE_POWER_CAPABILITIES_INIT(&PowerCaps);

    PowerCaps.DeviceD1 = WdfFalse;
    PowerCaps.DeviceD2 =
        PdoExtension->FdoExtension->HostWakeOperational ?
            WdfTrue : WdfFalse;
    PowerCaps.WakeFromD0 = WdfFalse;
    PowerCaps.WakeFromD1 = WdfFalse;
    PowerCaps.WakeFromD2 =
        PdoExtension->FdoExtension->HostWakeOperational ?
            WdfTrue : WdfFalse;

    PowerCaps.WakeFromD3 =
        PdoExtension->FdoExtension->HostWakeOperational ?
            WdfTrue : WdfFalse;
    PowerCaps.DeviceWake =
        PdoExtension->FdoExtension->HostWakeOperational ?
            PowerDeviceD2 : PowerDeviceUnspecified;

    PowerCaps.DeviceState[PowerSystemWorking]   = PowerDeviceD0;
    PowerCaps.DeviceState[PowerSystemSleeping1] =
        PdoExtension->FdoExtension->HostWakeOperational ?
            PowerDeviceD2 : PowerDeviceD3;
    PowerCaps.DeviceState[PowerSystemSleeping2] =
        PdoExtension->FdoExtension->HostWakeOperational ?
            PowerDeviceD2 : PowerDeviceD3;
    PowerCaps.DeviceState[PowerSystemSleeping3] =
        PdoExtension->FdoExtension->HostWakeOperational ?
            PowerDeviceD2 : PowerDeviceD3;
    PowerCaps.DeviceState[PowerSystemHibernate] = PowerDeviceD3;
    PowerCaps.DeviceState[PowerSystemShutdown]  = PowerDeviceD3;

    WdfDeviceSetPowerCapabilities(ChildDevice, &PowerCaps);

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&QueueConfig, WdfIoQueueDispatchParallel);

    QueueConfig.PowerManaged = WdfFalse;

    QueueConfig.EvtIoDeviceControl = PdoIoQuDeviceControl;

    Status = WdfIoQueueCreate(ChildDevice,
                              &QueueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &Queue);
    DoTrace(LEVEL_INFO, TFLAG_PNP, (" WdfIoQueueCreate (%!STATUS!)", Status));
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

    if (PdoExtension->ResetRecoveryType == ResetRecoveryTypeParentResetInterface) {

        WDF_QUERY_INTERFACE_CONFIG_INIT(&DeviceResetInterfaceConfig, NULL, &GUID_DEVICE_RESET_INTERFACE_STANDARD, NULL);
        DeviceResetInterfaceConfig.SendQueryToParentStack = TRUE;

        Status = WdfDeviceAddQueryInterface(ChildDevice, &DeviceResetInterfaceConfig);
        if (!NT_SUCCESS(Status)) {
            DoTrace(LEVEL_ERROR, TFLAG_PNP, ("WdfDeviceAddQueryInterface failed, %!STATUS!", Status));
            goto Cleanup;
        }

    } else if (PdoExtension->ResetRecoveryType == ResetRecoveryTypeDriverImplemented) {

        RtlZeroMemory(&ResetInterface, sizeof(ResetInterface));
        ResetInterface.Size = sizeof(ResetInterface);
        ResetInterface.Version = DEVICE_RESET_INTERFACE_VERSION;
        ResetInterface.Context = PdoExtension;

        ResetInterface.InterfaceReference = WdfDeviceInterfaceReferenceNoOp;
        ResetInterface.InterfaceDereference = WdfDeviceInterfaceDereferenceNoOp;

        ResetInterface.SupportedResetTypes = (1 << PlatformLevelDeviceReset);
        ResetInterface.DeviceReset = PdoResetHandler;

        WDF_QUERY_INTERFACE_CONFIG_INIT(&DeviceResetInterfaceConfig, (PINTERFACE) &ResetInterface, &GUID_DEVICE_RESET_INTERFACE_STANDARD, NULL);
        Status = WdfDeviceAddQueryInterface(ChildDevice, &DeviceResetInterfaceConfig);
        if (!NT_SUCCESS(Status))
        {
            DoTrace(LEVEL_ERROR, TFLAG_PNP, ("WdfDeviceAddQueryInterface failed, %!STATUS!", Status));
            goto Cleanup;
        }
    }

    Status = WdfFdoAddStaticChild(_Device, ChildDevice);
    DoTrace(LEVEL_INFO, TFLAG_PNP, (" WdfFdoAddStaticChild (%!STATUS!)", Status));
    if (!NT_SUCCESS(Status)) {
        goto Cleanup;
    }

Cleanup:

    if (!NT_SUCCESS(Status)) {

        DoTrace(LEVEL_ERROR, TFLAG_PNP, (" -PdoCreate: exit %!STATUS!", Status));

        if (DeviceInit != NULL) {
            WdfDeviceInitFree(DeviceInit);
        }

        if(ChildDevice) {
            WdfObjectDelete(ChildDevice);
        }
    }
    else
    {
        DoTrace(LEVEL_INFO, TFLAG_PNP, (" -PdoCreate: exit %!STATUS!", Status));
    }

    if (NULL != ContainerID.Buffer) {
        RtlFreeUnicodeString(&ContainerID);
    }

    return Status;
}

NTSTATUS
PdoDevPrepareHardware(
    _In_  WDFDEVICE     _Device,
    _In_  WDFCMRESLIST  _ResourcesRaw,
    _In_  WDFCMRESLIST  _ResourcesTranslated
    )

{
    NTSTATUS Status = STATUS_SUCCESS;
    WDFDEVICE ParentDevice;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(_ResourcesRaw);
    UNREFERENCED_PARAMETER(_ResourcesTranslated);

    DoTrace(LEVEL_INFO, TFLAG_PNP,("+PdoDevPrepareHardware"));

    ParentDevice = WdfPdoGetParent(_Device);

    Status = WdfDeviceStopIdle(ParentDevice, FALSE);
    DoTrace(LEVEL_INFO, TFLAG_PNP, ("WdfDeviceStopIdle %!STATUS!", Status));

    NT_ASSERT(NT_SUCCESS(Status));

    DoTrace(LEVEL_INFO, TFLAG_PNP, ("-PdoDevPrepareHardware"));

    return Status;
}

NTSTATUS
PdoDevReleaseHardware(
    _In_  WDFDEVICE     _Device,
    _In_  WDFCMRESLIST  _ResourcesTranslated
    )

{
    WDFDEVICE ParentDevice;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(_ResourcesTranslated);

    DoTrace(LEVEL_INFO, TFLAG_PNP,("+PdoDevReleaseHardware"));

    ParentDevice = WdfPdoGetParent(_Device);

    WdfDeviceResumeIdle(ParentDevice);

    return STATUS_SUCCESS;
}

NTSTATUS
PdoDevD0Entry(
    _In_   WDFDEVICE              _Device,
    _In_   WDF_POWER_DEVICE_STATE _PreviousState
    )

{
    NTSTATUS       Status = STATUS_SUCCESS;

    PAGED_CODE();

    UNREFERENCED_PARAMETER(_Device);
    UNREFERENCED_PARAMETER(_PreviousState);

    DoTrace(LEVEL_INFO, TFLAG_UART, ("+PdoDevD0Entry"));

    DoTrace(LEVEL_INFO, TFLAG_UART, ("-PdoDevD0Entry %!STATUS!", Status));

    return Status;
}

NTSTATUS
PdoDevD0Exit(
    _In_   WDFDEVICE              _Device,
    _In_   WDF_POWER_DEVICE_STATE _TargetState
    )

{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(_Device);
    UNREFERENCED_PARAMETER(_TargetState);

    DoTrace(LEVEL_INFO, TFLAG_UART, ("+PdoDevD0Exit: D0 -> D%d", _TargetState-WdfPowerDeviceD0));

    DoTrace(LEVEL_INFO, TFLAG_UART, ("-PdoDevD0Exit"));

    return STATUS_SUCCESS;
}

VOID
PdoDevDisableWakeAtBus(
    _In_  WDFDEVICE _Device
    )

{

    DoTrace(LEVEL_INFO, TFLAG_POWER,("<==(D)== PdoDevDisableWakeAtBus"));

    PPDO_EXTENSION extension = PdoGetExtension(_Device);

    DeviceDisableWakeControl(
        extension->FdoExtension->WdfDevice);
}

NTSTATUS
PdoDevEnableWakeAtBus(
    _In_  WDFDEVICE          _Device,
    _In_  SYSTEM_POWER_STATE _PowerState
    )

{

    DoTrace(LEVEL_INFO, TFLAG_POWER,("==(E)==> PdoDevEnableWakeAtBus from %S",
            _PowerState == PowerSystemWorking ? L"S0" : L"Sx"));

    PPDO_EXTENSION extension = PdoGetExtension(_Device);

    return DeviceEnableWakeControl(
        extension->FdoExtension->WdfDevice,
        _PowerState);
}

VOID
PdoIoQuDeviceControl(
    _In_  WDFQUEUE     _Queue,
    _In_  WDFREQUEST   _Request,
    _In_  size_t       _OutputBufferLength,
    _In_  size_t       _InputBufferLength,
    _In_  ULONG        _IoControlCode
    )

{
    WDFDEVICE Device = NULL;
    NTSTATUS Status = STATUS_INVALID_PARAMETER;
    WDF_REQUEST_FORWARD_OPTIONS ForwardOptions;
    WDFDEVICE ParentDevice;
    ULONG ControlCode = (_IoControlCode & 0x00003ffc) >> 2;

    UNREFERENCED_PARAMETER(_OutputBufferLength);
    UNREFERENCED_PARAMETER(_InputBufferLength);

    DoTrace(LEVEL_INFO, TFLAG_IOCTL,("+IoDeviceControl - InBufLen:%d, OutBufLen:%d",
            (ULONG) _InputBufferLength, (ULONG) _OutputBufferLength));

    switch (_IoControlCode) {
    case IOCTL_BTHX_GET_VERSION:
    case IOCTL_BTHX_SET_VERSION:
    case IOCTL_BTHX_QUERY_CAPABILITIES:
    case IOCTL_BTHX_WRITE_HCI:
    case IOCTL_BTHX_READ_HCI:
        Device = WdfIoQueueGetDevice(_Queue);
        WDF_REQUEST_FORWARD_OPTIONS_INIT(&ForwardOptions);
        ForwardOptions.Flags = WDF_REQUEST_FORWARD_OPTION_SEND_AND_FORGET;
        ParentDevice = WdfPdoGetParent(Device);

        Status = WdfRequestForwardToParentDeviceIoQueue(_Request,
                                                        WdfDeviceGetDefaultQueue(ParentDevice),
                                                        &ForwardOptions);
        break;

    default:

        DoTrace(LEVEL_ERROR, TFLAG_IOCTL,("Unexpected IOCTL_(0x%x, Func %d)", _IoControlCode, ControlCode));
        break;
    }

    if (!NT_SUCCESS(Status)){
        DoTrace(LEVEL_ERROR, TFLAG_IOCTL,(" IOCTL_(0x%x, Func %d) failed %!STATUS!", _IoControlCode, ControlCode, Status));
        WdfRequestComplete(_Request, Status);
        return;
    }

    return;
}

NTSTATUS
PdoDevSelfManagedIoInit(
    _In_  WDFDEVICE  _Device
    )

{
    PPDO_EXTENSION PdoExtension = PdoGetExtension(_Device);
    PFDO_EXTENSION FdoExtension;

    PAGED_CODE();

    if ((PdoExtension == NULL) || (PdoExtension->FdoExtension == NULL)) {
        return STATUS_SUCCESS;
    }
    FdoExtension = PdoExtension->FdoExtension;

    if (FdoExtension->ReadEventQueue != NULL) {
        WdfIoQueueStart(FdoExtension->ReadEventQueue);
    }
    if (FdoExtension->ReadDataQueue != NULL) {
        WdfIoQueueStart(FdoExtension->ReadDataQueue);
    }

    BtTrace("pdo SelfManagedIoInit: parent read queues started\n");
    return STATUS_SUCCESS;
}

VOID
PdoDevSelfManagedIoCleanup(
    _In_  WDFDEVICE  _Device
    )

{
    PPDO_EXTENSION PdoExtension = PdoGetExtension(_Device);
    PFDO_EXTENSION FdoExtension;

    PAGED_CODE();

    if ((PdoExtension == NULL) || (PdoExtension->FdoExtension == NULL)) {
        return;
    }
    FdoExtension = PdoExtension->FdoExtension;

    if (FdoExtension->ReadEventQueue != NULL) {
        WdfIoQueuePurgeSynchronously(FdoExtension->ReadEventQueue);
    }
    if (FdoExtension->ReadDataQueue != NULL) {
        WdfIoQueuePurgeSynchronously(FdoExtension->ReadDataQueue);
    }

    ReadPacketListsPurge(FdoExtension);
    BtTrace("pdo SelfManagedIoCleanup: parent read queues purged\n");
}
