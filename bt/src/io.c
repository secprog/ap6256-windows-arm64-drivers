/*
 * SPDX-License-Identifier: MS-PL
 * Copyright (c) Microsoft Corporation All Rights Reserved
 * See bt/LICENSE-MS-PL.txt for the license text.
 */

#include "driver.h"
#include "IO.tmh"

#pragma warning(disable:4127)

#ifdef ALLOC_PRAGMA
#endif

VOID
CB_RequestFromBthportCancel(
    _In_ WDFREQUEST _RequestFromUpper
    )

{
    PUART_WRITE_CONTEXT TransferContext;
    WDFREQUEST  RequestToUART;
    WDFMEMORY   Memory;
    BOOLEAN CancelSuccess;
    LONG CompletePath = REQUEST_PATH_NONE;

    DoTrace(LEVEL_WARNING, TFLAG_IO, ("+CB_RequestFromBthportCancel: Request(%p) from upper driver", _RequestFromUpper));

    TransferContext = GetWriteRequestContext(_RequestFromUpper);
    NT_ASSERT(TransferContext && L"TransferContext is not valid!");

    RequestToUART = TransferContext->RequestToUART;
    Memory = TransferContext->Memory;

    CompletePath = InterlockedOr(&TransferContext->RequestCompletePath, REQUEST_PATH_CANCELLATION);

    if (REQUEST_PATH_NONE == CompletePath) {

        DoTrace(LEVEL_WARNING, TFLAG_IO, ("  >CancelSentRequest(%p) to IO Target", RequestToUART));
        CancelSuccess = WdfRequestCancelSentRequest(RequestToUART);
        DoTrace(LEVEL_WARNING, TFLAG_IO, ("  <CancelSentRequest: %S", CancelSuccess ? L"Cancelled" : L"Failed"));

        WdfObjectDereference(RequestToUART);

        WdfObjectDelete(Memory);

        WdfRequestComplete(_RequestFromUpper, STATUS_CANCELLED);
    }

}

NTSTATUS
HLP_AllocateResourceForWrite(
    _In_  WDFDEVICE   _Device,
    _In_  WDFIOTARGET _IoTargetSerial,
    _Out_ WDFREQUEST *_PRequest
    )

{
    NTSTATUS Status;
    WDF_OBJECT_ATTRIBUTES ObjAttributes;

    DoTrace(LEVEL_INFO, TFLAG_IO,("+HLP_AllocateResourceForWrite"));

    WDF_OBJECT_ATTRIBUTES_INIT(&ObjAttributes);
    ObjAttributes.ParentObject = _Device;

    Status = WdfRequestCreate(&ObjAttributes,
                              _IoTargetSerial,
                              _PRequest);

    if (!NT_SUCCESS(Status))
    {
        DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfRequestCreate() failed %!STATUS!", Status));
        goto Done;
    }

Done:

    return Status;
}

VOID
HLP_FreeResourceForWrite(
    PUART_WRITE_CONTEXT _TransferContext
    )

{
    DoTrace(LEVEL_INFO, TFLAG_IO,("+HLP_FreeResourceForWrite"));

    if (_TransferContext)
    {
        if (_TransferContext->Memory)
        {
           WdfObjectDelete(_TransferContext->Memory);
           _TransferContext->Memory = NULL;
        }

        if (_TransferContext->RequestToUART)
        {
            WdfObjectDelete(_TransferContext->RequestToUART);
            _TransferContext->RequestToUART = NULL;

        }
    }
}

VOID
CR_WriteDeviceIO(
    _In_  WDFREQUEST  _Request,
    _In_  WDFIOTARGET  _Target,
    _In_  PWDF_REQUEST_COMPLETION_PARAMS  _Params,
    _In_  WDFCONTEXT  _Context
    )

{
    NTSTATUS Status;
    PUART_WRITE_CONTEXT TransferContext;
    PFDO_EXTENSION FdoExtension;
    WDFREQUEST RequestFromBthport;
    ULONG  BytesDataWritten = 0;
    LONG CompletePath = REQUEST_PATH_NONE;

    UNREFERENCED_PARAMETER(_Target);

    Status = _Params->IoStatus.Status;
    TransferContext = (PUART_WRITE_CONTEXT) _Context;

    DoTrace(LEVEL_INFO, TFLAG_DATA,("+CR_WriteDeviceIO: %!STATUS!, Request %p, Context %p",
            Status, _Request, _Context));

    NT_ASSERT( (Status == STATUS_SUCCESS || Status == STATUS_CANCELLED) && L"WriteHCI request failed!");

    RequestFromBthport = TransferContext->RequestFromBthport;

    CompletePath = InterlockedOr(&TransferContext->RequestCompletePath, REQUEST_PATH_COMPLETION);

    if (REQUEST_PATH_NONE != CompletePath)
    {
        DoTrace(LEVEL_ERROR, TFLAG_IO,(" Request %p is in the process of being cancelled", RequestFromBthport));
    }
    else
    {

        if (STATUS_CANCELLED == WdfRequestUnmarkCancelable(RequestFromBthport)) {

            CompletePath = InterlockedCompareExchange(&TransferContext->RequestCompletePath,
                                                      REQUEST_PATH_NONE,
                                                      REQUEST_PATH_COMPLETION);

            if (CompletePath & REQUEST_PATH_CANCELLATION) {
                CompletePath = REQUEST_PATH_NONE;
            }
        }

        if (REQUEST_PATH_NONE == CompletePath) {

            WdfObjectDereference(_Request);

            if (NT_SUCCESS(Status))
            {
                WDFMEMORY ReqOutMemory = NULL;
                ULONG  BytesWritten;
                PULONG    OutBuffer = NULL;
                size_t    OutBufferSize = 0;

                BytesWritten =  (ULONG) _Params->Parameters.Write.Length;

                DoTrace(LEVEL_INFO, TFLAG_DATA,("   Packet: Type %d, DataLen %d, BytesWritten %d",
                        TransferContext->HCIContext->Type,
                        TransferContext->HCIContext->DataLen,
                        BytesWritten));

                NT_ASSERT(BytesWritten == TransferContext->HCIPacketLen && "Unexpected incomplete HCI Write!");

                if (BytesWritten != TransferContext->HCIPacketLen)
                {

                    Status = STATUS_UNSUCCESSFUL;
                    goto Done;
                }

                Status = WdfRequestRetrieveOutputMemory(RequestFromBthport, &ReqOutMemory);
                if (NT_SUCCESS(Status))
                {
                    OutBuffer = (PULONG) WdfMemoryGetBuffer(ReqOutMemory, &OutBufferSize);
                    if (OutBufferSize >= sizeof(ULONG))
                    {

                        *OutBuffer = TransferContext->HCIContext->DataLen;
                        BytesDataWritten = sizeof(ULONG);
                    }
                }
            }
            else
            {

            }
        }
    }

Done:

    if (TransferContext->WakeReferenceHeld) {
        TransferContext->WakeReferenceHeld = FALSE;
        DeviceReleaseTxWake(TransferContext->FdoExtension);
    }

    if (REQUEST_PATH_NONE == CompletePath)
    {

        FdoExtension = TransferContext->FdoExtension;

        if (TransferContext->HCIContext->Type == (UCHAR) HciPacketCommand)
        {
            InterlockedIncrement(&FdoExtension->CntCommandCompleted);
        }
        else if (TransferContext->HCIContext->Type == (UCHAR) HciPacketAclData)
        {
            InterlockedIncrement(&FdoExtension->CntWriteDataCompleted);
        }

        DoTrace(LEVEL_INFO, TFLAG_IO,(" WriteDeviceIO: Request %p complete with %!STATUS! and %d BytesDataWritten",
                RequestFromBthport, Status, BytesDataWritten));

        WdfObjectDelete(TransferContext->Memory);

        WdfRequestCompleteWithInformation(RequestFromBthport, Status, BytesDataWritten);

    }

    WdfObjectDelete(_Request);

    WdfObjectDereference(RequestFromBthport);

    DoTrace(LEVEL_INFO, TFLAG_IO,("-CR_WriteDeviceIO"));
}

VOID
ReadSegmentStateSet(
    PUART_READ_CONTEXT _ReadContext,
    UART_READ_STATE    _NewState
    )

{
    UART_READ_STATE OldState = _ReadContext->ReadSegmentState;

    DoTrace(LEVEL_INFO, TFLAG_IO, ("+<<<< -- %s to %s state -- >>>>",
            OldState == GET_PKT_TYPE           ? "Type"    :
            OldState == GET_PKT_HEADER         ? "Header"  :
            OldState == GET_PKT_PAYLOAD        ? "Payload" :
            OldState == GET_PKT_DISCARD_PAYLOAD ? "Discard" : "Unknown",
            _NewState == GET_PKT_TYPE           ? "Type"    :
            _NewState == GET_PKT_HEADER         ? "Header"  :
            _NewState == GET_PKT_PAYLOAD        ? "Payload" :
            _NewState == GET_PKT_DISCARD_PAYLOAD ? "Discard" : "Unknown" ));

    switch (_NewState)
    {
        case GET_PKT_TYPE:

            _ReadContext->BytesReadNextSegment = 0;
            _ReadContext->H4Packet.Type = 0;
            _ReadContext->BytesToRead4FullPacket = 0;
            RtlZeroMemory(_ReadContext->H4Packet.Packet.Raw, HCI_ACLDATA_HEADER_LEN);
            break;
        case GET_PKT_HEADER:
        case GET_PKT_PAYLOAD:
        case GET_PKT_DISCARD_PAYLOAD:

            _ReadContext->BytesReadNextSegment = 0;
            break;
    }

    _ReadContext->ReadSegmentState = _NewState;
}

NTSTATUS
ReadH4PacketComplete(
    PFDO_EXTENSION _FdoExtension,
    UCHAR  _Type,
    _In_reads_bytes_(_BufferLength) PUCHAR _Buffer,
    ULONG  _BufferLength
    )
{
    NTSTATUS Status = STATUS_SUCCESS;

    DoTrace(LEVEL_INFO, TFLAG_IO, ("+ReadH4PacketComplete %S Packet Length %d",
        _Type == (UCHAR) HciPacketEvent ? L"Event" : L"AclData", _BufferLength ));

#if DBG

    RtlCopyMemory(_FdoExtension->LastPacket, _Buffer, _BufferLength);
    _FdoExtension->LastPacketLength = _BufferLength;
#endif

    if (_Type == (UCHAR) HciPacketEvent)
    {
        Status = ReadRequestComplete(_FdoExtension,
                            HciPacketEvent,
                            _BufferLength,
                            _Buffer,
                            _FdoExtension->ReadEventQueue,
                            &_FdoExtension->EventQueueCount,
                            &_FdoExtension->ReadEventList,
                            &_FdoExtension->EventListCount);
    }
    else
    {
        Status = ReadRequestComplete(_FdoExtension,
                            HciPacketAclData,
                            _BufferLength,
                            _Buffer,
                            _FdoExtension->ReadDataQueue,
                           &_FdoExtension->DataQueueCount,
                           &_FdoExtension->ReadDataList,
                           &_FdoExtension->DataListCount);
    }

    DoTrace(LEVEL_INFO, TFLAG_IO, ("-ReadH4PacketComplete %!STATUS!", Status));

    return STATUS_SUCCESS;
}

NTSTATUS
ReadH4PacketReassemble(
    _Inout_  PUART_READ_CONTEXT _ReadContext,
    _In_  ULONG  _BytesRead,
    _In_reads_bytes_(_BytesRead) PUCHAR _Buffer
    )

{
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BytesRemained = _BytesRead;
    PUCHAR Buffer = _Buffer;
    PFDO_EXTENSION FdoExtension = _ReadContext->FdoExtension;
    PH4_PACKET H4Packet;
    ULONG PacketLen;
    ULONG BytesToRead;

    DoTrace(LEVEL_INFO, TFLAG_IO, ("+ReadH4PacketReassemble: %d _BytesRead, ReadSegmentState %d",
        _BytesRead, _ReadContext->ReadSegmentState));

    while (NT_SUCCESS(Status) && BytesRemained > 0) {

        switch (_ReadContext->ReadSegmentState) {
        case GET_PKT_TYPE:
            H4Packet = (PH4_PACKET) Buffer;
            BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, 1);

            if (H4Packet->Type == (UCHAR) HciPacketEvent) {
                DoTrace(LEVEL_INFO, TFLAG_IO, (" [Event] ---------- "));
                 _ReadContext->BytesToRead4FullPacket = HCI_EVENT_HEADER_SIZE;
            }
            else if (H4Packet->Type == (UCHAR) HciPacketAclData) {
                DoTrace(LEVEL_INFO, TFLAG_IO, (" [AclData] ---------- "));
                 _ReadContext->BytesToRead4FullPacket = HCI_ACL_HEADER_SIZE;
            }
            else {

                Status = STATUS_INVALID_PARAMETER;
                DoTrace(LEVEL_ERROR, TFLAG_IO, (" Unexpected PacketType %d", H4Packet->Type));
                NT_ASSERT(FALSE && L"Detected unknown packet type");
                goto OutOfSync;
            }

            _ReadContext->H4Packet.Type = H4Packet->Type;
            ReadSegmentStateSet(_ReadContext, GET_PKT_HEADER);
            break;

        case GET_PKT_HEADER:
            if (_ReadContext->H4Packet.Type == (UCHAR) HciPacketEvent) {
                if (_ReadContext->BytesReadNextSegment == 0 && BytesRemained) {
                    _ReadContext->H4Packet.Packet.Event.EventCode = *Buffer;
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [Event] Code 0x%x", _ReadContext->H4Packet.Packet.Event.EventCode));
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, 1);
                    _ReadContext->BytesToRead4FullPacket = 1;
                }

                if (_ReadContext->BytesReadNextSegment == 1 && BytesRemained) {
                    _ReadContext->H4Packet.Packet.Event.ParamsCount = *Buffer;
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [Event] ParamsCount 0x%x", _ReadContext->H4Packet.Packet.Event.ParamsCount));
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, 1);

                    if (_ReadContext->H4Packet.Packet.Event.ParamsCount == 0) {

                        PacketLen = HCI_EVENT_HEADER_LEN + _ReadContext->H4Packet.Packet.Event.ParamsCount;
                        DoTrace(LEVEL_INFO, TFLAG_DATA, (" [Event completed] PacketLen %d", PacketLen));
                        Status = ReadH4PacketComplete(FdoExtension,
                                                      _ReadContext->H4Packet.Type,
                                                      (PUCHAR) &_ReadContext->H4Packet.Packet.Event,
                                                      PacketLen);

                        ReadSegmentStateSet(_ReadContext, GET_PKT_TYPE);
                    }

                    else {
                        if (BytesRemained < _ReadContext->H4Packet.Packet.Event.ParamsCount) {
                          _ReadContext->BytesToRead4FullPacket =
                                _ReadContext->H4Packet.Packet.Event.ParamsCount - BytesRemained;
                        }

                        ReadSegmentStateSet(_ReadContext, GET_PKT_PAYLOAD);
                    }
                }
            }
            else {

                if (_ReadContext->BytesReadNextSegment == 0 && BytesRemained) {
                    _ReadContext->H4Packet.Packet.Raw[_ReadContext->BytesReadNextSegment] = *Buffer;
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [AclData] Header[0] 0x%x", _ReadContext->H4Packet.Packet.Raw[_ReadContext->BytesReadNextSegment]));
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, 1);
                    _ReadContext->BytesToRead4FullPacket = 3;
                }

                if (_ReadContext->BytesReadNextSegment == 1 && BytesRemained) {
                    _ReadContext->H4Packet.Packet.Raw[_ReadContext->BytesReadNextSegment] = *Buffer;
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [AclData] Header[1] 0x%x", _ReadContext->H4Packet.Packet.Raw[_ReadContext->BytesReadNextSegment]));
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, 1);
                    _ReadContext->BytesToRead4FullPacket = 2;
                }

                if (_ReadContext->BytesReadNextSegment == 2 && BytesRemained) {
                    _ReadContext->H4Packet.Packet.Raw[_ReadContext->BytesReadNextSegment] = *Buffer;
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [AclData] Header[2] 0x%x", _ReadContext->H4Packet.Packet.Raw[_ReadContext->BytesReadNextSegment]));
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, 1);
                    _ReadContext->BytesToRead4FullPacket = 1;
                }

                if (_ReadContext->BytesReadNextSegment == 3 && BytesRemained) {
                    _ReadContext->H4Packet.Packet.Raw[_ReadContext->BytesReadNextSegment] = *Buffer;
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [AclData] Header[3] 0x%x", _ReadContext->H4Packet.Packet.Raw[_ReadContext->BytesReadNextSegment]));
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, 1);

                    if (_ReadContext->H4Packet.Packet.AclData.DataLength > HCI_MAX_ACL_PAYLOAD_SIZE) {
                        DoTrace(LEVEL_ERROR, TFLAG_IO, (" Discarding oversized ACL DataLength %d (maximum %d)",
                                _ReadContext->H4Packet.Packet.AclData.DataLength,
                                HCI_MAX_ACL_PAYLOAD_SIZE));

                        ReadSegmentStateSet(_ReadContext, GET_PKT_DISCARD_PAYLOAD);
                        _ReadContext->BytesToRead4FullPacket =
                            _ReadContext->H4Packet.Packet.AclData.DataLength;
                    }
                    else {

                        if (BytesRemained < _ReadContext->H4Packet.Packet.AclData.DataLength) {
                            _ReadContext->BytesToRead4FullPacket =
                                _ReadContext->H4Packet.Packet.AclData.DataLength - BytesRemained;
                        }

                        ReadSegmentStateSet(_ReadContext, GET_PKT_PAYLOAD);
                    }
                }
            }
            break;

        case GET_PKT_PAYLOAD:
            if (_ReadContext->H4Packet.Type == (UCHAR) HciPacketEvent) {

                BytesToRead = _ReadContext->H4Packet.Packet.Event.ParamsCount - _ReadContext->BytesReadNextSegment;

                if (BytesRemained >= BytesToRead) {

                    RtlCopyMemory(&_ReadContext->H4Packet.Packet.Event.Params[_ReadContext->BytesReadNextSegment],
                                  Buffer,
                                  BytesToRead);
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [Event] Payload[%d + %d] = FULL",
                            _ReadContext->BytesReadNextSegment,
                            BytesToRead));
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, BytesToRead);

                    PacketLen = HCI_EVENT_HEADER_LEN + _ReadContext->H4Packet.Packet.Event.ParamsCount;
                    Status = ReadH4PacketComplete(FdoExtension,
                                                  _ReadContext->H4Packet.Type,
                                                  (PUCHAR) &_ReadContext->H4Packet.Packet.Event,
                                                  PacketLen);

                    ReadSegmentStateSet(_ReadContext, GET_PKT_TYPE);
                }
                else {

                    RtlCopyMemory(&_ReadContext->H4Packet.Packet.Event.Params[_ReadContext->BytesReadNextSegment],
                                  Buffer,
                                  BytesRemained);
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [Event] Payload[%d + %d] = Partial; %d to read",
                            _ReadContext->BytesReadNextSegment,
                            BytesRemained,
                            BytesToRead - BytesRemained));
                    _ReadContext->BytesReadNextSegment += BytesRemained;
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, BytesRemained);

                    _ReadContext->BytesToRead4FullPacket =
                        _ReadContext->H4Packet.Packet.Event.ParamsCount - _ReadContext->BytesReadNextSegment;
                }
            }
            else {

                if (_ReadContext->H4Packet.Packet.AclData.DataLength > HCI_MAX_ACL_PAYLOAD_SIZE) {
                    Status = STATUS_INVALID_PARAMETER;
                    DoTrace(LEVEL_ERROR, TFLAG_IO, (" Unexpected ACL DataLength %d > Presetted maximum size %d",
                            _ReadContext->H4Packet.Packet.AclData.DataLength,
                            HCI_MAX_ACL_PAYLOAD_SIZE));
                    NT_ASSERT(FALSE && L"Max ACL DataLength exceeded the presetted Max");
                    goto OutOfSync;
                }

                BytesToRead = _ReadContext->H4Packet.Packet.AclData.DataLength - _ReadContext->BytesReadNextSegment;

                if (BytesRemained >= BytesToRead) {

                    RtlCopyMemory(&_ReadContext->H4Packet.Packet.AclData.Data[_ReadContext->BytesReadNextSegment],
                                  Buffer,
                                  BytesToRead);
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [AclData] Payload[%d + %d] = FULL",
                            _ReadContext->BytesReadNextSegment,
                            BytesToRead));
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, BytesToRead);

                    PacketLen = HCI_ACLDATA_HEADER_LEN + _ReadContext->H4Packet.Packet.AclData.DataLength;
                    Status = ReadH4PacketComplete(FdoExtension,
                                                  _ReadContext->H4Packet.Type,
                                                  (PUCHAR) &_ReadContext->H4Packet.Packet.AclData,
                                                  PacketLen);

                    ReadSegmentStateSet(_ReadContext, GET_PKT_TYPE);
                }
                else {

                    RtlCopyMemory(&_ReadContext->H4Packet.Packet.AclData.Data[_ReadContext->BytesReadNextSegment],
                                  Buffer,
                                  BytesRemained);
                    DoTrace(LEVEL_INFO, TFLAG_IO, (" [AclData] Payload[%d + %d] = Partial; %d to read",
                            _ReadContext->BytesReadNextSegment,
                            BytesRemained,
                            BytesToRead - BytesRemained));
                    _ReadContext->BytesReadNextSegment += BytesRemained;
                    BUFFER_AND_SIZE_ADJUSTED(Buffer, BytesRemained, _ReadContext->BytesReadNextSegment, BytesRemained);

                    _ReadContext->BytesToRead4FullPacket =
                        _ReadContext->H4Packet.Packet.AclData.DataLength - _ReadContext->BytesReadNextSegment;
                }
            }
            break;

        case GET_PKT_DISCARD_PAYLOAD:
            if (BytesRemained < _ReadContext->BytesToRead4FullPacket) {
                BytesToRead = BytesRemained;
            }
            else {
                BytesToRead = _ReadContext->BytesToRead4FullPacket;
            }

            BUFFER_AND_SIZE_ADJUSTED(Buffer,
                                     BytesRemained,
                                     _ReadContext->BytesReadNextSegment,
                                     BytesToRead);
            _ReadContext->BytesToRead4FullPacket -= BytesToRead;

            if (_ReadContext->BytesToRead4FullPacket == 0) {

                ReadSegmentStateSet(_ReadContext, GET_PKT_TYPE);
            }
            break;

        default:
            DoTrace(LEVEL_ERROR, TFLAG_IO, (" Unknown ReadSegmentState"));
            break;
        }
    }

    return Status;

OutOfSync:

    DoTrace(LEVEL_ERROR, TFLAG_IO, (" Out-of-sync error detected in ProcessReadBuffer() %!STATUS!", Status));

    return Status;
}

VOID
ReadH4PacketCompletionRoutine(
    _In_  WDFREQUEST   _Request,
    _In_  WDFIOTARGET  _Target,
    _In_  PWDF_REQUEST_COMPLETION_PARAMS  _Params,
    _In_  WDFCONTEXT  _Context
    )

{
    NTSTATUS Status;
    PUART_READ_CONTEXT ReadContext;
    PFDO_EXTENSION FdoExtension;
    ULONG BytesRead;
    WDFMEMORY ReadMemory;
    PUCHAR  OutBuffer;
    size_t  OutBufferSize;
    READ_REQUEST_STATE PreviousState;

    UNREFERENCED_PARAMETER(_Request);
    UNREFERENCED_PARAMETER(_Target);

    Status = _Params->IoStatus.Status;
    BytesRead =  (ULONG) _Params->Parameters.Read.Length;

    ReadContext = (PUART_READ_CONTEXT) _Context;
    ReadContext->Status = Status;

    PreviousState = InterlockedCompareExchange((PLONG)&ReadContext->RequestState,
                                               REQUEST_COMPLETE,
                                               REQUEST_SENT);

    DoTrace(LEVEL_WARNING, TFLAG_DATA, ("+ReadH4PacketCompletionRoutine %!STATUS! %d BytesRead %S)",
            Status, BytesRead, PreviousState == REQUEST_PENDING ? L"Async" : L"*Sync*"));

    FdoExtension = (PFDO_EXTENSION) ReadContext->FdoExtension;

    if (NT_SUCCESS(Status) || Status == STATUS_IO_TIMEOUT || Status == STATUS_TIMEOUT) {

    }
    else  {
        DoTrace(LEVEL_ERROR, TFLAG_IO, (" ReadH4PacketCompletionRoutine failed %!STATUS!", Status));
        if (Status == STATUS_CANCELLED) {

        }

        goto Exit;
    }

    ReadMemory = _Params->Parameters.Read.Buffer;
    OutBuffer = (PUCHAR) WdfMemoryGetBuffer(ReadMemory, &OutBufferSize);
    NT_ASSERT(OutBufferSize >= BytesRead);
    DoTrace(LEVEL_INFO, TFLAG_IO, (" ReadH4PacketCompletionRoutine %d BytesRead pBuffer %p", BytesRead, OutBuffer));

    if (OutBuffer && BytesRead)
    {

        Status = ReadH4PacketReassemble(ReadContext,
                                        BytesRead,
                                        OutBuffer);

        if (!NT_SUCCESS(Status))
        {
            FdoExtension->OutOfSyncErrorCount++;
            DoTrace(LEVEL_ERROR, TFLAG_IO, (" ====> [%d] 0x%x  <=====",
                    FdoExtension->OutOfSyncErrorCount,
                    *OutBuffer));
            NT_ASSERT(NT_SUCCESS(Status) && L"Encountered an out-of-sync condition!");

            ReadSegmentStateSet(ReadContext, GET_PKT_TYPE);

            if (FdoExtension->HardwareErrorDetected && FdoExtension->OutOfSyncErrorCount > MAX_HARDWARE_ERROR_COUNT)
            {

#ifdef REPORT_HARDWARE_ERROR
                WDFREQUEST Request;

                DoTrace(LEVEL_ERROR, TFLAG_IO, (" ++++ Report a hardware error; OutOfSyncCount %d",  FdoExtension->OutOfSyncErrorCount));

                WdfSpinLockAcquire(FdoExtension->QueueAccessLock);

                    Status = WdfIoQueueRetrieveNextRequest(FdoExtension->ReadEventQueue, &Request);

                    if (Status == STATUS_NO_MORE_ENTRIES)
                    {
                        Status = WdfIoQueueRetrieveNextRequest(FdoExtension->ReadDataQueue, &Request);
                    }
                WdfSpinLockRelease(FdoExtension->QueueAccessLock);

                if (NT_SUCCESS(Status))
                {
                    DoTrace(LEVEL_ERROR, TFLAG_IO, (" Complete a request with STATUS_DEVICE_DATA_ERROR"));
                    WdfRequestComplete(Request, STATUS_DEVICE_DATA_ERROR);
                }
#endif
                Status = STATUS_DEVICE_DATA_ERROR;

                goto Exit;

            }
            else
            {

                DoTrace(LEVEL_ERROR, TFLAG_IO, (" Detect out-of-sync error but read ahead..."));

                FdoExtension->HardwareErrorDetected = FALSE;

                goto ReadNext;
            }
        }
    }
    else
    {
        NT_ASSERT(Status == STATUS_TIMEOUT);
    }

ReadNext:

    if (PreviousState == REQUEST_PENDING)
    {
        ULONG BytesToRead;

        if (ReadContext->ReadSegmentState == GET_PKT_TYPE) {
            BytesToRead = INITIAL_H4_READ_SIZE;
        }
        else if (ReadContext->BytesToRead4FullPacket == 0 ||
                 ReadContext->BytesToRead4FullPacket > sizeof(FdoExtension->ReadBuffer)) {
            BytesToRead = sizeof(FdoExtension->ReadBuffer);
        }
        else {
            BytesToRead = ReadContext->BytesToRead4FullPacket;
        }

        DoTrace(LEVEL_INFO, TFLAG_IO, (" ReadH4Packet(Read Buffer Size %d bytes)", BytesToRead));

        ReadH4Packet(ReadContext,
                     FdoExtension->ReadRequest,
                     FdoExtension->ReadMemory,
                     FdoExtension->ReadBuffer,
                     sizeof(FdoExtension->ReadBuffer),
                     BytesToRead);
    }
    else
    {

    }

    DoTrace(LEVEL_INFO, TFLAG_IO, ("-CR_ReadReadIO (fall though)"));

    return;

Exit:

    if (!NT_SUCCESS(Status))
    {
        NT_ASSERT(Status == STATUS_CANCELLED);
        FdoExtension->ReadPumpRunning = FALSE;
        DoTrace(LEVEL_WARNING, TFLAG_IO, (" Pump has stopped!"));
    }

    DoTrace(LEVEL_INFO, TFLAG_IO, ("-CR_ReadReadIO (error)"));
}

NTSTATUS
ReadH4Packet(
    _In_  PUART_READ_CONTEXT _ReadContext,
    _In_  WDFREQUEST         _WdfRequest,
    _In_  WDFMEMORY          _WdfMemory,
    _Pre_notnull_ _Pre_writable_byte_size_ (_BufferCapacity) PVOID _Buffer,
    _In_  ULONG              _BufferCapacity,
    _In_  ULONG              _BufferLen
    )

{
    PFDO_EXTENSION   FdoExtension;
    WDF_REQUEST_REUSE_PARAMS RequestReuseParams;
    NTSTATUS Status;

    DoTrace(LEVEL_INFO, TFLAG_IO, ("+ReadH4Packet"));

    FdoExtension = _ReadContext->FdoExtension;

    if (0 == _BufferLen || _BufferLen > _BufferCapacity) {
        DoTrace(LEVEL_ERROR, TFLAG_IO, (" ReadH4Packet: invalid length %d for buffer capacity %d",
                _BufferLen,
                _BufferCapacity));
        Status = STATUS_INVALID_PARAMETER;
        goto Done;
    }

    while (TRUE) {

        DoTrace(LEVEL_INFO, TFLAG_IO, (" ReadH4Packet - <start>"));
        NT_ASSERT(_ReadContext->RequestState != REQUEST_SENT);

        if (!IsDeviceInitialized(FdoExtension)) {
            Status = STATUS_DEVICE_NOT_READY;
            DoTrace(LEVEL_ERROR, TFLAG_IO, (" ReadH4Packet: cannot attach IO %!STATUS!", Status));
            goto Done;
        }

        WDF_REQUEST_REUSE_PARAMS_INIT(&RequestReuseParams, WDF_REQUEST_REUSE_NO_FLAGS, STATUS_SUCCESS);
        Status = WdfRequestReuse(_WdfRequest, &RequestReuseParams);
        if (!NT_SUCCESS(Status)) {
            DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfRequestReuse failed %!STATUS!", Status));
            goto Done;
        }

        Status = WdfMemoryAssignBuffer(_WdfMemory, _Buffer, _BufferLen);
        if (!NT_SUCCESS(Status)) {
            DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfMemoryAssignBuffer failed %!STATUS!", Status));
            goto Done;
        }

        Status = WdfIoTargetFormatRequestForRead(FdoExtension->IoTargetSerial,
                                                 _WdfRequest,
                                                 _WdfMemory,
                                                 NULL, NULL);

        if (!NT_SUCCESS(Status)) {
            DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfIoTargetFormatRequestForRead failed %!STATUS!", Status));
            goto Done;
        }

        WdfRequestSetCompletionRoutine(_WdfRequest,
                                       ReadH4PacketCompletionRoutine,
                                       _ReadContext);

        InterlockedExchange((PLONG)&_ReadContext->RequestState, REQUEST_SENT);

        if (FALSE == WdfRequestSend(_WdfRequest,
                                    FdoExtension->IoTargetSerial,
                                    WDF_NO_SEND_OPTIONS))
        {
            Status = WdfRequestGetStatus(_WdfRequest);
            DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfRequestSend failed %!STATUS!", Status));

            goto Done;
        }
        else
        {
            READ_REQUEST_STATE PreviousState;

            PreviousState = InterlockedCompareExchange((PLONG) &_ReadContext->RequestState,
                                                       REQUEST_PENDING,
                                                       REQUEST_SENT);

            DoTrace(LEVEL_WARNING, TFLAG_IO, (" WdfRequestSend ReqState: %d -> %d",
                    PreviousState, _ReadContext->RequestState));

            if (PreviousState == REQUEST_SENT)
            {

                Status = STATUS_PENDING;
                break;
            }
            else
            {
                Status = FdoExtension->ReadContext.Status;
                if (NT_SUCCESS(Status))
                {

                }
                else
                {

                    break;
                }
            }
        }
    }

Done:

    if (!NT_SUCCESS(Status))
    {
        NT_ASSERT(Status == STATUS_CANCELLED);
        FdoExtension->ReadPumpRunning = FALSE;
    }

    DoTrace(LEVEL_INFO, TFLAG_IO, ("-ReadH4Packet %!STATUS!", Status));

    return Status;
}

__inline
PHCI_PACKET_ENTRY
HLP_CreatePacketEntry(
    _In_ ULONG  _PacketLength,
    _In_reads_bytes_(_PacketLength) PUCHAR _Packet
    )
{
    PHCI_PACKET_ENTRY  PacketEntry = NULL;

    PacketEntry = (PHCI_PACKET_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(HCI_PACKET_ENTRY) + _PacketLength, POOLTAG_BTHSERIALHCIBUSSAMPLE);
    if (PacketEntry != NULL) {
        InitializeListHead(&PacketEntry->DataEntry);
        RtlCopyMemory(PacketEntry->Packet, _Packet, _PacketLength);
        PacketEntry->PacketLen = _PacketLength;
    }

    return PacketEntry;
}

static VOID
HLP_FreePacketEntryLocked(
    _In_ PFDO_EXTENSION _FdoExtension,
    _In_ PHCI_PACKET_ENTRY _PacketEntry
    )
{
    ULONG allocationBytes =
        (ULONG)sizeof(HCI_PACKET_ENTRY) + _PacketEntry->PacketLen;

    NT_ASSERT(_FdoExtension->PrefetchedPacketBytes >= allocationBytes);
    ExFreePool(_PacketEntry);
    _FdoExtension->PrefetchedPacketBytes -= allocationBytes;
}

static VOID
HLP_PurgePacketList(
    _In_ PFDO_EXTENSION _FdoExtension,
    _Inout_ PLIST_ENTRY _ListHead,
    _Inout_ PLONG _ListCount
    )
{
    for (;;) {
        WdfSpinLockAcquire(_FdoExtension->QueueAccessLock);
        if (IsListEmpty(_ListHead)) {
            NT_ASSERT(*_ListCount == 0);
            WdfSpinLockRelease(_FdoExtension->QueueAccessLock);
            break;
        }
        HLP_FreePacketEntryLocked(
            _FdoExtension,
            (PHCI_PACKET_ENTRY)RemoveHeadList(_ListHead));
        InterlockedDecrement(_ListCount);
        WdfSpinLockRelease(_FdoExtension->QueueAccessLock);
    }
}

VOID
ReadPacketListsPurge(
    _In_ PFDO_EXTENSION _FdoExtension
    )
{
    if (_FdoExtension->ReadEventQueue != NULL) {
        HLP_PurgePacketList(
            _FdoExtension,
            &_FdoExtension->ReadEventList,
            &_FdoExtension->EventListCount);
    }
    if (_FdoExtension->ReadDataQueue != NULL) {
        HLP_PurgePacketList(
            _FdoExtension,
            &_FdoExtension->ReadDataList,
            &_FdoExtension->DataListCount);
    }
}

NTSTATUS
ReadRequestComplete(
    _In_ PFDO_EXTENSION _FdoExtension,
    _In_ UCHAR          _PacketType,
    _In_ ULONG          _PacketLength,
    _In_reads_bytes_opt_(_PacketLength) PUCHAR _Packet,
    _Inout_ WDFQUEUE    _Queue,
    _Inout_ PLONG       _QueueCount,
    _Inout_ PLIST_ENTRY _ListHead,
    _Inout_ PLONG       _ListCount
    )

{
    WDFREQUEST  Request = NULL;
    NTSTATUS    Status = STATUS_SUCCESS;
    PHCI_PACKET_ENTRY  PacketEntry = NULL;
    WDFMEMORY ReqOutMemory;
    size_t BufferSize = 0, BytesToReturn;
    PBTHX_HCI_READ_WRITE_CONTEXT HCIContext;
    BOOLEAN CompleteRequest = FALSE;

    DoTrace(LEVEL_INFO, TFLAG_IO, ("+ReadRequestComplete"));

    WdfSpinLockAcquire(_FdoExtension->QueueAccessLock);

    if (_Packet) {

        Status = WdfIoQueueRetrieveNextRequest(_Queue, &Request);
        if (Status == STATUS_SUCCESS) {

            InterlockedDecrement(_QueueCount);
            DoTrace(LEVEL_INFO, TFLAG_IO, (" (C2) Complete a request %p, _Packet %p, _PacketLength %d",
                Request, _Packet, _PacketLength));

            CompleteRequest = TRUE;

            NT_ASSERT(IsListEmpty(_ListHead));
        }
        else if (Status == STATUS_NO_MORE_ENTRIES) {

            ULONG allocationBytes;

            if ((_PacketLength == 0) ||
                (_PacketLength > MAX_HCI_ACLDATA_SIZE)) {
                Status = STATUS_INVALID_BUFFER_SIZE;
                goto Unlock;
            }
            allocationBytes = (ULONG)sizeof(HCI_PACKET_ENTRY) + _PacketLength;
            if (((ULONG)*_ListCount >= HCI_PREFETCH_MAX_ENTRIES_PER_LIST) ||
                (_FdoExtension->PrefetchedPacketBytes >
                    HCI_PREFETCH_MAX_ALLOCATION_BYTES) ||
                (allocationBytes > HCI_PREFETCH_MAX_ALLOCATION_BYTES -
                    _FdoExtension->PrefetchedPacketBytes)) {
                Status = STATUS_QUOTA_EXCEEDED;
                DoTrace(LEVEL_WARNING, TFLAG_IO,
                    ("HCI prefetch limit reached; dropping complete packet"));
                goto Unlock;
            }
            PacketEntry = HLP_CreatePacketEntry(_PacketLength, _Packet);
            if (PacketEntry == NULL) {

                Status = STATUS_INSUFFICIENT_RESOURCES;
                DoTrace(LEVEL_ERROR, TFLAG_IO, (" (C0/Error) Could not allocate HCI_PACKET_ENTRY %!STATUS!", Status));

            }
            else {

                InsertTailList(_ListHead, &PacketEntry->DataEntry);
                InterlockedIncrement(_ListCount);
                _FdoExtension->PrefetchedPacketBytes += allocationBytes;
                PacketEntry = NULL;
                Status = STATUS_SUCCESS;
                DoTrace(LEVEL_INFO, TFLAG_IO, (" (C0) Queuing packet with list count %d", *_ListCount));
            }
        }
    }
    else {
        if (!IsListEmpty(_ListHead)) {
            Status = WdfIoQueueRetrieveNextRequest(_Queue, &Request);
            if (Status == STATUS_SUCCESS) {

                InterlockedDecrement(_QueueCount);

                PacketEntry = (PHCI_PACKET_ENTRY) RemoveHeadList(_ListHead);
                _Packet = PacketEntry->Packet;
                _PacketLength = PacketEntry->PacketLen;
                InterlockedDecrement(_ListCount);

                DoTrace(LEVEL_INFO, TFLAG_IO, (" (C2) Complete a request %p, _Packet %p, _PacketLength %d",
                    Request, _Packet, _PacketLength));

                CompleteRequest = TRUE;
            }
            else {
                NT_ASSERT(FALSE && L"Failed to retrieve a request just queued!");
            }
        }
        else {

            Status = STATUS_PENDING;
            DoTrace(LEVEL_INFO, TFLAG_IO, (" (C1) Read request is queued"));
        }
   }

Unlock:
    WdfSpinLockRelease(_FdoExtension->QueueAccessLock);

    if (!CompleteRequest) {
        goto Done;
    }

    Status = WdfRequestRetrieveOutputMemory(Request, &ReqOutMemory);
    if (Status != STATUS_SUCCESS) {
        DoTrace(LEVEL_ERROR, TFLAG_IO, (" Could not retrieve output buffer"));
        WdfRequestCompleteWithInformation(Request, Status, (ULONG_PTR)0);
        goto Done;
    }

    HCIContext = WdfMemoryGetBuffer(ReqOutMemory, &BufferSize);
    BytesToReturn = FIELD_OFFSET(BTHX_HCI_READ_WRITE_CONTEXT, Data) + _PacketLength;

    NT_ASSERT(BytesToReturn <= BufferSize);

    HCIContext->Type    = _PacketType;
    HCIContext->DataLen = _PacketLength;
    if (BytesToReturn <= BufferSize) {
        RtlCopyMemory(&HCIContext->Data, _Packet, _PacketLength);
    }
    else {
        Status = STATUS_BUFFER_TOO_SMALL;
        BytesToReturn = 0;
    }

    HCIContextValidate(HCIContext->Type == (UCHAR) HciPacketEvent ?
                       _FdoExtension->CntEventCompleted : _FdoExtension->CntReadDataCompleted,
                       HCIContext);

    if (HCIContext->Type == (UCHAR) HciPacketEvent) {
        InterlockedIncrement(&_FdoExtension->CntEventCompleted);
        DoTrace(LEVEL_INFO, TFLAG_DATA, (" [%d] HciPacketEvent completing %!STATUS!, %d BytesToReturn",
                _FdoExtension->CntEventCompleted, Status, (ULONG) BytesToReturn));
    }
    else if (HCIContext->Type == (UCHAR) HciPacketAclData) {
        InterlockedIncrement(&_FdoExtension->CntReadDataCompleted);
        DoTrace(LEVEL_INFO, TFLAG_DATA, (" [%d] HciPacketAclData completing %!STATUS!, %d BytesToReturn",
                _FdoExtension->CntReadDataCompleted, Status, (ULONG) BytesToReturn));
    }

    DoTrace(LEVEL_INFO, TFLAG_IO, (" Completing Request(%p) %!STATUS!, %d BytesToReturn",
            Request, Status, (ULONG) BytesToReturn));

    WdfRequestCompleteWithInformation(Request, Status, BytesToReturn);

Done:

    if (PacketEntry != NULL) {
        WdfSpinLockAcquire(_FdoExtension->QueueAccessLock);
        HLP_FreePacketEntryLocked(_FdoExtension, PacketEntry);
        WdfSpinLockRelease(_FdoExtension->QueueAccessLock);
    }

    DoTrace(LEVEL_INFO, TFLAG_IO, ("-ReadRequestComplete: %!STATUS!", Status));

    return Status;
}

VOID
ReadResourcesReset(
    _In_ WDFDEVICE Device
    )
{
    PFDO_EXTENSION extension = FdoGetExtension(Device);

    extension->ReadPumpRunning = FALSE;

    if (extension->ReadEventQueue != NULL) {
        WdfIoQueuePurgeSynchronously(extension->ReadEventQueue);
    }
    if (extension->ReadDataQueue != NULL) {
        WdfIoQueuePurgeSynchronously(extension->ReadDataQueue);
    }

    ReadPacketListsPurge(extension);

    extension->EventQueueCount = 0;
    extension->DataQueueCount = 0;
    extension->HardwareErrorDetected = FALSE;
    extension->OutOfSyncErrorCount = 0;

    RtlZeroMemory(
        &extension->ReadContext,
        sizeof(extension->ReadContext));
    extension->ReadContext.FdoExtension = extension;
    extension->ReadContext.RequestState = REQUEST_COMPLETE;
    ReadSegmentStateSet(&extension->ReadContext, GET_PKT_TYPE);
    RtlZeroMemory(extension->ReadBuffer, sizeof(extension->ReadBuffer));

    if (extension->ReadEventQueue != NULL) {
        WdfIoQueueStart(extension->ReadEventQueue);
    }
    if (extension->ReadDataQueue != NULL) {
        WdfIoQueueStart(extension->ReadDataQueue);
    }
}

VOID
ReadResourcesFree(
    _In_  WDFDEVICE _Device
)

{
    PFDO_EXTENSION     FdoExtension;

    DoTrace(LEVEL_INFO, TFLAG_IO,("+ReadResourcesFree"));

    FdoExtension = FdoGetExtension(_Device);

    ReadPacketListsPurge(FdoExtension);

    if (FdoExtension->ReadRequest)
    {
        WdfObjectDelete(FdoExtension->ReadRequest);
        FdoExtension->ReadRequest = NULL;
    }

    if (FdoExtension->ReadMemory)
    {
        WdfObjectDelete(FdoExtension->ReadMemory);
        FdoExtension->ReadMemory = NULL;
    }

    if (FdoExtension->ReadEventQueue)
    {
        WdfObjectDelete(FdoExtension->ReadEventQueue);
        FdoExtension->ReadEventQueue = NULL;
    }

    if (FdoExtension->ReadDataQueue)
    {
        WdfObjectDelete(FdoExtension->ReadDataQueue);
        FdoExtension->ReadDataQueue = NULL;
    }
}

NTSTATUS
ReadResourcesAllocate(
    _In_  WDFDEVICE _Device
)

{
    NTSTATUS  Status;
    PFDO_EXTENSION   FdoExtension;
    WDF_IO_QUEUE_CONFIG QueueConfig;
    WDF_OBJECT_ATTRIBUTES ObjAttributes;

    DoTrace(LEVEL_INFO, TFLAG_IO,("+ReadResourcesAllocate"));

    FdoExtension = FdoGetExtension(_Device);

    InitializeListHead(&FdoExtension->ReadEventList);
    InitializeListHead(&FdoExtension->ReadDataList);
    FdoExtension->PrefetchedPacketBytes = 0;

    WDF_IO_QUEUE_CONFIG_INIT(&QueueConfig,
                             WdfIoQueueDispatchManual);

    Status = WdfIoQueueCreate(_Device,
                              &QueueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &FdoExtension->ReadEventQueue);

    if (!NT_SUCCESS(Status))
    {
        DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfIoQueueCreate(Event) %!STATUS!", Status));
        goto Done;
    }

    InitializeListHead(&FdoExtension->ReadEventList);

    FdoExtension->EventListCount = 0;
    FdoExtension->EventQueueCount  = 0;

    Status = WdfIoQueueCreate(_Device,
                              &QueueConfig,
                              WDF_NO_OBJECT_ATTRIBUTES,
                              &FdoExtension->ReadDataQueue);

    if (!NT_SUCCESS(Status))
    {
        DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfIoQueueCreate(Data) %!STATUS!", Status));
        goto Done;
    }

    InitializeListHead(&FdoExtension->ReadDataList);

    FdoExtension->DataListCount = 0;
    FdoExtension->DataQueueCount = 0;

    FdoExtension->CntCommandReq         = 0;
    FdoExtension->CntCommandCompleted   = 0;

    FdoExtension->CntEventReq           = 0;
    FdoExtension->CntEventCompleted     = 0;

    FdoExtension->CntWriteDataReq       = 0;
    FdoExtension->CntWriteDataCompleted = 0;

    FdoExtension->CntReadDataReq        = 0;
    FdoExtension->CntReadDataCompleted  = 0;

    WDF_OBJECT_ATTRIBUTES_INIT(&ObjAttributes);
    ObjAttributes.ParentObject = _Device;

    Status = WdfRequestCreate(&ObjAttributes,
                              FdoExtension->IoTargetSerial,
                              &FdoExtension->ReadRequest);

    if (!NT_SUCCESS(Status))
    {
        DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfRequestCreate(ReadRequest) failed %!STATUS!", Status));
        goto Done;
    }

    RtlZeroMemory(&FdoExtension->ReadContext, sizeof(UART_READ_CONTEXT));
    FdoExtension->ReadContext.FdoExtension = FdoExtension;
    ReadSegmentStateSet(&FdoExtension->ReadContext, GET_PKT_TYPE);

    Status = WdfMemoryCreatePreallocated(&ObjAttributes,
                                         &FdoExtension->ReadBuffer,
                                         sizeof(FdoExtension->ReadBuffer),
                                         &FdoExtension->ReadMemory);

    if (!NT_SUCCESS(Status))
    {
        DoTrace(LEVEL_ERROR, TFLAG_IO, (" WdfMemoryCreatePreallocated(ReadMemory) failed %!STATUS!", Status));
        goto Done;
    }

Done:

    DoTrace(LEVEL_INFO, TFLAG_IO,("-ReadResourcesAllocate %!STATUS!", Status));
    if (!NT_SUCCESS(Status))
    {
        ReadResourcesFree(_Device);
    }

    return Status;
}
