/*
 * SPDX-License-Identifier: MS-PL
 * Copyright (c) Microsoft Corporation All Rights Reserved
 * See bt/LICENSE-MS-PL.txt for the license text.
 */

#ifndef __IO_H__
#define __IO_H__

#define MIN_HCI_CMD_SIZE          (3)
#define MAX_HCI_CMD_SIZE        (258)

#define MIN_HCI_EVENT_SIZE        (2)
#define HCI_EVENT_HEADER_SIZE     (2)
#define MAX_HCI_EVENT_SIZE      (257)

#define HCI_ACL_HEADER_SIZE         (4)
#define HCI_MAX_ACL_PAYLOAD_SIZE    (1021)
#define MIN_HCI_ACLDATA_SIZE         HCI_ACL_HEADER_SIZE
#define MAX_HCI_ACLDATA_SIZE        (HCI_ACL_HEADER_SIZE + HCI_MAX_ACL_PAYLOAD_SIZE)

#define INITIAL_H4_READ_SIZE        (1+HCI_EVENT_HEADER_SIZE)
#define MAX_H4_HCI_PACKET_SIZE      (1+HCI_ACL_HEADER_SIZE + HCI_MAX_ACL_PAYLOAD_SIZE)

#define BUFFER_AND_SIZE_ADJUSTED(Buffer, Size, SegmentCount, Increment) {Buffer += Increment; Size -= Increment; SegmentCount += Increment;}

#define POOLTAG_BTHSERIALHCIBUSSAMPLE 'htbw'

#define HCI_PREFETCH_MAX_ENTRIES_PER_LIST 64UL
#define HCI_PREFETCH_MAX_ALLOCATION_BYTES (64UL * 1024UL)

#include <PSHPACK1.H>

typedef struct _HCI_COMMAND_PACKET {
    UINT16  Opcode;
    UCHAR   ParamsCount;
    UCHAR   Params[1];
} HCI_COMMAND_PACKET, *PHCI_COMMAND_PACKET;
#define HCI_COMMAND_HEADER_LEN  FIELD_OFFSET(HCI_COMMAND_PACKET, Params)

typedef struct _HCI_EVENT_PACKET {
    UCHAR   EventCode;
    UCHAR   ParamsCount;
    UCHAR   Params[1];
} HCI_EVENT_PACKET, *PHCI_EVENT_PACKET;
#define HCI_EVENT_HEADER_LEN  FIELD_OFFSET(HCI_EVENT_PACKET, Params)

typedef struct _HCI_ACLDATA_PACKET {
    UINT16    ConnectionHandle : 12;
    UINT16    PBFlag : 2;
    UINT16    BCFlag : 2;
    UINT16    DataLength;
    UCHAR     Data[1];
} HCI_ACLDATA_PACKET, *PHCI_ACLDATA_PACKET;
#define HCI_ACLDATA_HEADER_LEN  FIELD_OFFSET(HCI_ACLDATA_PACKET, Data)

typedef struct _H4_PACKET {
    UCHAR  Type;
    union {
        HCI_COMMAND_PACKET Command;
        HCI_EVENT_PACKET   Event;
        HCI_ACLDATA_PACKET AclData;
        UCHAR Raw[MAX_HCI_ACLDATA_SIZE];
    } Packet;
} H4_PACKET, *PH4_PACKET;

typedef struct _UART_COMMAND_PACKET {
    UCHAR   Type;
    HCI_COMMAND_PACKET Packet;
} UART_COMMAND_PACKET, *PUART_COMMAND_PACKET;

typedef struct _UART_EVENT_PACKET {
    UCHAR   Type;
    HCI_EVENT_PACKET Packet;
} UART_EVENT_PACKET, *PUART_EVENT_PACKET;

typedef struct _UART_ACLDATA_PACKET {
    UCHAR   Type;
    HCI_ACLDATA_PACKET Packet;
} UART_ACLDATA_PACKET, *PUART_ACLDATA_PACKET;

#include <POPPACK.H>

typedef struct _FDO_EXTENSION *PFDO_EXTENSION;

#define REQUEST_PATH_NONE           0x00000000
#define REQUEST_PATH_CANCELLATION   0x00000001
#define REQUEST_PATH_COMPLETION     0x00000002

typedef struct _UART_WRITE_CONTEXT {

    PFDO_EXTENSION   FdoExtension;

    WDFREQUEST  RequestFromBthport;

    LONG    RequestCompletePath;

    WDFREQUEST  RequestToUART;

    WDFMEMORY   Memory;

    PBTHX_HCI_READ_WRITE_CONTEXT HCIContext;

    PVOID HCIPacket;

    ULONG HCIPacketLen;

    BOOLEAN WakeReferenceHeld;

} UART_WRITE_CONTEXT, *PUART_WRITE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(UART_WRITE_CONTEXT, GetWriteRequestContext)

typedef enum {
    GET_PKT_TYPE            = 1,
    GET_PKT_HEADER          = 2,
    GET_PKT_PAYLOAD         = 3,
    GET_PKT_DISCARD_PAYLOAD = 4
} UART_READ_STATE;

typedef struct _HCI_PACKET_ENTRY {
    LIST_ENTRY  DataEntry;
    ULONG       PacketLen;
    _Field_size_bytes_(PacketLen) UCHAR Packet[1];
} HCI_PACKET_ENTRY, *PHCI_PACKET_ENTRY;

typedef enum _READ_REQUEST_STATE {
    REQUEST_SENT     = 1,
    REQUEST_PENDING  = 2,
    REQUEST_COMPLETE = 3
} READ_REQUEST_STATE;

typedef struct _UART_READ_CONTEXT {

    NTSTATUS Status;

    PFDO_EXTENSION FdoExtension;

    READ_REQUEST_STATE  RequestState;

    UART_READ_STATE  ReadSegmentState;

    ULONG BytesReadNextSegment;

    ULONG BytesToRead4FullPacket;

    H4_PACKET H4Packet;

} UART_READ_CONTEXT, *PUART_READ_CONTEXT;

#define MAX_HARDWARE_ERROR_COUNT 0

#define MAX_WRITE_TIMEOUT_IN_SEC  1
#define MAX_READ_TIMEOUT_IN_SEC   1

#endif
