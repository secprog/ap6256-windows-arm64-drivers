/*
 * SPDX-License-Identifier: MS-PL
 * Copyright (c) Microsoft Corporation All Rights Reserved
 * See bt/LICENSE-MS-PL.txt for the license text.
 */

#ifndef __DEVICE_H__
#define __DEVICE_H__

#pragma warning(disable:4214)

#define BT_PDO_HARDWARE_IDS L"AP6256BT\\UART_H4"
#define BT_PDO_COMPATIBLE_IDS L"MS_BTHX_BTHMINI"
#define BT_PDO_DEVICE_LOCATION L"AP6256 BCM4345C0 Bluetooth UART"

#define MIN_HCI_CMD_SIZE          (3)
#define MAX_HCI_CMD_SIZE        (258)

#define MIN_HCI_EVENT_SIZE        (2)
#define MAX_HCI_EVENT_SIZE      (257)

#define HCI_ACL_HEADER_SIZE         (4)
#define HCI_MAX_ACL_PAYLOAD_SIZE    (1021)
#define MIN_HCI_ACLDATA_SIZE         HCI_ACL_HEADER_SIZE
#define MAX_HCI_ACLDATA_SIZE        (HCI_ACL_HEADER_SIZE + HCI_MAX_ACL_PAYLOAD_SIZE)

#endif
