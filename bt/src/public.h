/*
 * SPDX-License-Identifier: MS-PL
 * Copyright (c) Microsoft Corporation All Rights Reserved
 * See bt/LICENSE-MS-PL.txt for the license text.
 */

#ifndef __PUBLIC_H
#define __PUBLIC_H

#ifdef DEFINE_GUID

DEFINE_GUID(GUID_DEVINTERFACE_BLUETOOTH_RADIO_ONOFF_VENDOR_SPECIFIC,
        0x98899865, 0x63de, 0x427b, 0x84, 0x77, 0x6c, 0xb7, 0x4d, 0x9f, 0xf2, 0xa7);

#endif

#define FILE_DEVICE_BUSENUM       FILE_DEVICE_BUS_EXTENDER
#define BUSENUM_IOCTL(id, access) CTL_CODE(FILE_DEVICE_BUSENUM, \
                                           (id),                \
                                           METHOD_BUFFERED,     \
                                           access)

#define IOCTL_BUSENUM_SET_RADIO_ONOFF_VENDOR_SPECFIC        BUSENUM_IOCTL(0x1, FILE_WRITE_DATA)

#endif
