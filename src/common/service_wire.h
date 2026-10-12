/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"
#define AP6256_SERVICE_MAX 4u
#define AP6256_SERVICE_NAME_MAX 200u
#define AP6256_SERVICE_INFO_MAX 768u
#define AP6256_SERVICE_REQUEST_MAX 32u
#define AP6256_SERVICE_RESPONSE_MAX 4096u
typedef struct _AP6256_SERVICE_ENTRY {
    UCHAR Name[AP6256_SERVICE_NAME_MAX], Hash[6], Info[AP6256_SERVICE_INFO_MAX];
    ULONG NameLength, InfoLength;
    UINT32 AdvertisementId;
    UINT16 ConfigurationMethods, Update;
    UCHAR Status, Transaction;
    BOOLEAN QueryInformation, HaveInformation;
} AP6256_SERVICE_ENTRY;
BOOLEAN Ap6256ServiceNameMatches(const UCHAR* Name, ULONG Length,
    const UCHAR* Pattern, ULONG PatternLength);
NTSTATUS Ap6256ServiceEncodeQuery(const AP6256_SERVICE_ENTRY* Entry,
    UCHAR* Buffer, ULONG Capacity, ULONG* Length);
NTSTATUS Ap6256ServiceDecodeResponse(const UCHAR* Buffer, ULONG Length,
    const AP6256_SERVICE_ENTRY* Query, AP6256_SERVICE_ENTRY* Entries, ULONG* Count);
NTSTATUS Ap6256ServiceDecodeAdvertisements(const UCHAR* Attributes, ULONG Length,
    AP6256_SERVICE_ENTRY* Entries, ULONG* Count);
