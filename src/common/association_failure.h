/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#define AP6256_ASSOC_FAILURE_MAX 2048u

typedef struct _AP6256_ASSOC_FAILURE {
    LONG ConnectGeneration;
    UINT32 FirmwareGeneration;
    ULONG Length;
    BOOLEAN ReAssociation;
    UCHAR Peer[6];
    UCHAR Response[AP6256_ASSOC_FAILURE_MAX];
} AP6256_ASSOC_FAILURE;
