/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "host_cipher_frame.h"

typedef struct _AP6256_HC_RSN {
    const AP6256_HC_U8 *Pairwise, *Akms, *Pmkids;
    AP6256_HC_U32 PairwiseCount, AkmCount, PmkidCount;
    AP6256_HC_U32 Group, Management;
    AP6256_HC_U16 Capabilities;
} AP6256_HC_RSN;

int Ap6256HostCipherRsnRead(const AP6256_HC_U8* Ies, AP6256_HC_U32 Length,
    AP6256_HC_RSN* Rsn);
int Ap6256HostCipherRsnMatch(const AP6256_HC_RSN* Rsn,
    AP6256_HC_U32 Akm, AP6256_HC_U32 Mfp, int Station);
int Ap6256HostCipherRsnPmkid(const AP6256_HC_RSN* Rsn,
    const AP6256_HC_U8 Pmkid[16], int Station);

int Ap6256Wpa3EnterpriseRsnMatch(const AP6256_HC_RSN* Rsn, int Station);
