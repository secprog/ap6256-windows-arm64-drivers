/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_cipher_rsn.h"
typedef AP6256_HC_U8 U8;
typedef AP6256_HC_U32 U32;
static U32 HcRsn16(const U8* p) {return (U32)p[0] | ((U32)p[1] << 8);}
static U32 HcRsn32(const U8* p) {return HcRsn16(p) | (HcRsn16(p + 2) << 16);}
static int HcRsnSuite(const U8* p, U32 suite) {
    return p && !p[0] && p[1] == 15 && p[2] == 172 && p[3] == suite;
}
int Ap6256HostCipherRsnRead(const U8* Ies, U32 Length, AP6256_HC_RSN* Rsn)
{
    const U8* p = 0;
    U32 n = 0, size, count, i;
    AP6256_HC_RSN r = {0};
    if (!Rsn) return 0;
    *Rsn = r;
    if (!Ies || Length > AP6256_HC_MAX_FRAME) return 0;
    while (Length) {
        if (Length < 2 || (size = (U32)Ies[1] + 2) > Length) return 0;
        if (Ies[0] == 48) {
            if (p) return 0;
            p = Ies + 2; n = size - 2;
        }
        Ies += size; Length -= size;
    }
    if (!p || n < 18 || HcRsn16(p) != 1) return 0;
    r.Group = HcRsn32(p + 2); p += 6; n -= 6;
    for (i = 0; i < 2; ++i) {
        if (n < 2) return 0;
        count = HcRsn16(p); p += 2; n -= 2;
        if (!count || count > n / 4) return 0;
        if (i) {r.Akms = p; r.AkmCount = count;}
        else {r.Pairwise = p; r.PairwiseCount = count;}
        p += 4 * count; n -= 4 * count;
    }
    r.Management = 0x06ac0f00u;
    if (n) {
        if (n < 2) return 0;
        r.Capabilities = (AP6256_HC_U16)HcRsn16(p); p += 2; n -= 2;
        if ((r.Capabilities & 0xc0u) == 0x40u) return 0;
    }
    if (n) {
        if (n < 2) return 0;
        count = HcRsn16(p); p += 2; n -= 2;
        if (count > n / 16) return 0;
        r.Pmkids = p; r.PmkidCount = count;
        p += 16 * count; n -= 16 * count;
    }
    if (n) {
        if (n != 4) return 0;
        r.Management = HcRsn32(p);
    }
    *Rsn = r; return 1;
}
int Ap6256HostCipherRsnMatch(const AP6256_HC_RSN* Rsn, U32 Akm, U32 Mfp, int Station)
{
    U32 i, pair = 0, akm = 0, expected = Mfp == 2 ? 0xc0u : Mfp ? 0x80u : 0;
    if (!Rsn || Mfp > 2 || Station < 0 || Station > 1 ||
        (Akm != 1 && Akm != 2 && Akm != 5 && Akm != 8 && Akm != 12 && Akm != 18) ||
        ((Akm == 5 || Akm == 8 || Akm == 12 || Akm == 18) && Mfp != 2) ||
        Rsn->Group != 0x09ac0f00u || !Rsn->Pairwise || !Rsn->Akms ||
        !Rsn->PairwiseCount || Rsn->PairwiseCount > 63 || !Rsn->AkmCount || Rsn->AkmCount > 63 ||
        (Station && (Rsn->PairwiseCount != 1 || Rsn->AkmCount != 1 ||
            (Rsn->Capabilities & 0xc0u) != expected || (Rsn->Capabilities & 0x0400u)))) return 0;
    if ((!Mfp && (Rsn->Capabilities & 0x40u)) ||
        (Mfp && (!(Rsn->Capabilities & 0x80u) || Rsn->Management != 0x0cac0f00u))) return 0;
    for (i = 0; i < Rsn->PairwiseCount; ++i) pair |= HcRsnSuite(Rsn->Pairwise + 4 * i, 9);
    for (i = 0; i < Rsn->AkmCount; ++i) akm |= HcRsnSuite(Rsn->Akms + 4 * i, Akm);
    return pair && akm;
}
int Ap6256Wpa3EnterpriseRsnMatch(const AP6256_HC_RSN* Rsn, int Station)
{
    U32 i, pair = 0, akm = 0;
    if (!Rsn || Station < 0 || Station > 1 || Rsn->Group != 0x04ac0f00u ||
        Rsn->Management != 0x06ac0f00u || !(Rsn->Capabilities & 0x80u) ||
        !Rsn->Pairwise || !Rsn->Akms || !Rsn->PairwiseCount ||
        Rsn->PairwiseCount > 63 || !Rsn->AkmCount || Rsn->AkmCount > 63 ||
        (Station && (Rsn->PairwiseCount != 1 || Rsn->AkmCount != 1 ||
                     (Rsn->Capabilities & 0xc0u) != 0xc0u ||
                     (Rsn->Capabilities & 0x0400u)))) return 0;
    for (i = 0; i < Rsn->PairwiseCount; ++i) pair |= HcRsnSuite(Rsn->Pairwise + 4 * i, 4);
    for (i = 0; i < Rsn->AkmCount; ++i) akm |= HcRsnSuite(Rsn->Akms + 4 * i, 5);
    return pair && akm;
}

int Ap6256HostCipherRsnPmkid(const AP6256_HC_RSN* Rsn, const U8 Pmkid[16], int Station)
{
    U32 i, j, different;
    if (!Rsn || !Pmkid || Station < 0 || Station > 1 || Rsn->PmkidCount > 15 ||
        (Station && Rsn->PmkidCount != 1) ||
        (Rsn->PmkidCount && !Rsn->Pmkids)) return 0;
    for (i = 0; i < Rsn->PmkidCount; ++i) {
        different = 0;
        for (j = 0; j < 16; ++j) different |= Rsn->Pmkids[16 * i + j] ^ Pmkid[j];
        if (!different) return 1;
    }
    return 0;
}
