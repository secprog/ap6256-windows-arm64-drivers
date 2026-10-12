/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
Ap6256GeneratePmOffload(_In_ PAP6256_WIFI Wifi,
                                  _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                  _In_ ULONG TlvLength, UCHAR** Generated, ULONG* GeneratedLength)
{
    WDI_GET_PM_PROTOCOL_OFFLOAD_PARAMETERS parameters;
    WDI_GET_PM_PROTOCOL_OFFLOAD_RESULTS results;
    AP6256_GTK_STATE gtk;
    WDI_SET_CONFIGURED_CIPHER_KEY_CONTAINER keys[6];
    UINT8* generated = NULL;
    ULONG generatedLength = 0;
    NDIS_STATUS generationStatus;
    NTSTATUS status;
    ULONG slot;

    *Generated = NULL; *GeneratedLength = 0;
    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&results, sizeof(results));
    status = Ap6256NdisToNtStatus(
        ParseWdiGetPmProtocolOffload(TlvLength, Tlv, &Wifi->TlvContext,
                                     &parameters));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    Ap6256LockAcquire(&Wifi->ConnectLock);
    for (slot = 0; slot < AP6256_ARP_OFFLOAD_SLOTS; slot++) {
        if (Wifi->ArpOffloadValid[slot] &&
            Wifi->ArpOffloadIds[slot] == parameters.GetPMOffload) {
            results.Optional.ipv4ARPOffload_IsPresent = TRUE;
            results.ipv4ARPOffload = Wifi->ArpOffloads[slot];
            break;
        }
    }
    if (!results.Optional.ipv4ARPOffload_IsPresent) {
        for (slot = 0; slot < Wifi->NsOffloadCount; ++slot) {
            if (Wifi->NsOffloads[slot].ProtocolOffloadId == parameters.GetPMOffload) {
                results.Optional.ipv6ARPOffload_IsPresent = TRUE;
                results.ipv6ARPOffload = Wifi->NsOffloads[slot];
                break;
            }
        }
    }
    RtlZeroMemory(&gtk, sizeof(gtk));
    RtlZeroMemory(keys, sizeof(keys));
    if (Wifi->GtkOffloadValid && Wifi->GtkOffloadId == parameters.GetPMOffload) {
        status = Ap6256WifiReadGtkOffload(Wifi->Ctx, &gtk);
        if (NT_SUCCESS(status) && gtk.OffloadId != parameters.GetPMOffload) status = STATUS_DATA_ERROR;
        if (NT_SUCCESS(status)) {
            ULONG byte, count = 0;
            WDI_RSN_OFFLOAD_KEYS_CONTAINER* out = &results.DOT11RSNREKeyOffload;
            results.Optional.DOT11RSNREKeyOffload_IsPresent = TRUE;
            out->RsnKeyInfo.ProtocolOffloadId = gtk.OffloadId;
            for (byte = 0; byte < 8; ++byte)
                out->RsnKeyInfo.ReplayCounter = (out->RsnKeyInfo.ReplayCounter << 8) | gtk.Replay[byte];
            out->RsnKeyInfo.KCK_CONTENT.ElementCount = 16; out->RsnKeyInfo.KCK_CONTENT.pElements = gtk.Kck;
            out->RsnKeyInfo.KEK_CONTENT.ElementCount = 16; out->RsnKeyInfo.KEK_CONTENT.pElements = gtk.Kek;
            for (slot = 0; slot < RTL_NUMBER_OF(gtk.Keys); ++slot) {
                AP6256_GROUP_KEY_STATE* key = &gtk.Keys[slot];
                if (!key->Valid) continue;
                keys[count].CipherKeyType = slot < 4
                    ? WDI_CIPHER_KEY_TYPE_GROUP_KEY : WDI_CIPHER_KEY_TYPE_IGTK;
                keys[count].CipherAlgorithm = slot < 4 ? WDI_CIPHER_ALGO_CCMP : WDI_CIPHER_ALGO_BIP;
                if (slot < 4) {
                    keys[count].Optional.CCMPKey_IsPresent = TRUE;
                    keys[count].CCMPKey.ElementCount = 16; keys[count].CCMPKey.pElements = key->Key;
                } else {
                    keys[count].Optional.BIPKey_IsPresent = TRUE;
                    keys[count].BIPKey.ElementCount = 16; keys[count].BIPKey.pElements = key->Key;
                }
                RtlCopyMemory(keys[count].ReceiveSequenceCount.ReceiveSequenceCount, key->Rsc, 6);
                ++count;
            }
            out->Optional.CipherKey_IsPresent = count != 0;
            out->CipherKey.ElementCount = count; out->CipherKey.pElements = keys;
        }
    }
    Ap6256LockRelease(&Wifi->ConnectLock);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(&gtk, sizeof(gtk));
        CleanupParsedWdiGetPmProtocolOffload(&parameters);
        return status;
    }
    if (!results.Optional.ipv4ARPOffload_IsPresent &&
        !results.Optional.ipv6ARPOffload_IsPresent && !results.Optional.DOT11RSNREKeyOffload_IsPresent) {
        CleanupParsedWdiGetPmProtocolOffload(&parameters);
        return STATUS_INVALID_PARAMETER;
    }

    CleanupParsedWdiGetPmProtocolOffload(&parameters);

    generationStatus = GenerateWdiGetPmProtocolOffload(
        &results, 0, &Wifi->TlvContext, &generatedLength, &generated);
    RtlSecureZeroMemory(&gtk, sizeof(gtk));
    *Generated = generated; *GeneratedLength = generatedLength;
    return Ap6256NdisToNtStatus(generationStatus);
}
