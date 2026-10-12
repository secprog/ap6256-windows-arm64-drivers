/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "mbo.h"

static const UCHAR Ap6256MboOui[4] = {0x50, 0x6f, 0x9a, 0x16};

NTSTATUS Ap6256MboParseIes(const UCHAR* Ies, ULONG Length, AP6256_MBO_AP* Ap)
{
    AP6256_MBO_AP parsed = {0};
    ULONG offset = 0;
    RtlZeroMemory(Ap, sizeof(*Ap));
    if (Length && !Ies) return STATUS_INVALID_PARAMETER;
    while (offset < Length) {
        ULONG end, pos;
        if (Length - offset < 2 || (ULONG)Ies[offset + 1] > Length - offset - 2)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        end = offset + 2 + Ies[offset + 1];
        if (Ies[offset] != 221 || Ies[offset + 1] < 4 ||
            !RtlEqualMemory(Ies + offset + 2, Ap6256MboOui, sizeof(Ap6256MboOui))) {
            offset = end;
            continue;
        }
        parsed.Present = TRUE;
        pos = offset + 6;
        while (pos < end) {
            UCHAR id, size;
            ULONG value = 0;
            if (end - pos < 2) return STATUS_DEVICE_PROTOCOL_ERROR;
            id = Ies[pos++]; size = Ies[pos++];
            if (size > end - pos) return STATUS_DEVICE_PROTOCOL_ERROR;
            if (id >= 1 && id <= 8 && id != 2) {
                if (size != (id == 8 ? 2 : 1)) return STATUS_DEVICE_PROTOCOL_ERROR;
                value = Ies[pos];
                if (id == 8) value |= (ULONG)Ies[pos + 1] << 8;
                if ((id == 3 && (value < 1 || value > 3)) ||
                    (id == 4 && (value < 1 || value > 5)) ||
                    (id == 5 && value != 0 && value != 1 && value != 255) ||
                    (id == 6 && value > 9) || (id == 7 && value > 6))
                    return STATUS_DEVICE_PROTOCOL_ERROR;

                if (parsed.Attributes & AP6256_MBO_ATTR(id))
                    return STATUS_DEVICE_PROTOCOL_ERROR;
                parsed.Attributes |= (USHORT)AP6256_MBO_ATTR(id);
                switch (id) {
                case 1: parsed.Capability = (UCHAR)value; break;
                case 3: parsed.CellularCapability = (UCHAR)value; break;
                case 4: parsed.AssociationDisallowed = (UCHAR)value; break;
                case 5: parsed.CellularPreference = (UCHAR)value; break;
                case 6: parsed.TransitionReason = (UCHAR)value; break;
                case 7: parsed.RejectReason = (UCHAR)value; break;
                case 8: parsed.RetrySeconds = (USHORT)value; break;
                default: break;
                }
            } else if (id == 2) {
                if (size && (size < 4 || Ies[pos + size - 1] > 3))
                    return STATUS_DEVICE_PROTOCOL_ERROR;
                parsed.Attributes |= (USHORT)AP6256_MBO_ATTR(2);
            }
            pos += size;
        }
        offset = end;
    }
    *Ap = parsed;
    return STATUS_SUCCESS;
}

NTSTATUS Ap6256MboParseBtmRequest(const UCHAR* Body, ULONG Length,
    AP6256_MBO_AP* Ap, UCHAR* DialogToken)
{
    ULONG offset = 7;
    UCHAR mode;
    NTSTATUS status;
    RtlZeroMemory(Ap, sizeof(*Ap)); *DialogToken = 0;
    if (!Body || Length < 7 || Body[0] != 10 || Body[1] != 7)
        return STATUS_INVALID_PARAMETER;
    mode = Body[3];
    if (mode & 8) {
        if (Length - offset < 12) return STATUS_DEVICE_PROTOCOL_ERROR;
        offset += 12;
    }
    if (mode & 16) {
        if (offset == Length || (ULONG)Body[offset] > Length - offset - 1)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        offset += 1u + Body[offset];
    }
    status = Ap6256MboParseIes(Body + offset, Length - offset, Ap);
    if (!NT_SUCCESS(status)) return status;

    if (!(mode & 4) || (mode & 8)) {
        Ap->Attributes &= (USHORT)(0xffffu ^ AP6256_MBO_ATTR(8));
        Ap->RetrySeconds = 0;
    }
    *DialogToken = Body[2];
    return STATUS_SUCCESS;
}

NTSTATUS Ap6256MboSetPreferences(AP6256_MBO_PREFERENCES* Preferences,
    UCHAR CellularCapability, const AP6256_MBO_CHANNEL* Channels, ULONG Count)
{
    AP6256_MBO_PREFERENCES next = {0};
    ULONG i, j;
    if (CellularCapability < 1 || CellularCapability > 3 ||
        Count > AP6256_MBO_CHANNEL_MAX || (Count && !Channels))
        return STATUS_INVALID_PARAMETER;
    next.CellularCapability = CellularCapability;
    for (i = 0; i < Count; i++) {
        AP6256_MBO_CHANNEL entry = Channels[i];
        if (!entry.OperatingClass || !entry.Channel || entry.Reason > 3)
            return STATUS_INVALID_PARAMETER;
        for (j = 0; j < i; j++) {
            if (Channels[j].OperatingClass == entry.OperatingClass &&
                Channels[j].Channel == entry.Channel)
                return STATUS_INVALID_PARAMETER;
        }

        for (j = next.Count; j; j--) {
            AP6256_MBO_CHANNEL prev = next.Channels[j - 1];
            ULONG a = ((ULONG)prev.OperatingClass << 24) | ((ULONG)prev.Preference << 16) |
                ((ULONG)prev.Reason << 8) | prev.Channel;
            ULONG b = ((ULONG)entry.OperatingClass << 24) | ((ULONG)entry.Preference << 16) |
                ((ULONG)entry.Reason << 8) | entry.Channel;
            if (a <= b) break;
            next.Channels[j] = prev;
        }
        next.Channels[j] = entry;
        next.Count++;
    }
    *Preferences = next;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256MboEncode(const AP6256_MBO_PREFERENCES* Preferences,
    UCHAR Token, BOOLEAN Notification, UCHAR* Buffer, ULONG Capacity, ULONG* Length)
{
    UCHAR bytes[768];
    ULONG pos = Notification ? 4u : 6u, i = 0;
    *Length = 0;
    if (!Buffer || !Preferences || Preferences->Count > AP6256_MBO_CHANNEL_MAX ||
        Preferences->CellularCapability < 1 || Preferences->CellularCapability > 3 ||
        (Notification && !Token)) return STATUS_INVALID_PARAMETER;
    if (Notification) { bytes[0] = 10; bytes[1] = 26; bytes[2] = Token; bytes[3] = 221; }
    else { bytes[0] = 221; RtlCopyMemory(bytes + 2, Ap6256MboOui, 4); }
    do {
        ULONG start = i, end = i, count;
        if (i < Preferences->Count) {
            AP6256_MBO_CHANNEL entry = Preferences->Channels[i];
            while (end < Preferences->Count &&
                Preferences->Channels[end].OperatingClass == entry.OperatingClass &&
                Preferences->Channels[end].Preference == entry.Preference &&
                Preferences->Channels[end].Reason == entry.Reason) end++;
        }
        count = end - start;
        bytes[pos++] = Notification ? 221 : 2;
        bytes[pos++] = (UCHAR)((count ? count + 3 : 0) + (Notification ? 4 : 0));
        if (Notification) {
            RtlCopyMemory(bytes + pos, Ap6256MboOui, 3); pos += 3; bytes[pos++] = 2;
        }
        if (count) {
            bytes[pos++] = Preferences->Channels[start].OperatingClass;
            for (i = start; i < end; i++) bytes[pos++] = Preferences->Channels[i].Channel;
            bytes[pos++] = Preferences->Channels[start].Preference;
            bytes[pos++] = Preferences->Channels[start].Reason;
        }
        i = end;
    } while (i < Preferences->Count);
    bytes[pos++] = Notification ? 221 : 3;
    bytes[pos++] = Notification ? 5 : 1;
    if (Notification) {
        RtlCopyMemory(bytes + pos, Ap6256MboOui, 3); pos += 3; bytes[pos++] = 3;
    }
    bytes[pos++] = Preferences->CellularCapability;
    if ((!Notification && pos > AP6256_MBO_IE_MAX) || Capacity < pos)
        return STATUS_BUFFER_TOO_SMALL;
    if (!Notification) bytes[1] = (UCHAR)(pos - 2);
    RtlCopyMemory(Buffer, bytes, pos); *Length = pos;
    return STATUS_SUCCESS;
}

NTSTATUS Ap6256MboPreferencesFromIes(const UCHAR* Ies, ULONG Length,
    AP6256_MBO_PREFERENCES* Preferences)
{
    AP6256_MBO_AP ap;
    AP6256_MBO_CHANNEL channels[AP6256_MBO_CHANNEL_MAX];
    ULONG offset = 0, count = 0;
    NTSTATUS status = Ap6256MboParseIes(Ies, Length, &ap);
    if (!NT_SUCCESS(status)) return status;
    if (!ap.Present || !(ap.Attributes & AP6256_MBO_ATTR(3))) return STATUS_NOT_FOUND;
    while (offset < Length) {
        ULONG end = offset + 2 + Ies[offset + 1], pos = offset + 6;
        if (Ies[offset] == 221 && Ies[offset + 1] >= 4 &&
            RtlEqualMemory(Ies + offset + 2, Ap6256MboOui, 4)) {
            while (pos < end) {
                UCHAR id = Ies[pos], size = Ies[pos + 1];
                ULONG i;
                pos += 2;
                if (id == 2 && size) {
                    for (i = 1; i < (ULONG)size - 2; i++) {
                        if (count == AP6256_MBO_CHANNEL_MAX) return STATUS_BUFFER_OVERFLOW;
                        channels[count].OperatingClass = Ies[pos];
                        channels[count].Channel = Ies[pos + i];
                        channels[count].Preference = Ies[pos + size - 2];
                        channels[count++].Reason = Ies[pos + size - 1];
                    }
                }
                pos += size;
            }
        }
        offset = end;
    }
    return Ap6256MboSetPreferences(Preferences, ap.CellularCapability, channels, count);
}

NTSTATUS Ap6256MboBuildIe(const AP6256_MBO_PREFERENCES* Preferences,
    UCHAR* Buffer, ULONG Capacity, ULONG* Length)
{ return Ap6256MboEncode(Preferences, 0, FALSE, Buffer, Capacity, Length); }
NTSTATUS Ap6256MboBuildNotification(const AP6256_MBO_PREFERENCES* Preferences,
    UCHAR DialogToken, UCHAR* Buffer, ULONG Capacity, ULONG* Length)
{ return Ap6256MboEncode(Preferences, DialogToken, TRUE, Buffer, Capacity, Length); }
NTSTATUS Ap6256MboBuildReject(UCHAR Reason, UCHAR* Buffer, ULONG Capacity, ULONG* Length)
{
    *Length = 0;
    if (Reason > 6 || !Buffer) return STATUS_INVALID_PARAMETER;
    if (Capacity < 9) return STATUS_BUFFER_TOO_SMALL;
    Buffer[0] = 221; Buffer[1] = 7; RtlCopyMemory(Buffer + 2, Ap6256MboOui, 4);
    Buffer[6] = 7; Buffer[7] = 1; Buffer[8] = Reason; *Length = 9;
    return STATUS_SUCCESS;
}

VOID Ap6256MboRememberRetry(AP6256_MBO_STATE* State, const UCHAR* Bssid,
    USHORT Seconds, ULONGLONG NowMs)
{
    ULONG i, selected = 0;
    ULONGLONG earliest = ~((ULONGLONG)0), delay = (ULONGLONG)Seconds * 1000;
    if (!Bssid) return;
    for (i = 0; i < AP6256_MBO_RETRY_MAX; i++) {
        if (RtlEqualMemory(State->Retry[i].Bssid, Bssid, 6)) { selected = i; break; }
        if (State->Retry[i].Until < earliest) { selected = i; earliest = State->Retry[i].Until; }
    }
    RtlCopyMemory(State->Retry[selected].Bssid, Bssid, 6);
    State->Retry[selected].Until = ~((ULONGLONG)0) - NowMs < delay
        ? ~((ULONGLONG)0) : NowMs + delay;
}

BOOLEAN Ap6256MboRetryBlocked(AP6256_MBO_STATE* State, const UCHAR* Bssid, ULONGLONG NowMs)
{
    ULONG i;
    if (!Bssid) return FALSE;
    for (i = 0; i < AP6256_MBO_RETRY_MAX; i++) {
        if (State->Retry[i].Until <= NowMs) State->Retry[i].Until = 0;
        if (State->Retry[i].Until && RtlEqualMemory(State->Retry[i].Bssid, Bssid, 6))
            return TRUE;
    }
    return FALSE;
}
