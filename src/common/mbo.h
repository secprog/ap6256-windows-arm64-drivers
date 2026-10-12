/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"

#define AP6256_MBO_IE_MAX 257u
#define AP6256_MBO_CHANNEL_MAX 64u
#define AP6256_MBO_RETRY_MAX 16u
#define AP6256_MBO_AP_MAX 64u
#define AP6256_STATION_VENDOR_IE_MAX 1024u
#define AP6256_MBO_ATTR(id) (1u << (id))
typedef struct _AP6256_MBO_AP {
    BOOLEAN Present;
    USHORT Attributes;
    UCHAR Capability, AssociationDisallowed, CellularPreference, TransitionReason;
    UCHAR CellularCapability, RejectReason;
    USHORT RetrySeconds;
} AP6256_MBO_AP;
typedef struct _AP6256_MBO_CHANNEL {
    UCHAR OperatingClass, Channel, Preference, Reason;
} AP6256_MBO_CHANNEL;
typedef struct _AP6256_MBO_PREFERENCES {
    UCHAR CellularCapability, Count;
    AP6256_MBO_CHANNEL Channels[AP6256_MBO_CHANNEL_MAX];
} AP6256_MBO_PREFERENCES;
typedef struct _AP6256_MBO_RETRY {
    UCHAR Bssid[6];
    ULONGLONG Until;
} AP6256_MBO_RETRY;
typedef struct _AP6256_MBO_SCAN_AP {
    UCHAR Bssid[6];
    AP6256_MBO_AP Ap;
    BOOLEAN Secure, PmfCapable;
    ULONGLONG Seen;
} AP6256_MBO_SCAN_AP;
typedef struct _AP6256_MBO_STATE {
    AP6256_MBO_PREFERENCES RequestedPreferences, Preferences;
    AP6256_MBO_AP AssociatedAp, Transition;
    AP6256_MBO_RETRY Retry[AP6256_MBO_RETRY_MAX];
    AP6256_MBO_SCAN_AP Scan[AP6256_MBO_AP_MAX];
    UCHAR ProbeIe[AP6256_MBO_IE_MAX], AssociationIes[AP6256_STATION_VENDOR_IE_MAX];
    ULONG ProbeIeLength, AssociationIesLength;
    BOOLEAN ProbeInstalled, AssociationInstalled, AssociationOwnMbo, Enabled;
    UCHAR DialogToken;
    BOOLEAN Associated;
} AP6256_MBO_STATE;

NTSTATUS Ap6256MboParseIes(const UCHAR* Ies, ULONG Length, AP6256_MBO_AP* Ap);
NTSTATUS Ap6256MboParseBtmRequest(const UCHAR* Body, ULONG Length,
    AP6256_MBO_AP* Ap, UCHAR* DialogToken);
NTSTATUS Ap6256MboSetPreferences(AP6256_MBO_PREFERENCES* Preferences,
    UCHAR CellularCapability, const AP6256_MBO_CHANNEL* Channels, ULONG Count);
NTSTATUS Ap6256MboPreferencesFromIes(const UCHAR* Ies, ULONG Length,
    AP6256_MBO_PREFERENCES* Preferences);
NTSTATUS Ap6256MboBuildIe(const AP6256_MBO_PREFERENCES* Preferences,
    UCHAR* Buffer, ULONG Capacity, ULONG* Length);
NTSTATUS Ap6256MboBuildNotification(const AP6256_MBO_PREFERENCES* Preferences,
    UCHAR DialogToken, UCHAR* Buffer, ULONG Capacity, ULONG* Length);
NTSTATUS Ap6256MboBuildReject(UCHAR Reason, UCHAR* Buffer, ULONG Capacity, ULONG* Length);
VOID Ap6256MboRememberRetry(AP6256_MBO_STATE* State, const UCHAR* Bssid,
    USHORT Seconds, ULONGLONG NowMs);
BOOLEAN Ap6256MboRetryBlocked(AP6256_MBO_STATE* State, const UCHAR* Bssid, ULONGLONG NowMs);
