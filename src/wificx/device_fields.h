/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
WDFDEVICE Device;
BOOLEAN WifiCapabilitiesSet;
DOT11_AUTH_CIPHER_PAIR WifiAuthCipher[12];
DOT11_AUTH_CIPHER_PAIR WifiMgmtCipher[11];
PVOID WifiDirectDevice;
UINT16 WifiStationPortId, WifiDirectPortId;

WDFOBJECT WifiEngine;
UINT16 WifiGroupPortId;
KSPIN_LOCK TalStateLock;
DOT11_AUTH_CIPHER_PAIR WifiGroupCipher[2];
