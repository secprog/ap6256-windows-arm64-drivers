/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

static const WDI_PHY_TYPE Ap6256Phy24[] = {
    WDI_PHY_TYPE_HRDSSS, WDI_PHY_TYPE_ERP, WDI_PHY_TYPE_HT
};

static const WDI_PHY_TYPE Ap6256Phy5[] = {
    WDI_PHY_TYPE_OFDM, WDI_PHY_TYPE_HT, WDI_PHY_TYPE_VHT
};

static const WDI_CHANNEL_MAPPING_ENTRY Ap6256ChannelMap24[] = {
    { 1, 2412 }, { 2, 2417 }, { 3, 2422 }, { 4, 2427 }, { 5, 2432 },
    { 6, 2437 }, { 7, 2442 }, { 8, 2447 }, { 9, 2452 }, { 10, 2457 },
    { 11, 2462 }, { 12, 2467 }, { 13, 2472 }, { 14, 2484 }
};

static const WDI_CHANNEL_MAPPING_ENTRY Ap6256ChannelMap5[] = {
    { 36, 5180 }, { 40, 5200 }, { 44, 5220 }, { 48, 5240 },
    { 52, 5260 }, { 56, 5280 }, { 60, 5300 }, { 64, 5320 },
    { 100, 5500 }, { 104, 5520 }, { 108, 5540 }, { 112, 5560 },
    { 116, 5580 }, { 120, 5600 }, { 124, 5620 }, { 128, 5640 },
    { 132, 5660 }, { 136, 5680 }, { 140, 5700 }, { 144, 5720 },
    { 149, 5745 }, { 153, 5765 }, { 157, 5785 }, { 161, 5805 }, { 165, 5825 }
};

static const UINT32 Ap6256Widths24[] = { 20, 40 };

static const UINT32 Ap6256Widths5[] = { 20, 40, 80 };

static const UINT32 Ap6256TxPowerLevels[] = { 50 };

static const WDI_ALGO_PAIRS Ap6256AlgoPairs[] = {
    { WDI_AUTH_ALGO_80211_OPEN, WDI_CIPHER_ALGO_NONE },
    { WDI_AUTH_ALGO_RSNA_PSK,   WDI_CIPHER_ALGO_CCMP },
    { WDI_AUTH_ALGO_RSNA,       WDI_CIPHER_ALGO_CCMP },

    { WDI_AUTH_ALGO_WPA3_SAE,   WDI_CIPHER_ALGO_CCMP },
    { WDI_AUTH_ALGO_OWE,        WDI_CIPHER_ALGO_CCMP },

    { WDI_AUTH_ALGO_RSNA_PSK,   WDI_CIPHER_ALGO_GCMP_256 },
    { WDI_AUTH_ALGO_RSNA,       WDI_CIPHER_ALGO_GCMP_256 },
    { WDI_AUTH_ALGO_WPA3_ENT,   WDI_CIPHER_ALGO_GCMP_256 },
    { WDI_AUTH_ALGO_WPA3_ENT_192, WDI_CIPHER_ALGO_GCMP_256 },
    { WDI_AUTH_ALGO_WPA3_SAE,   WDI_CIPHER_ALGO_GCMP_256 },
    { WDI_AUTH_ALGO_OWE,        WDI_CIPHER_ALGO_GCMP_256 }
};

static const WDI_ALGO_PAIRS Ap6256MgmtAlgoPairs[] = {
    { WDI_AUTH_ALGO_RSNA_PSK,   WDI_CIPHER_ALGO_BIP },
    { WDI_AUTH_ALGO_RSNA,       WDI_CIPHER_ALGO_BIP },
    { WDI_AUTH_ALGO_WPA3_SAE,   WDI_CIPHER_ALGO_BIP },
    { WDI_AUTH_ALGO_OWE,        WDI_CIPHER_ALGO_BIP },
    { WDI_AUTH_ALGO_RSNA_PSK,   WDI_CIPHER_ALGO_BIP_GMAC_256 },
    { WDI_AUTH_ALGO_RSNA,       WDI_CIPHER_ALGO_BIP_GMAC_256 },
    { WDI_AUTH_ALGO_WPA3_ENT,   WDI_CIPHER_ALGO_BIP_GMAC_256 },
    { WDI_AUTH_ALGO_WPA3_ENT_192, WDI_CIPHER_ALGO_BIP_GMAC_256 },
    { WDI_AUTH_ALGO_WPA3_SAE,   WDI_CIPHER_ALGO_BIP_GMAC_256 },
    { WDI_AUTH_ALGO_OWE,        WDI_CIPHER_ALGO_BIP_GMAC_256 }
};
