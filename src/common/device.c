/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ap6256.h"
#include "sdio.h"
#include "chip.h"
#include "firmware.h"
#include "ft_fw.h"
#include "owe.h"
#include "bcdc.h"
#include "wowl.h"
#include "datapath.h"
#include "wifi_ops.h"
#include "tdls.h"
#include "hotspot.h"
#include "p2p.h"
#include "pno.h"
#include "sae_fw.h"
#include "host_cipher_control.h"
#include "netadapter.h"
#include "model.h"

#ifdef ALLOC_PRAGMA
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WaitFunctionReady(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Function)
{
    UCHAR readyBit = (Function == 2) ? SDIO_FUNC_READY_2 : SDIO_FUNC_READY_1;
    int retries;

    for (retries = 0; retries < 2000; retries++) {
        UCHAR rdy = 0;
        NTSTATUS status = Ap6256SdioReadF0(Ctx, 0x03  , &rdy);
        if (NT_SUCCESS(status) && (rdy & readyBit)) {
            return STATUS_SUCCESS;
        }
        LARGE_INTEGER d; d.QuadPart = -(1 * 10 * 1000);
        KeDelayExecutionThread(KernelMode, FALSE, &d);
    }
    TraceError(TRACE_DEVICE, "function %u never became ready\n", Function);
    return STATUS_DEVICE_NOT_READY;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256ProbeRoamingControls(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    static const PCSTR names[] = {
        "wnm", "wnm_bsstrans_resp", "wnm_bsstrans_policy", "rrm", "ext_cap"
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(names); i++) {
        UINT32 words[4] = {0};
        AP6256_BCDC_QUERY_RESULT result;
        NTSTATUS status = Ap6256BcdcGetIovarResultIf(Ctx, 0, names[i],
            words, sizeof(words), &result);

        TraceDiag("feature probe: %s status 0x%08X reply %u error %u fw %d "
                  "length %u words %08X %08X %08X %08X\n",
                  names[i], status, (ULONG)result.FirmwareReply,
                  (ULONG)result.FirmwareError, result.FirmwareStatus,
                  result.PayloadLength, words[0], words[1], words[2], words[3]);

        if (!NT_SUCCESS(status) && !result.FirmwareReply) break;
    }
}

static ULONG Ap6256ConfiguredF2BlockSize(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    ULONG value = 0;
    ULONG valueLength = 0;
    ULONG valueType = REG_NONE;
    NTSTATUS status;

    status = Ap6256RegQueryValue(Ctx->Pdo, L"F2BlockSize", sizeof(value),
                                 &value, &valueLength, &valueType);
    if (!NT_SUCCESS(status) || valueType != REG_DWORD ||
        valueLength != sizeof(value)) {
        return AP6256_F2_BLOCKSIZE;
    }
    if (value == 64u || value == 128u || value == 256u || value == 512u) {
        return value;
    }
    TraceWarn(TRACE_DEVICE,
              "registry F2BlockSize %u is not 64, 128, 256 or 512; using %u\n",
              value, (ULONG)AP6256_F2_BLOCKSIZE);
    return AP6256_F2_BLOCKSIZE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BringUpChip(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                            _In_ BOOLEAN OnCommandWorker)
{
    NTSTATUS status;
    UCHAR ien;
    USHORT hostBlockSize;
    CHAR caps[512];
    NTSTATUS capStatus;

    if (Ap6256FirmwareVolumeGone()) {
        TraceDiag("bring-up skipped: system is shutting down\n");
        return STATUS_SYSTEM_SHUTDOWN;
    }

    TraceInfo(TRACE_DEVICE, "bring-up starting\n");
    {
        ULONG busClock = 0;
        UCHAR busWidth = 0;
        NTSTATUS clockStatus = Ap6256SdBusGetBusClock(Ctx, &busClock);
        NTSTATUS widthStatus = Ap6256SdBusGetBusWidth(Ctx, &busWidth);
        TraceDiag("bus at bring-up: clock %u (0x%08X) width %u (0x%08X)\n",
                  busClock, clockStatus, busWidth, widthStatus);
    }

    status = Ap6256SdBusGetHostBlockSize(Ctx, &hostBlockSize);
    if (!NT_SUCCESS(status)) goto fail;
    if (hostBlockSize == 0) {
        status = STATUS_DEVICE_CONFIGURATION_ERROR;
        goto fail;
    }
    Ctx->Sdio.Function1BlockSize = min((ULONG)hostBlockSize, AP6256_F1_BLOCKSIZE);
    Ctx->Sdio.Function2BlockSize = min((ULONG)hostBlockSize,
                                       Ap6256ConfiguredF2BlockSize(Ctx));
    TraceInfo(TRACE_DEVICE, "function 2 block size %u (host block length %u)\n",
              Ctx->Sdio.Function2BlockSize, (ULONG)hostBlockSize);

    status = Ap6256SdBusEnableFunction(Ctx, 1);
    if (!NT_SUCCESS(status)) goto fail;
    status = Ap6256SdBusSetBlockSize(Ctx, 1, Ctx->Sdio.Function1BlockSize);
    if (!NT_SUCCESS(status)) goto fail;
    status = Ap6256WaitFunctionReady(Ctx, 1);
    if (!NT_SUCCESS(status)) goto fail;

    {
        UCHAR sleep = 0;
        status = Ap6256SdioReadF1(Ctx, SBSDIO_FUNC1_SLEEPCSR, &sleep);
        if (!NT_SUCCESS(status)) goto fail;
        if ((sleep & SBSDIO_FUNC1_SLEEPCSR_KSO_EN) == 0) {
            status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_SLEEPCSR,
                (UCHAR)(sleep | SBSDIO_FUNC1_SLEEPCSR_KSO_EN));
            if (!NT_SUCCESS(status)) goto fail;
            LARGE_INTEGER delay;
            delay.QuadPart = -20000;
            (VOID)KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    (VOID)Ap6256SdioSetCardBlockSize(Ctx, 1, 0);
    status = Ap6256SdioSetCardBlockSize(Ctx, 2, Ctx->Sdio.Function2BlockSize);
    if (!NT_SUCCESS(status)) goto fail;

    status = Ap6256ChipAttach(Ctx);
    if (!NT_SUCCESS(status)) goto fail;

    status = Ap6256FirmwareDownload(Ctx);
    if (!NT_SUCCESS(status)) goto fail;

    if (Ctx->Chip.SdiodCore == NULL) {
        status = STATUS_DEVICE_CONFIGURATION_ERROR;
        goto fail;
    }

    {
        UCHAR clockControl = 0;
        status = Ap6256SdioReadF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR, &clockControl);
        if (!NT_SUCCESS(status)) goto fail;
        status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR,
                                   (UCHAR)(clockControl | SBSDIO_FORCE_HT));
        if (!NT_SUCCESS(status)) goto fail;
    }

    status = Ap6256SdioWriteBackplane32(
        Ctx, Ctx->Chip.SdiodCore->Base + SD_REG_TOSBMAILBOXDATA,
        SDPCM_PROT_VERSION << SMB_DATA_VERSION_SHIFT);
    if (!NT_SUCCESS(status)) goto fail;

    status = Ap6256SdBusEnableFunction(Ctx, 2);
    if (!NT_SUCCESS(status)) goto fail;
    status = Ap6256WaitFunctionReady(Ctx, 2);
    if (!NT_SUCCESS(status)) goto fail;

    status = Ap6256SdioWriteBackplane32(
        Ctx, Ctx->Chip.SdiodCore->Base + SD_REG_HOSTINTMASK,
        SDPCM_HOSTINTMASK);
    if (!NT_SUCCESS(status)) goto fail;

    {
        ULONG coreRev = (ULONG)Ctx->Chip.SdiodCore->Rev;
        ULONG blockSize = Ctx->Sdio.Function2BlockSize;
        UCHAR watermark = 0;
        UCHAR mesWatermark = 0;
        UCHAR deviceControl = 0;
        UCHAR readWatermark = 0;
        UCHAR readMesBusy = 0;

        if (coreRev >= SBSDIO_FIFOTUNE_MIN_COREREV) {
            if (blockSize == 512u) {
                watermark = SBSDIO_OVERFLOW_BLKSZ512_WM;
                mesWatermark = SBSDIO_OVERFLOW_BLKSZ512_MES;
            } else {
                watermark = (UCHAR)min(blockSize / 4u, SBSDIO_WATERMARK_MASK);
                mesWatermark = (UCHAR)min(blockSize / 4u, SBSDIO_WATERMARK_MASK);
            }
            if (watermark != 0) {
                status = Ap6256SdioWriteF1(Ctx, SBSDIO_WATERMARK, watermark);
                if (!NT_SUCCESS(status)) goto fail;
                status = Ap6256SdioReadF1(Ctx, SBSDIO_DEVICE_CTL, &deviceControl);
                if (!NT_SUCCESS(status)) goto fail;
                status = Ap6256SdioWriteF1(Ctx, SBSDIO_DEVICE_CTL,
                                           (UCHAR)(deviceControl | SBSDIO_DEVCTL_F2WM_ENAB));
                if (!NT_SUCCESS(status)) goto fail;
            }
            if (mesWatermark != 0) {
                status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_MESBUSYCTRL,
                                           (UCHAR)(mesWatermark | SBSDIO_MESBUSYCTRL_ENAB));
                if (!NT_SUCCESS(status)) goto fail;
            }
        } else {
            watermark = SBSDIO_DEFAULT_WATERMARK;
            status = Ap6256SdioWriteF1(Ctx, SBSDIO_WATERMARK, watermark);
            if (!NT_SUCCESS(status)) goto fail;
        }

        (VOID)Ap6256SdioReadF1(Ctx, SBSDIO_DEVICE_CTL, &deviceControl);
        (VOID)Ap6256SdioReadF1(Ctx, SBSDIO_WATERMARK, &readWatermark);
        (VOID)Ap6256SdioReadF1(Ctx, SBSDIO_FUNC1_MESBUSYCTRL, &readMesBusy);
        TraceDiag("SDIO FIFO tuning: sdiod core rev %u, F2 block %u -> watermark "
                  "%u, MES busy %u; chip reads DEVCTL 0x%02X WATERMARK 0x%02X "
                  "MESBUSYCTRL 0x%02X\n",
                  coreRev, blockSize, (ULONG)watermark, (ULONG)mesWatermark,
                  (ULONG)deviceControl, (ULONG)readWatermark,
                  (ULONG)readMesBusy);
    }

    ien = SDIO_CCCR_IEN_FUNC0 | SDIO_CCCR_IEN_FUNC1 | SDIO_CCCR_IEN_FUNC2;
    status = Ap6256SdioWriteF0(Ctx, 0x04  , ien);
    if (!NT_SUCCESS(status)) goto fail;
    status = Ap6256SdBusRegisterInterrupt(Ctx);
    if (!NT_SUCCESS(status)) goto fail;

    status = Ap6256BcdcInit(Ctx);
    if (!NT_SUCCESS(status)) goto fail;

    status = Ap6256DatapathInit(Ctx);
    if (!NT_SUCCESS(status)) goto fail;

    status = Ap6256PnoResultsInitialize(Ctx);
    if (!NT_SUCCESS(status)) goto fail;
    Ap6256DatapathStart(Ctx);

    status = Ap6256DatapathEnableTxGlom(Ctx);
    if (!NT_SUCCESS(status)) goto fail;

    status = Ap6256FirmwareLoadClm(Ctx);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_DEVICE, "CLM configuration failed 0x%08X\n", status);
        goto fail;
    }

    status = Ap6256WifiUp(Ctx);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_DEVICE, "Wi-Fi UP configuration failed 0x%08X\n", status);
        goto fail;
    }

    if (Ctx->ConfiguredMacAddressValid) {
        status = Ap6256WifiSetMacAddress(Ctx, Ctx->ConfiguredMacAddress);
        if (!NT_SUCCESS(status)) goto fail;
    }

    status = Ap6256BcdcGetIovar(Ctx, "cur_etheraddr", Ctx->MacAddress, sizeof(Ctx->MacAddress));

    if (!NT_SUCCESS(Ap6256WifiSetPacketFilterMax(Ctx,
                                                 &Ctx->PacketFilterMax))) {
        TraceWarn(TRACE_DEVICE,
                  "the firmware would not take a packet filter ceiling; "
                  "using %u\n",
                  Ctx->PacketFilterMax);
    }
    TraceInfo(TRACE_DEVICE, "packet filter slots: %u\n", Ctx->PacketFilterMax);

    Ctx->PermanentMacAddressValid = (BOOLEAN)NT_SUCCESS(
        Ap6256WifiGetPermanentMacAddress(Ctx, Ctx->PermanentMacAddress));
    if (Ctx->PermanentMacAddressValid) {
        TraceInfo(TRACE_DEVICE,
                  "permanent MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
                  Ctx->PermanentMacAddress[0], Ctx->PermanentMacAddress[1],
                  Ctx->PermanentMacAddress[2], Ctx->PermanentMacAddress[3],
                  Ctx->PermanentMacAddress[4], Ctx->PermanentMacAddress[5]);
    }

    Ap6256P2pInitialize(Ctx);
    if (NT_SUCCESS(status)) {
        Ap6256NetSetMacAddress(Ctx);
        TraceInfo(TRACE_DEVICE, "MAC %02X:%02X:%02X:%02X:%02X:%02X\n",
                  Ctx->MacAddress[0], Ctx->MacAddress[1], Ctx->MacAddress[2],
                  Ctx->MacAddress[3], Ctx->MacAddress[4], Ctx->MacAddress[5]);
    } else {
        goto fail;
    }

    {
        RtlZeroMemory(caps, sizeof(caps));
        capStatus = Ap6256BcdcGetIovar(Ctx, "cap", caps, sizeof(caps) - 1);
        if (NT_SUCCESS(capStatus)) {
            caps[RTL_NUMBER_OF(caps) - 1] = '\0';
            TraceDiag("firmware capabilities: %s\n", caps);
        } else {
            TraceDiag("firmware capability query failed 0x%08X\n", capStatus);
        }

        Ctx->FirmwareP2pSupported = FALSE;
        if (NT_SUCCESS(capStatus)) {
            ULONG i;
            for (i = 0; i + 3 < RTL_NUMBER_OF(caps); i++) {
                if (caps[i] == '\0') break;
                if ((i == 0 || caps[i - 1] == ' ') &&
                    caps[i] == 'p' && caps[i + 1] == '2' &&
                    caps[i + 2] == 'p' &&
                    (caps[i + 3] == '\0' || caps[i + 3] == ' ')) {
                    Ctx->FirmwareP2pSupported = TRUE;
                    break;
                }
            }
        }
        Ctx->FirmwareMchanSupported = FALSE;
        if (NT_SUCCESS(capStatus)) {
            ULONG i;
            for (i = 0; i + 5 < RTL_NUMBER_OF(caps) && caps[i] != '\0'; ++i) {
                if ((i == 0 || caps[i - 1] == ' ') &&
                    RtlEqualMemory(caps + i, "mchan", 5) &&
                    (caps[i + 5] == ' ' || caps[i + 5] == '\0')) {
                    Ctx->FirmwareMchanSupported = TRUE;
                    break;
                }
            }
        }
        TraceDiag("firmware multi-channel concurrency %u\n", Ctx->FirmwareMchanSupported);
        TraceDiag("firmware probe: cap \"p2p\" token -> "
                  "AP/P2P/virtualization capability %s\n",
                  Ctx->FirmwareP2pSupported ? "yes" : "no");

        {
            UINT32 probe;
            NTSTATUS s1, s2, s3, s4, s5, ndStatus;
            UCHAR ndState[24];

            probe = 0;
            s1 = Ap6256BcdcGetIovar(Ctx, "sae", &probe, sizeof(probe));
            probe = 0;
            s2 = Ap6256BcdcGetIovar(Ctx, "sae_password", &probe, sizeof(probe));
            probe = 0;
            s3 = Ap6256BcdcGetIovar(Ctx, "mfp", &probe, sizeof(probe));
            probe = 0;
            s4 = Ap6256BcdcGetIovar(Ctx, "arpoe", &probe, sizeof(probe));
            probe = 0;
            s5 = Ap6256BcdcGetIovar(Ctx, "ndoe", &probe, sizeof(probe));
            probe = 0;
            Ctx->FirmwareWowlAdapter = FALSE;
            Ctx->FirmwareGtkOffloadSupported = FALSE;
            {
                AP6256_BCDC_QUERY_RESULT result;
                UINT32 ready = 0;
                status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "wdi_wowl_ready",
                    &ready, sizeof(ready), &result);
                Ctx->FirmwareWowlAdapter = (BOOLEAN)(NT_SUCCESS(status) &&
                    result.PayloadLength == sizeof(ready) && ready == AP6256_WOWL_ABI);
                if (Ctx->FirmwareWowlAdapter) {
                    status = Ap6256SdioInitializeRetention(Ctx);
                    if (!NT_SUCCESS(status)) goto fail;
                    Ctx->FirmwareGtkOffloadSupported = TRUE;
                }
                TraceDiag("WoWLAN patch ABI ready %u, GTK backend %u\n",
                    Ctx->FirmwareWowlAdapter, Ctx->FirmwareGtkOffloadSupported);
            }
            Ctx->WowlCapabilities = 0;
            {
                NTSTATUS wowlStatus = Ap6256BcdcGetIovar(
                    Ctx, "wowl_cap", &probe, sizeof(probe));
                if (NT_SUCCESS(wowlStatus))
                    Ctx->WowlCapabilities = probe;
                TraceDiag("firmware probe: wowl_cap query 0x%08X, mask 0x%08X\n",
                          wowlStatus, Ctx->WowlCapabilities);
            }

            Ctx->FirmwareSaeSupported =
                (BOOLEAN)(NT_SUCCESS(s1) || NT_SUCCESS(s2));
            Ctx->FirmwareMfpSupported = (BOOLEAN)NT_SUCCESS(s3);
            Ctx->FirmwareArpOffloadSupported = (BOOLEAN)NT_SUCCESS(s4);

            RtlZeroMemory(ndState, sizeof(ndState));
            ndStatus = Ap6256BcdcGetIovar(Ctx, Ctx->FirmwareWowlAdapter ? "wdi_nd_status" : "nd_status", ndState, sizeof(ndState));
            Ctx->FirmwareNdOffloadSupported =
                (BOOLEAN)(NT_SUCCESS(s5) && NT_SUCCESS(ndStatus));
            TraceDiag("firmware probe: arpoe 0x%08X, ndoe 0x%08X, nd_status 0x%08X -> "
                      "ARP control %s, ND backend %s\n",
                      s4, s5, ndStatus,
                      Ctx->FirmwareArpOffloadSupported ? "yes" : "no",
                      Ctx->FirmwareNdOffloadSupported ? "yes" : "no");
            if (Ctx->FirmwareFtPatchVerified) {
                status = Ap6256FtFirmwareQualify(Ctx);
                if (!NT_SUCCESS(status)) goto fail;
            } else TraceDiag("802.11r FT bridge not selected in this build\n");
            if (Ctx->FirmwareOwePatchVerified) {
                status = Ap6256OweFirmwareQualify(Ctx);
                if (!NT_SUCCESS(status)) goto fail;
            }
            if (Ctx->FirmwareHostCipherPatchVerified) {

                NTSTATUS hcStatus = Ap6256HostCipherQualify(Ctx, TRUE);
                if (!NT_SUCCESS(hcStatus))
                    TraceDiag("host-cipher relay unavailable: qualification 0x%08X; capability disabled\n", hcStatus);
                else
                    TraceDiag("host-cipher relay ready: GCMP-256 / BIP-GMAC-256 with Windows CNG\n");
            }

            TraceDiag("firmware probe: sae 0x%08X, sae_password 0x%08X, "
                      "mfp 0x%08X -> SAE %s, MFP %s\n",
                      s1, s2, s3,
                      Ctx->FirmwareSaeSupported ? "yes" : "no",
                      Ctx->FirmwareMfpSupported ? "yes" : "no");
        }
    }

    Ap6256ProbeRoamingControls(Ctx);
    status = Ap6256WifiQualifyMbo(Ctx);
    if (!NT_SUCCESS(status)) goto fail;

    status = Ap6256ModelPrepareConcurrent(Ctx);
    if (!NT_SUCCESS(status)) goto fail;

    Ap6256TdlsInitialize(Ctx, NT_SUCCESS(capStatus) ? caps : NULL, sizeof(caps));
    Ap6256PnoEnableResultEvents(Ctx);
    Ap6256SaeFirmwarePrepare(Ctx);
    status = Ap6256NetHardwareStart(Ctx);
    if (!NT_SUCCESS(status)) goto fail;
    TraceInfo(TRACE_DEVICE, "bring-up complete\n");
    return STATUS_SUCCESS;

fail:
    TraceError(TRACE_DEVICE, "bring-up failed 0x%08X\n", status);
    Ap6256TearDownChip(Ctx, OnCommandWorker);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256TearDownChip(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                         _In_ BOOLEAN OnCommandWorker)
{
    UCHAR interruptEnable;
    UINT32 interruptStatus;

    Ctx->PowerThread = KeGetCurrentThread();

    Ap6256HostCipherFirmwareRetire(Ctx);
    Ctx->FirmwareHostCipherPatchVerified = FALSE;
    if (Ctx->Sdio.Sleeping && NT_SUCCESS(Ap6256SdioSetSleep(Ctx, FALSE)))
        Ap6256DatapathResume(Ctx);
    Ap6256PnoResultsQuiesce(Ctx);
    Ap6256NetHardwareStop(Ctx, STATUS_POWER_STATE_INVALID, OnCommandWorker);

    if (Ctx->FirmwareState == Ap6256FwRunning && Ctx->DatapathRunning) {
        (VOID)Ap6256WifiRadioUpDown(Ctx, FALSE);
    }

    if (Ctx->Sdio.BusInterface != NULL) {
        if (Ctx->Sdio.ClockOn && Ctx->Chip.SdiodCore != NULL) {
            (VOID)Ap6256SdioWriteBackplane32(
                Ctx, Ctx->Chip.SdiodCore->Base + SD_REG_HOSTINTMASK, 0);
            interruptStatus = 0;
            if (NT_SUCCESS(Ap6256SdioReadBackplane32(
                    Ctx, Ctx->Chip.SdiodCore->Base + SD_REG_INTSTATUS,
                    &interruptStatus)) && interruptStatus != 0) {
                (VOID)Ap6256SdioWriteBackplane32(
                    Ctx, Ctx->Chip.SdiodCore->Base + SD_REG_INTSTATUS,
                    interruptStatus);
            }
        }

        interruptEnable = 0;
        if (NT_SUCCESS(Ap6256SdioReadF0(Ctx, 0x04  ,
                                        &interruptEnable))) {
            interruptEnable &= (UCHAR)~(SDIO_CCCR_IEN_FUNC1 |
                                         SDIO_CCCR_IEN_FUNC2);
            if ((interruptEnable & (UCHAR)~SDIO_CCCR_IEN_FUNC0) == 0) {
                interruptEnable &= (UCHAR)~SDIO_CCCR_IEN_FUNC0;
            }
            (VOID)Ap6256SdioWriteF0(Ctx, 0x04, interruptEnable);
        }
    }

    Ap6256DatapathStop(Ctx);
    Ap6256HostCipherStoreStopAll(&Ctx->HostCipherStore);
    Ap6256PnoResultsDestroy(Ctx);
    Ap6256BcdcCleanup(Ctx);

    if (Ctx->Sdio.BusInterface != NULL) {
        (VOID)Ap6256SdBusDisableFunction(Ctx, 2);
    }
    if (Ctx->Sdio.ClockOn && Ctx->Chip.ArmCore != NULL) {
        (VOID)Ap6256ChipSetPassive(Ctx);
    }
    if (Ctx->Sdio.ClockOn) {
        (VOID)Ap6256SdioDisableBackplaneClock(Ctx);
    }
    if (Ctx->Sdio.BusInterface != NULL) {
        (VOID)Ap6256SdBusDisableFunction(Ctx, 1);
    }

    Ctx->LowPowerArmed = FALSE;
    Ctx->FirmwareWowlAdapter = FALSE;
    Ctx->FirmwareGtkOffloadSupported = FALSE;
    Ctx->WowlCapabilities = 0;
    Ctx->Sdio.RetentionInitialized = FALSE;
    Ctx->Sdio.SaveRestoreEnabled = FALSE;
    Ctx->Sdio.Sleeping = FALSE;
    Ctx->Sdio.SepIntSaved = FALSE;
    Ctx->PowerThread = NULL;
    InterlockedExchange(&Ctx->FirmwareIoQuiesced, 0);
    InterlockedExchange(&Ctx->HostTxQuiesced, 0);
    Ctx->Sdio.ClockOn = FALSE;
    Ctx->Sdio.BackplaneWindow = MAXULONG;
    Ctx->FirmwareState = Ap6256FwNotLoaded;
    Ctx->D11IoType = 0;
    Ctx->Go.FirmwareReady = FALSE;
    Ctx->Go.Started = FALSE;
    Ctx->P2pBssValid = FALSE;
    RtlZeroMemory((PVOID)Ctx->FirmwareIfMap, sizeof(Ctx->FirmwareIfMap));
    Ctx->FirmwareLinkUp = FALSE;
    Ctx->SupplicantComplete = FALSE;
    Ctx->ConnectionRequiresSupplicant = FALSE;
    TraceInfo(TRACE_DEVICE, "tear-down complete\n");
}
