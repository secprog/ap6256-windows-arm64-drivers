/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "firmware.h"
#include "chip.h"
#include "sdio.h"
#include "bcdc.h"
#include "native_mgmt.h"
#include "sae_firmware.h"
#include "ft_firmware.h"
#include "owe_firmware.h"
#include "service.h"
#include "ftm_firmware.h"
#include "host_cipher.h"
#include "host_fips.h"
#include "host_cipher_control.h"
#include "pno.h"
#include "pno_delay.h"
#include "netadapter.h"
#include "model.h"

static BOOLEAN Ap6256CrashRamRange(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Address, ULONG Length)
{
    return Address >= Ctx->Chip.RamBase && Length <= Ctx->Chip.RamSize &&
        Address - Ctx->Chip.RamBase <= Ctx->Chip.RamSize - Length;
}

static NTSTATUS Ap6256CrashString(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Address,
                                CHAR* Text, ULONG Length)
{
    NTSTATUS status;
    BOOLEAN rom = Ctx->Chip.ChipId == 0x4345 && Ctx->Chip.ChipRev == 9 &&
        Address != 0 && Length <= 0xb0000u && Address <= 0xb0000u - Length;
    if (Length == 0 || (!rom && !Ap6256CrashRamRange(Ctx, Address, Length)))
        return STATUS_INVALID_ADDRESS;
    status = Ap6256SdioRamRW(Ctx, FALSE, Address, (PUCHAR)Text, Length);
    Text[Length - 1] = 0;
    return status;
}

static VOID Ap6256PrepareFirmwareCrash(PAP6256_DEVICE_CONTEXT Ctx,
                                      UINT32 Mailbox, UINT32 InterruptStatus)
{
    AP6256_FW_CRASH* c = &Ctx->FirmwareCrash;
    KIRQL irql;
    RtlZeroMemory(c, sizeof(*c));
    c->Magic = AP6256_CRASH_MAGIC; c->Version = 1; c->Size = sizeof(*c);
    c->Mailbox = Mailbox; c->InterruptStatus = InterruptStatus;
    c->SharedAddress = Ctx->Chip.SharedAddress;
    c->SharedStatus = c->TrapStatus = c->ConsoleStatus = STATUS_PENDING;
    RtlCopyMemory(c->MacAddress, Ctx->MacAddress, sizeof(c->MacAddress));
    KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &irql);
    c->TxSeq = Ctx->Sdio.TxSeq; c->MaxTxSeq = Ctx->Sdio.MaxTxSeq;
    KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, irql);
    if (Ctx->Bcdc.Initialized) {
        KeAcquireSpinLock(&Ctx->Bcdc.ResponseLock, &irql);
        c->Command = Ctx->Bcdc.PendingCommand; c->IfIndex = Ctx->Bcdc.PendingIfIndex;
        c->Set = Ctx->Bcdc.PendingSet;
        c->RequestId = Ctx->Bcdc.Pending ? Ctx->Bcdc.PendingId : 0;
        RtlCopyMemory(c->Iovar, Ctx->Bcdc.PendingIovar, sizeof(c->Iovar));
        KeReleaseSpinLock(&Ctx->Bcdc.ResponseLock, irql);
    }
    TraceDiag("firmware halt: mailbox 0x%08X interrupt 0x%08X last cmd %u if %u set %u id %u iovar '%s' SDPCM seq %u max %u\n",
        c->Mailbox, c->InterruptStatus, c->Command, c->IfIndex, c->Set,
        c->RequestId, c->Iovar, c->TxSeq, c->MaxTxSeq);
}

static NTSTATUS Ap6256CrashReadTrap(PAP6256_DEVICE_CONTEXT Ctx,
                                   UINT32 Address, AP6256_FW_TRAP* Trap)
{
    ULONG offset;
    if ((Address & 3u) || !Ap6256CrashRamRange(Ctx, Address, sizeof(*Trap)))
        return STATUS_INVALID_ADDRESS;

    for (offset = 0; offset < sizeof(*Trap); offset += sizeof(UINT32)) {
        UINT32 value;
        NTSTATUS status = Ap6256SdioReadBackplane32(Ctx, Address + offset, &value);
        if (!NT_SUCCESS(status)) return status;
        RtlCopyMemory((PUCHAR)Trap + offset, &value, sizeof(value));
    }
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256CrashReadConsole(PAP6256_DEVICE_CONTEXT Ctx,
                                      UINT32 Address, PUCHAR Buffer, ULONG Length)
{
    ULONG offset = 0;
    if (!Length || !Ap6256CrashRamRange(Ctx, Address, Length))
        return STATUS_INVALID_ADDRESS;

    while (offset < Length) {
        UINT32 current = Address + offset;
        UINT32 aligned = current & ~3u;
        ULONG skip = current & 3u;
        ULONG count = min(Length - offset, sizeof(UINT32) - skip);
        UINT32 value;
        NTSTATUS status;
        if (!Ap6256CrashRamRange(Ctx, aligned, sizeof(value)))
            return STATUS_INVALID_ADDRESS;
        status = Ap6256SdioReadBackplane32(Ctx, aligned, &value);
        if (!NT_SUCCESS(status)) return status;
        RtlCopyMemory(Buffer + offset, (PUCHAR)&value + skip, count);
        offset += count;
    }
    return STATUS_SUCCESS;
}

static VOID Ap6256CaptureFirmwareCrash(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_FW_CRASH* c = &Ctx->FirmwareCrash;
    UINT32 console[3] = {0};
    ULONG n, start, offset, tail;
    CHAR part[257];
    c->TrapStatus = c->ConsoleStatus = STATUS_NOT_FOUND;
    if (!Ap6256CrashRamRange(Ctx, c->SharedAddress, sizeof(c->Shared))) {
        c->SharedStatus = STATUS_INVALID_ADDRESS;
        goto captured;
    }
    c->SharedStatus = Ap6256SdioRamRW(Ctx, FALSE, c->SharedAddress,
                                    (PUCHAR)&c->Shared, sizeof(c->Shared));
    if (!NT_SUCCESS(c->SharedStatus)) goto captured;
    if ((c->Shared.Flags & SDPCM_SHARED_VERSION_MASK) > SDPCM_SHARED_VERSION) {
        c->SharedStatus = STATUS_REVISION_MISMATCH;
        goto captured;
    }
    c->Valid |= AP6256_CRASH_SHARED;
    if (c->Shared.Flags & SDPCM_SHARED_TRAP) {
        c->TrapStatus = STATUS_INVALID_ADDRESS;
        if (Ap6256CrashRamRange(Ctx, c->Shared.TrapAddress, sizeof(c->Trap)))
            c->TrapStatus = Ap6256CrashReadTrap(Ctx, c->Shared.TrapAddress, &c->Trap);
        if (NT_SUCCESS(c->TrapStatus)) {
            c->Valid |= AP6256_CRASH_TRAP;
            TraceDiag("firmware trap: type %u epc 0x%08X pc 0x%08X lr 0x%08X sp 0x%08X cpsr 0x%08X spsr 0x%08X\n",
                c->Trap.Type, c->Trap.Epc, c->Trap.Pc, c->Trap.Lr, c->Trap.Sp,
                c->Trap.Cpsr, c->Trap.Spsr);
            TraceDiag("firmware trap: r0-r3 %08X %08X %08X %08X r4-r7 %08X %08X %08X %08X\n",
                c->Trap.Registers[0], c->Trap.Registers[1], c->Trap.Registers[2], c->Trap.Registers[3],
                c->Trap.Registers[4], c->Trap.Registers[5], c->Trap.Registers[6], c->Trap.Registers[7]);
        }
    }
    if (c->Shared.Flags & SDPCM_SHARED_ASSERT) {
        if (NT_SUCCESS(Ap6256CrashString(Ctx, c->Shared.AssertFileAddress,
                                        c->AssertFile, sizeof(c->AssertFile))))
            c->Valid |= AP6256_CRASH_FILE;
        if (NT_SUCCESS(Ap6256CrashString(Ctx, c->Shared.AssertExpressionAddress,
                                        c->AssertExpression, sizeof(c->AssertExpression))))
            c->Valid |= AP6256_CRASH_EXPRESSION;
        TraceDiag("firmware assert: %s:%u expression '%s' (file address 0x%08X expression address 0x%08X)\n",
            c->AssertFile, c->Shared.AssertLine, c->AssertExpression,
            c->Shared.AssertFileAddress, c->Shared.AssertExpressionAddress);
    }

    if (!Ap6256CrashRamRange(Ctx, c->Shared.ConsoleAddress, 8 + sizeof(console)))
        goto captured;
    c->ConsoleStatus = Ap6256CrashReadConsole(Ctx, c->Shared.ConsoleAddress + 8,
                                           (PUCHAR)console, sizeof(console));
    if (!NT_SUCCESS(c->ConsoleStatus)) goto captured;
    if (!console[1] || console[2] > console[1] ||
        !Ap6256CrashRamRange(Ctx, console[0], console[1])) {
        c->ConsoleStatus = STATUS_INVALID_ADDRESS;
        goto captured;
    }
    n = min(console[1], 2048u);
    tail = n - min(n, (ULONG)sizeof(c->Console) - 1);
    start = console[2] >= n ? console[2] - n : console[1] - (n - console[2]);
    for (offset = 0; offset < n;) {
        ULONG chunk = min(n - offset, min(256u, console[1] - start));
        ULONG skip = offset < tail ? min(chunk, tail - offset) : 0;
        if (!chunk || chunk >= sizeof(part) || skip > chunk) {
            c->ConsoleStatus = STATUS_INVALID_BUFFER_SIZE;
            goto captured;
        }
        RtlZeroMemory(part, sizeof(part));
        c->ConsoleStatus = Ap6256CrashReadConsole(Ctx, console[0] + start,
                                               (PUCHAR)part, chunk);
        if (!NT_SUCCESS(c->ConsoleStatus)) goto captured;
        part[chunk] = 0;
        TraceDiag("firmware console [%u/%u]: %s\n", offset, n, part);
        if (skip < chunk) {
            ULONG destination = offset + skip - tail;
            ULONG copy = chunk - skip;
            if (destination >= sizeof(c->Console) ||
                copy >= sizeof(c->Console) - destination ||
                skip >= sizeof(part) || copy > sizeof(part) - skip) {
                c->ConsoleStatus = STATUS_INVALID_BUFFER_SIZE;
                goto captured;
            }
            RtlCopyMemory(c->Console + destination, part + skip, copy);
        }
        offset += chunk; start += chunk;
        if (start == console[1]) start = 0;
    }
    c->ConsoleLength = n - tail; c->Valid |= AP6256_CRASH_CONSOLE;
captured:
    TraceDiag("firmware crash capture: valid 0x%X shared 0x%08X status 0x%08X flags 0x%08X trap address 0x%08X status 0x%08X console 0x%08X\n",
        c->Valid, c->SharedAddress, c->SharedStatus, c->Shared.Flags,
        c->Shared.TrapAddress, c->TrapStatus, c->ConsoleStatus);
}

_Use_decl_annotations_
VOID Ap6256FirmwareHalt(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Mailbox, UINT32 InterruptStatus)
{
    if (InterlockedCompareExchange(&Ctx->FirmwareHalted, 1, 0) != 0) return;
    Ap6256HostCipherStoreInvalidateAll(&Ctx->HostCipherStore);
    InterlockedExchange(&Ctx->HostCipherFirmwareQualified, 0);
    Ap6256FipsReset(Ctx);
    Ctx->FirmwareState = Ap6256FwError;
    Ap6256PrepareFirmwareCrash(Ctx, Mailbox, InterruptStatus);
    Ap6256ModelRecordFirmwareCrash(Ctx);

    Ap6256NetFirmwareHalted(Ctx);
    Ap6256BcdcFirmwareHalted(Ctx);
    Ap6256CaptureFirmwareCrash(Ctx);
    Ap6256ModelRecordFirmwareCrash(Ctx);
}

#define AP6256_FW_MAX_SIZE      (1u * 1024 * 1024)
#define AP6256_NVRAM_MAX_SIZE   (32u * 1024)
#define AP6256_CLM_MAX_SIZE     (64u * 1024)
#define AP6256_FW_READY_RETRIES  2000u

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256ReadArtifact(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCWSTR Suffix,
                                   _In_reads_(FallbackCount) PCWSTR* Fallbacks,
                                   _In_ ULONG FallbackCount, _In_ ULONG MaxSize,
                                   _Outptr_result_buffer_(*Length) PUCHAR* Buffer, _Out_ PULONG Length);

static volatile LONG Ap6256VolumeGone;

static BOOLEAN Ap6256StatusIsVolumeGone(_In_ NTSTATUS Status)
{
    return (BOOLEAN)(Status == STATUS_TOO_LATE ||
                     Status == STATUS_VOLUME_DISMOUNTED);
}

BOOLEAN Ap6256FirmwareVolumeGone(VOID)
{
    return (BOOLEAN)(InterlockedCompareExchange(&Ap6256VolumeGone, 0, 0) != 0);
}

static INT Ap6256HexNibble(_In_ UCHAR Character)
{
    if (Character >= '0' && Character <= '9') return Character - '0';
    if (Character >= 'a' && Character <= 'f') return Character - 'a' + 10;
    if (Character >= 'A' && Character <= 'F') return Character - 'A' + 10;
    return -1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256ReadFilePath(_In_ PCWSTR FullPath, _In_ ULONG MaxSize,
                                   _Outptr_result_buffer_(*Length) PUCHAR* Buffer,
                                   _Out_ PULONG Length)
{
    NTSTATUS status;
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES oa;
    HANDLE handle = NULL;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION fileInfo;
    PUCHAR data = NULL;
    ULONG size;
    WCHAR normalizedPath[520];
    PCWSTR ntPath = FullPath;

    *Buffer = NULL;
    *Length = 0;

    if (FullPath[0] != L'\0' && FullPath[1] == L':') {
        status = RtlStringCchPrintfW(normalizedPath,
                                     RTL_NUMBER_OF(normalizedPath),
                                     L"\\??\\%ws", FullPath);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        ntPath = normalizedPath;
    } else if (FullPath[0] == L'\\' && FullPath[1] == L'\\') {
        status = RtlStringCchPrintfW(normalizedPath,
                                     RTL_NUMBER_OF(normalizedPath),
                                     L"\\??\\UNC\\%ws", FullPath + 2);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        ntPath = normalizedPath;
    }

    RtlInitUnicodeString(&path, ntPath);
    InitializeObjectAttributes(&oa, &path,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = ZwCreateFile(&handle, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                          NULL, 0);
    if (!NT_SUCCESS(status)) {
        if (Ap6256StatusIsVolumeGone(status)) {

            if (InterlockedExchange(&Ap6256VolumeGone, 1) == 0) {
                TraceDiag("file system is gone (0x%08X opening '%ws'): the "
                          "system is shutting down, so no firmware can be "
                          "loaded and the chip will not be brought up\n",
                          status, FullPath);
            }
        } else {
            TraceWarn(TRACE_FIRMWARE, "open '%ws' failed 0x%08X\n",
                      FullPath, status);
        }
        return status;
    }

    status = ZwQueryInformationFile(handle, &iosb, &fileInfo, sizeof(fileInfo),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        goto done;
    }
    if (fileInfo.EndOfFile.QuadPart == 0 ||
        fileInfo.EndOfFile.QuadPart > MaxSize) {
        TraceError(TRACE_FIRMWARE, "'%ws' size %lld out of range\n",
                   FullPath, fileInfo.EndOfFile.QuadPart);
        status = STATUS_FILE_TOO_LARGE;
        goto done;
    }
    size = (ULONG)fileInfo.EndOfFile.QuadPart;

    data = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, size, AP6256_POOL_TAG);
    if (data == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    status = ZwReadFile(handle, NULL, NULL, NULL, &iosb, data, size, NULL, NULL);
    if (!NT_SUCCESS(status) || iosb.Information != size) {
        TraceError(TRACE_FIRMWARE, "read '%ws' failed 0x%08X (%Iu/%u)\n",
                   FullPath, status, iosb.Information, size);
        if (NT_SUCCESS(status)) status = STATUS_END_OF_FILE;
        ExFreePoolWithTag(data, AP6256_POOL_TAG);
        data = NULL;
        goto done;
    }

    *Buffer = data;
    *Length = size;
    status = STATUS_SUCCESS;
    TraceInfo(TRACE_FIRMWARE, "loaded '%ws' (%u bytes)\n", FullPath, size);

done:
    ZwClose(handle);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256ReadFile(_In_ PCWSTR FileName, _In_ ULONG MaxSize,
                               _Outptr_result_buffer_(*Length) PUCHAR* Buffer,
                               _Out_ PULONG Length)
{
    WCHAR pathBuf[256];
    NTSTATUS status = RtlStringCchPrintfW(pathBuf, RTL_NUMBER_OF(pathBuf),
                                          L"%ws\\%ws", AP6256_FW_DIR, FileName);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return Ap6256ReadFilePath(pathBuf, MaxSize, Buffer, Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256QueryPathOverride(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCWSTR ValueName,
                                        _Out_writes_z_(OutCch) PWSTR Out, _In_ ULONG OutCch)
{
    NTSTATUS status;
    UNICODE_STRING value;
    WCHAR tmp[520];

    Out[0] = L'\0';

    value.Buffer = tmp;
    value.Length = 0;
    value.MaximumLength = sizeof(tmp);
    status = Ap6256RegQueryUnicodeString(Ctx->Pdo, ValueName, &value);

    if (NT_SUCCESS(status) && value.Length != 0) {
        status = RtlStringCchCopyNW(Out, OutCch, value.Buffer, value.Length / sizeof(WCHAR));
    } else if (NT_SUCCESS(status)) {
        status = STATUS_OBJECT_NAME_NOT_FOUND;
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256LoadArtifact(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ PCWSTR OverrideValue, _In_ PCWSTR Suffix,
                                   _In_reads_(FallbackCount) PCWSTR* Fallbacks,
                                   _In_ ULONG FallbackCount, _In_ ULONG MaxSize,
                                   _Outptr_result_buffer_(*Length) PUCHAR* Buffer, _Out_ PULONG Length)
{
    WCHAR overridePath[520];

    if (NT_SUCCESS(Ap6256QueryPathOverride(Ctx, OverrideValue, overridePath, RTL_NUMBER_OF(overridePath)))) {
        NTSTATUS status;
        PWSTR lastSeparator = NULL;
        PWSTR cursor;

        for (cursor = overridePath; *cursor != L'\0'; cursor++) {
            if (*cursor == L'\\') {
                lastSeparator = cursor;
            }
        }

        if (lastSeparator != NULL && Ctx->Chip.ChipId != 0) {
            WCHAR chipPath[560];
            size_t directoryCch = (size_t)(lastSeparator - overridePath) + 1;

            if (directoryCch < RTL_NUMBER_OF(chipPath)) {
                RtlCopyMemory(chipPath, overridePath, directoryCch * sizeof(WCHAR));
                chipPath[directoryCch] = L'\0';
                status = RtlStringCchPrintfW(chipPath + directoryCch,
                                             RTL_NUMBER_OF(chipPath) - directoryCch,
                                             L"%04Xr%u%ws",
                                             Ctx->Chip.ChipId, Ctx->Chip.ChipRev,
                                             Suffix);
                if (NT_SUCCESS(status)) {
                    status = Ap6256ReadFilePath(chipPath, MaxSize, Buffer, Length);
                    if (NT_SUCCESS(status)) {
                        TraceInfo(TRACE_FIRMWARE,
                                  "using revision-exact artifact %ws\n", chipPath);
                        return status;
                    }
                }
            }
        }

        status = Ap6256ReadFilePath(overridePath, MaxSize, Buffer, Length);
        if (NT_SUCCESS(status)) {
            TraceInfo(TRACE_FIRMWARE, "using %ws override = %ws\n", OverrideValue, overridePath);
            return status;
        }
        TraceWarn(TRACE_FIRMWARE, "%ws override '%ws' unreadable, using defaults\n",
                  OverrideValue, overridePath);
    }
    return Ap6256ReadArtifact(Ctx, Suffix, Fallbacks, FallbackCount, MaxSize, Buffer, Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256ReadArtifact(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ PCWSTR Suffix,
                                   _In_reads_(FallbackCount) PCWSTR* Fallbacks,
                                   _In_ ULONG FallbackCount,
                                   _In_ ULONG MaxSize,
                                   _Outptr_result_buffer_(*Length) PUCHAR* Buffer,
                                   _Out_ PULONG Length)
{
    NTSTATUS status;
    WCHAR runtimeName[40];

    status = RtlStringCchPrintfW(runtimeName, RTL_NUMBER_OF(runtimeName),
                                 L"%04Xr%u%ws", Ctx->Chip.ChipId, Ctx->Chip.ChipRev, Suffix);
    if (NT_SUCCESS(status)) {
        status = Ap6256ReadFile(runtimeName, MaxSize, Buffer, Length);
        if (NT_SUCCESS(status)) {
            return status;
        }

        if (Ap6256StatusIsVolumeGone(status)) {
            return status;
        }
    }

    for (ULONG i = 0; i < FallbackCount; i++) {
        status = Ap6256ReadFile(Fallbacks[i], MaxSize, Buffer, Length);
        if (NT_SUCCESS(status)) {
            return status;
        }
        if (Ap6256StatusIsVolumeGone(status)) {
            return status;
        }
    }
    return STATUS_NOT_FOUND;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FirmwareQueryMacAddress(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                       _Out_writes_(6) PUCHAR MacAddress)
{
    static PCWSTR nvramFallbacks[] = {
                                       AP6256_FW_NVRAM_NAME, AP6256_FW_NVRAM_NAME_CY };
    static const UCHAR key[] = "macaddr=";
    PUCHAR nvram = NULL;
    ULONG nvramLength = 0;
    NTSTATUS status;
    ULONG offset;

    RtlZeroMemory(MacAddress, 6);

    status = Ap6256LoadArtifact(Ctx, L"SROMImagePath", AP6256_FW_NVRAM_SUFFIX,
                                nvramFallbacks, RTL_NUMBER_OF(nvramFallbacks),
                                AP6256_NVRAM_MAX_SIZE, &nvram, &nvramLength);
    if (!NT_SUCCESS(status)) return status;

    status = STATUS_NOT_FOUND;
    for (offset = 0; offset + sizeof(key) - 1 + 17 <= nvramLength; offset++) {
        ULONG index;
        UCHAR parsed[6];

        if (offset != 0 && nvram[offset - 1] != '\n' && nvram[offset - 1] != '\r') {
            continue;
        }
        if (RtlCompareMemory(nvram + offset, key, sizeof(key) - 1) != sizeof(key) - 1) {
            continue;
        }

        for (index = 0; index < RTL_NUMBER_OF(parsed); index++) {
            ULONG digit = offset + (ULONG)sizeof(key) - 1 + index * 3;
            INT high = Ap6256HexNibble(nvram[digit]);
            INT low = Ap6256HexNibble(nvram[digit + 1]);

            if (high < 0 || low < 0 || (index != 5 && nvram[digit + 2] != ':')) {
                break;
            }
            parsed[index] = (UCHAR)((high << 4) | low);
        }
        if (index == RTL_NUMBER_OF(parsed)) {
            BOOLEAN allZero = TRUE;
            BOOLEAN allOnes = TRUE;

            for (index = 0; index < RTL_NUMBER_OF(parsed); index++) {
                allZero = allZero && parsed[index] == 0;
                allOnes = allOnes && parsed[index] == 0xff;
            }
            if ((parsed[0] & 1) == 0 && !allZero && !allOnes) {
                RtlCopyMemory(MacAddress, parsed, sizeof(parsed));
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_ADDRESS;
            }
            break;
        }
        status = STATUS_DEVICE_DATA_ERROR;
        break;
    }

    ExFreePoolWithTag(nvram, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256NvramStrip(_In_reads_(InLen) PUCHAR In, _In_ ULONG InLen,
                                 _Outptr_result_buffer_(*OutLen) PUCHAR* Out, _Out_ PULONG OutLen)
{

    ULONG cap = InLen + 8;
    PUCHAR out = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, cap, AP6256_POOL_TAG);
    ULONG o = 0;
    ULONG i = 0;
    BOOLEAN lineHasContent = FALSE;

    *Out = NULL;
    *OutLen = 0;
    if (out == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (i < InLen && o < cap) {
        UCHAR c = In[i++];

        if (c == '\r') {
            continue;
        }
        if (c == '#') {
            while (i < InLen && In[i] != '\n') i++;
            continue;
        }
        if (c == '\n') {
            if (lineHasContent) {
                out[o++] = '\0';
                lineHasContent = FALSE;
            }
            continue;
        }
        if (c == ' ' || c == '\t') {
            if (!lineHasContent) continue;
        }
        out[o++] = c;
        lineHasContent = TRUE;
    }

    if (lineHasContent && o < cap) {
        out[o++] = '\0';
    }
    if (o < cap) {
        out[o++] = '\0';
    }

    while ((o & 3) && o < cap) {
        out[o++] = '\0';
    }

    *Out = out;
    *OutLen = o;
    return STATUS_SUCCESS;
}

static BOOLEAN Ap6256IsNvramLengthToken(_In_ UINT32 Value)
{
    return (UINT16)(~Value >> 16) == (UINT16)Value;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WaitForShared(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 address = 0;
    UINT32 sharedPointerAddress;
    UINT32 ramEnd;
    SDPCM_SHARED shared;
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    ULONG retry;

    if (Ctx->Chip.RamSize < sizeof(shared) + sizeof(UINT32) ||
        Ctx->Chip.RamBase > MAXUINT32 - Ctx->Chip.RamSize) {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    ramEnd = Ctx->Chip.RamBase + Ctx->Chip.RamSize;
    sharedPointerAddress = ramEnd - sizeof(UINT32);

    for (retry = 0; retry < AP6256_FW_READY_RETRIES; retry++) {
        status = Ap6256SdioRamRW(Ctx, FALSE, sharedPointerAddress,
                                 (PUCHAR)&address, sizeof(address));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        if (address != 0 && !Ap6256IsNvramLengthToken(address) &&
            address >= Ctx->Chip.RamBase &&
            address <= ramEnd - sizeof(shared)) {
            RtlZeroMemory(&shared, sizeof(shared));
            status = Ap6256SdioRamRW(Ctx, FALSE, address,
                                     (PUCHAR)&shared, sizeof(shared));
            if (!NT_SUCCESS(status)) {
                return status;
            }
            if ((shared.Flags & SDPCM_SHARED_VERSION_MASK) > SDPCM_SHARED_VERSION) {
                TraceError(TRACE_FIRMWARE,
                           "unsupported sdpcm_shared version %u at 0x%08X\n",
                           shared.Flags & SDPCM_SHARED_VERSION_MASK, address);
                return STATUS_REVISION_MISMATCH;
            }
            if ((shared.Flags & (SDPCM_SHARED_ASSERT | SDPCM_SHARED_TRAP)) != 0) {
                TraceError(TRACE_FIRMWARE,
                           "firmware failed during startup (shared flags=0x%08X)\n",
                           shared.Flags);
                return STATUS_DEVICE_HARDWARE_ERROR;
            }

            Ctx->Chip.SharedAddress = address;
            InterlockedExchange(&Ctx->FirmwareHalted, 0);
            status = Ap6256HostCipherFirmwareStarted(Ctx);
            if (!NT_SUCCESS(status)) return status;

            Ctx->Go.NativeStateUncertain = FALSE;

            RtlZeroMemory(Ctx->PowerSaveDx, sizeof(Ctx->PowerSaveDx));
            TraceInfo(TRACE_FIRMWARE,
                      "sdpcm_shared ready at 0x%08X (version %u)\n",
                      address, shared.Flags & SDPCM_SHARED_VERSION_MASK);
            return STATUS_SUCCESS;
        }

        {
            LARGE_INTEGER delay;
            delay.QuadPart = -(1 * 10 * 1000);
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
        }
    }

    TraceError(TRACE_FIRMWARE,
               "firmware did not publish sdpcm_shared (last=0x%08X)\n", address);
    return STATUS_DEVICE_NOT_READY;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FirmwareDownload(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    PUCHAR fw = NULL;        ULONG fwLen = 0;
    PUCHAR nvramRaw = NULL;  ULONG nvramRawLen = 0;
    PUCHAR nvram = NULL;     ULONG nvramLen = 0;
    UINT32 resetVector = 0;
    UINT32 varAddr, token, lastWord, ramEnd, nvramWords;
    BOOLEAN nativeManagementPatched = FALSE;
    BOOLEAN pnoDelayPatched = FALSE;
    BOOLEAN saePatched = FALSE;
    BOOLEAN ftPatched = FALSE;
    BOOLEAN owePatched = FALSE;
    BOOLEAN servicePatched = FALSE;
    BOOLEAN ftmPatched = FALSE;
    BOOLEAN hostCipherPatched = FALSE;

    static PCWSTR fwFallbacks[]    = {
                                       AP6256_FW_IMAGE_NAME, AP6256_FW_IMAGE_NAME_CY };
    static PCWSTR nvramFallbacks[] = {
                                       AP6256_FW_NVRAM_NAME, AP6256_FW_NVRAM_NAME_CY };

    Ctx->FirmwareState = Ap6256FwDownloading;
    Ap6256HostCipherFirmwareRetire(Ctx);
    Ap6256FipsReset(Ctx);
    Ctx->FirmwareEnhancedPnoSupported = FALSE;
    Ctx->FirmwarePnoDelaySupported = FALSE;
    Ctx->FirmwarePnoGscanSupported = FALSE;
    Ctx->FirmwareNativeManagement = FALSE;
    Ctx->FirmwareSaePatchVerified = FALSE;
    Ctx->FirmwareExternalAuth = FALSE;
    Ctx->FirmwarePrivateSaeAbi = FALSE;
    Ctx->FirmwarePrivateSae = FALSE;
    Ctx->FirmwareHostFt = FALSE;
    Ctx->FirmwareFtPatchVerified = FALSE;
    Ctx->FirmwareOwePatchVerified = FALSE;
    Ctx->FirmwareServicePatchVerified = FALSE;
    Ctx->FirmwareServiceOffload = FALSE;
    Ctx->FirmwareFtmPatchVerified = FALSE;
    Ctx->FirmwareFtmSupported = FALSE;
    Ctx->FirmwareHostCipherPatchVerified = FALSE;
    Ctx->FirmwareHostOwe = FALSE;
    Ctx->FirmwareOweGeneration = Ctx->FirmwareOweNextGeneration = 0;
    RtlZeroMemory(Ctx->FirmwareOwePeer, sizeof(Ctx->FirmwareOwePeer));
    Ctx->FirmwareBssTransitionEnabled = FALSE;

    status = Ap6256LoadArtifact(Ctx, L"DongleImagePath", AP6256_FW_RTECDC_SUFFIX, fwFallbacks,
                                RTL_NUMBER_OF(fwFallbacks), AP6256_FW_MAX_SIZE, &fw, &fwLen);
    if (!NT_SUCCESS(status)) {

        if (Ap6256StatusIsVolumeGone(status)) {
            TraceDiag("firmware not loaded: system is shutting down "
                      "(0x%08X)\n", status);
        } else {
            TraceError(TRACE_FIRMWARE,
                       "firmware image not found in configured or fallback "
                       "paths\n");
        }
        goto cleanup;
    }
    status = Ap6256LoadArtifact(Ctx, L"SROMImagePath", AP6256_FW_NVRAM_SUFFIX, nvramFallbacks,
                                RTL_NUMBER_OF(nvramFallbacks), AP6256_NVRAM_MAX_SIZE,
                                &nvramRaw, &nvramRawLen);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_FIRMWARE, "NVRAM not found in configured or fallback paths\n");
        goto cleanup;
    }

    if (Ctx->Chip.RamBase > MAXUINT32 - Ctx->Chip.RamSize) {
        status = STATUS_DEVICE_CONFIGURATION_ERROR;
        goto cleanup;
    }
    ramEnd = Ctx->Chip.RamBase + Ctx->Chip.RamSize;
    if (fwLen < sizeof(UINT32) || fwLen > Ctx->Chip.RamSize) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto cleanup;
    }

    resetVector = *(UINT32 UNALIGNED*)fw;

    Ap6256PnoIdentify(Ctx, fw, fwLen);
    status = Ap6256PrepareNativeManagement(Ctx, fw, fwLen, &nativeManagementPatched);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = Ap6256PnoPrepareInitialDelay(Ctx, fw, fwLen, &pnoDelayPatched);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = Ap6256PrepareSae(Ctx, &fw, &fwLen, &saePatched);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = Ap6256PrepareFt(Ctx, &fw, &fwLen, &ftPatched);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = Ap6256PrepareOwe(Ctx, &fw, &fwLen, &owePatched);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = Ap6256PrepareService(Ctx, &fw, &fwLen, &servicePatched);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = Ap6256PrepareFtm(Ctx, &fw, &fwLen, &ftmPatched);
    if (!NT_SUCCESS(status)) goto cleanup;
    status = Ap6256PrepareHostCiphers(Ctx, &fw, &fwLen, &hostCipherPatched);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = Ap6256ChipSetPassive(Ctx);
    if (!NT_SUCCESS(status)) goto cleanup;

    TraceInfo(TRACE_FIRMWARE, "writing %u bytes of firmware at 0x%06X\n", fwLen, Ctx->Chip.RamBase);
    status = Ap6256SdioRamRW(Ctx, TRUE, Ctx->Chip.RamBase, fw, fwLen);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_FIRMWARE, "firmware write failed 0x%08X\n", status);
        goto cleanup;
    }

    status = Ap6256NvramStrip(nvramRaw, nvramRawLen, &nvram, &nvramLen);
    if (!NT_SUCCESS(status)) goto cleanup;

    if (nvramLen > Ctx->Chip.RamSize - sizeof(UINT32)) {
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto cleanup;
    }
    varAddr = ramEnd - nvramLen - sizeof(UINT32);
    if (Ctx->Chip.RamBase + fwLen > varAddr) {
        TraceError(TRACE_FIRMWARE,
                   "firmware/NVRAM overlap (fw=%u nvram=%u ram=%u)\n",
                   fwLen, nvramLen, Ctx->Chip.RamSize);
        status = STATUS_INVALID_IMAGE_FORMAT;
        goto cleanup;
    }
    TraceInfo(TRACE_FIRMWARE, "writing %u bytes of NVRAM at 0x%06X\n", nvramLen, varAddr);
    status = Ap6256SdioRamRW(Ctx, TRUE, varAddr, nvram, nvramLen);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_FIRMWARE, "NVRAM write failed 0x%08X\n", status);
        goto cleanup;
    }

    nvramWords = nvramLen / sizeof(UINT32);
    token = (((~nvramWords) & 0x0000ffffu) << 16) |
            (nvramWords & 0x0000ffffu);
    lastWord = ramEnd - sizeof(UINT32);
    status = Ap6256SdioWriteBackplane32(Ctx, lastWord, token);
    if (!NT_SUCCESS(status)) goto cleanup;

    if (nativeManagementPatched) {
        status = servicePatched ? Ap6256VerifyNativeManagementImage(Ctx, fw, fwLen) :
            Ap6256VerifyNativeManagement(Ctx);
        if (!NT_SUCCESS(status)) goto cleanup;
    }
    if (pnoDelayPatched) {
        status = Ap6256PnoVerifyInitialDelay(Ctx);
        if (!NT_SUCCESS(status)) goto cleanup;
    }
    if (saePatched) {
        status = Ap6256VerifySae(Ctx, fw, fwLen);
        if (!NT_SUCCESS(status)) goto cleanup;
    }
    if (ftPatched) {
        status = Ap6256VerifyFt(Ctx, fw, fwLen);
        if (!NT_SUCCESS(status)) goto cleanup;
    }
    if (owePatched) {
        status = Ap6256VerifyOwe(Ctx, fw, fwLen);
        if (!NT_SUCCESS(status)) goto cleanup;
    }
    if (servicePatched) {
        status = Ap6256VerifyService(Ctx, fw, fwLen);
        if (!NT_SUCCESS(status)) goto cleanup;
    }
    if (ftmPatched) {
        status = Ap6256VerifyFtm(Ctx, fw, fwLen);
        if (!NT_SUCCESS(status)) goto cleanup;
    }
    if (hostCipherPatched) {
        status = Ap6256VerifyHostCiphers(Ctx, fw, fwLen);
        if (!NT_SUCCESS(status)) goto cleanup;
    }
    status = Ap6256ChipSetActive(Ctx, resetVector);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_FIRMWARE, "set active failed 0x%08X\n", status);
        goto cleanup;
    }

    status = Ap6256WaitForShared(Ctx);
    if (!NT_SUCCESS(status)) goto cleanup;

    status = Ap6256SdioEnableBackplaneClock(Ctx, TRUE);
    if (!NT_SUCCESS(status)) goto cleanup;

    Ctx->FirmwareState = Ap6256FwRunning;
    Ctx->FirmwarePnoDelaySupported = pnoDelayPatched;
    Ctx->FirmwareNativeManagement = nativeManagementPatched;
    Ctx->FirmwareSaePatchVerified = saePatched;
    Ctx->FirmwareFtPatchVerified = ftPatched;
    Ctx->FirmwareOwePatchVerified = owePatched;
    Ctx->FirmwareServicePatchVerified = servicePatched;
    Ctx->FirmwareFtmPatchVerified = ftmPatched;
    Ctx->FirmwareHostCipherPatchVerified = hostCipherPatched;
    if (nativeManagementPatched) {
        TraceDiag("native management: active RRM/Neighbor/BTM repair; "
                  "PMF validation retained, Windows station moves retained\n");
    }
    TraceInfo(TRACE_FIRMWARE, "firmware running\n");
    status = STATUS_SUCCESS;

cleanup:
    if (!NT_SUCCESS(status)) {
        Ctx->FirmwareState = Ap6256FwError;
        Ctx->FirmwareEnhancedPnoSupported = FALSE;
        Ctx->FirmwarePnoDelaySupported = FALSE;
        Ctx->FirmwarePnoGscanSupported = FALSE;
        Ctx->FirmwareNativeManagement = FALSE;
        Ctx->FirmwareSaePatchVerified = FALSE;
        Ctx->FirmwareHostFt = FALSE;
        Ctx->FirmwareFtPatchVerified = FALSE;
        Ctx->FirmwareOwePatchVerified = FALSE;
    Ctx->FirmwareServicePatchVerified = FALSE;
    Ctx->FirmwareServiceOffload = FALSE;
        Ctx->FirmwareFtmPatchVerified = FALSE;
        Ctx->FirmwareFtmSupported = FALSE;
        Ctx->FirmwareHostCipherPatchVerified = FALSE;
        Ctx->FirmwareHostOwe = FALSE;
        Ctx->FirmwareOweGeneration = Ctx->FirmwareOweNextGeneration = 0;
        RtlZeroMemory(Ctx->FirmwareOwePeer, sizeof(Ctx->FirmwareOwePeer));
        Ctx->FirmwareBssTransitionEnabled = FALSE;
    }
    if (fw)       ExFreePoolWithTag(fw, AP6256_POOL_TAG);
    if (nvramRaw) ExFreePoolWithTag(nvramRaw, AP6256_POOL_TAG);
    if (nvram)    ExFreePoolWithTag(nvram, AP6256_POOL_TAG);
    return status;
}

#pragma pack(push, 1)
typedef struct _CLM_DOWNLOAD_HEADER {
    UINT16 Flag;
    UINT16 DownloadType;
    UINT32 Length;
    UINT32 CrcReserved;
} CLM_DOWNLOAD_HEADER;
#pragma pack(pop)

#define CLM_DL_TYPE_CLM     2
#define CLM_DL_HANDLER_VERSION 1
#define CLM_DL_FLAG_BEGIN   0x0002
#define CLM_DL_FLAG_END     0x0004
#define CLM_CHUNK_SIZE      1400

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FirmwareLoadClm(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    PUCHAR clm = NULL; ULONG clmLen = 0;
    ULONG offset = 0;
    PUCHAR payload = NULL;
    static PCWSTR clmFallbacks[] = {
                                     AP6256_FW_CLM_NAME, AP6256_FW_CLM_NAME_CY };

    status = Ap6256LoadArtifact(Ctx, L"ClmImagePath", AP6256_FW_CLM_SUFFIX, clmFallbacks,
                                RTL_NUMBER_OF(clmFallbacks), AP6256_CLM_MAX_SIZE, &clm, &clmLen);
    if (!NT_SUCCESS(status)) {
        TraceInfo(TRACE_FIRMWARE, "no CLM blob; firmware built-in regulatory in use\n");
        return STATUS_SUCCESS;
    }

    payload = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                      sizeof(CLM_DOWNLOAD_HEADER) + CLM_CHUNK_SIZE,
                                      AP6256_POOL_TAG);
    if (payload == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    while (offset < clmLen) {
        CLM_DOWNLOAD_HEADER* hdr = (CLM_DOWNLOAD_HEADER*)payload;
        ULONG remaining = clmLen - offset;
        ULONG chunk = (remaining < CLM_CHUNK_SIZE) ? remaining : CLM_CHUNK_SIZE;
        UINT16 flag = CLM_DL_HANDLER_VERSION << 12;

        if (chunk > remaining) {
            chunk = remaining;
        }
        if (offset == 0)               flag |= CLM_DL_FLAG_BEGIN;
        if (offset + chunk >= clmLen)   flag |= CLM_DL_FLAG_END;

        RtlZeroMemory(hdr, sizeof(*hdr));
        hdr->Flag = flag;
        hdr->DownloadType = CLM_DL_TYPE_CLM;
        hdr->Length = chunk;

#pragma warning(suppress: 6385)
        RtlCopyMemory(payload + sizeof(*hdr), clm + offset, chunk);

        status = Ap6256BcdcSetIovar(Ctx, "clmload", payload, sizeof(*hdr) + chunk);
        if (!NT_SUCCESS(status)) {
            TraceError(TRACE_FIRMWARE, "clmload chunk @%u failed 0x%08X\n", offset, status);
            goto done;
        }
        offset += chunk;
    }

    TraceInfo(TRACE_FIRMWARE, "CLM blob loaded (%u bytes)\n", clmLen);
    status = STATUS_SUCCESS;

done:
    if (payload) ExFreePoolWithTag(payload, AP6256_POOL_TAG);
    if (clm)     ExFreePoolWithTag(clm, AP6256_POOL_TAG);
    return status;
}
