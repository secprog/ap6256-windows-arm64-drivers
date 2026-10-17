/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ft_firmware.h"

_Use_decl_annotations_
NTSTATUS Ap6256PrepareFt(PAP6256_DEVICE_CONTEXT Ctx,
    PUCHAR* Image, PULONG Length, BOOLEAN* Applied)
{
    *Applied = FALSE;
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Image);
    UNREFERENCED_PARAMETER(Length);
    return STATUS_SUCCESS;
}

#include "owe_firmware.h"

_Use_decl_annotations_
NTSTATUS Ap6256PrepareOwe(PAP6256_DEVICE_CONTEXT Ctx,
    PUCHAR* Image, PULONG Length, BOOLEAN* Applied)
{
    *Applied = FALSE;
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Image);
    UNREFERENCED_PARAMETER(Length);
    return STATUS_SUCCESS;
}
