/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "kmdf_driver.h"

_Use_decl_annotations_
NTSTATUS Ap6256ModelDeviceInitConfig(PWDFDEVICE_INIT DeviceInit)
{
    UNREFERENCED_PARAMETER(DeviceInit);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256ModelDeviceCreateAdapter(PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256ModelHardwareReady(PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    return STATUS_SUCCESS;
}
