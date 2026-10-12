/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "kmdf_driver.h"
#include "../common/netadapter.h"

_Use_decl_annotations_
NTSTATUS Ap6256ModelDeviceInitConfig(PWDFDEVICE_INIT DeviceInit)
{
    return Ap6256NetDeviceInitConfig(DeviceInit);
}

_Use_decl_annotations_
NTSTATUS Ap6256ModelDeviceCreateAdapter(PAP6256_DEVICE_CONTEXT Ctx)
{
    return Ap6256NetAdapterCreate(Ctx);
}
