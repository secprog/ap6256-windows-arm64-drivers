/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#if defined(AP6256_ENABLE_WDI) || defined(AP6256_ENABLE_WIFICX) || !defined(AP6256_ALLOW_STUB_NETADAPTER)
#error "Select the explicit diagnostic configuration in the build."
#endif
#include <wdf.h>
