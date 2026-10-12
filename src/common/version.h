/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#ifndef __AP6256_VERSION_H__
#define __AP6256_VERSION_H__

#ifdef AP6256_BUILD_VERSION_GENERATED
#include "ap6256_build_version.h"
#else
#define AP6256_VER_MAJOR  1
#define AP6256_VER_MINOR  0
#define AP6256_VER_BUILD  0
#define AP6256_VER_REV   0
#endif

#define AP6256_VER_STR__(a, b, c, d)  #a "." #b "." #c "." #d
#define AP6256_VER_STR_(a, b, c, d)   AP6256_VER_STR__(a, b, c, d)
#define AP6256_VER_STR                                                       \
    AP6256_VER_STR_(AP6256_VER_MAJOR, AP6256_VER_MINOR, AP6256_VER_BUILD,    \
                    AP6256_VER_REV)

#endif
