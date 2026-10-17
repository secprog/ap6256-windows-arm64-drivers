/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

OUTPUT_FORMAT(elf32-littlearm)
ENTRY(r9_nd_control)
SECTIONS { . = 0x215200; .text : { *(.text*) *(.rodata*) }
ASSERT(. <= 0x216800,"departure code crosses state reservation")
/DISCARD/ : { *(.ARM.exidx*) *(.ARM.extab*) *(.comment*) } }
