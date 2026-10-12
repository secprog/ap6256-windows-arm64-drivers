/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

typedef struct _AP6256_FW_TRAP {
    UINT32 Type, Epc, Cpsr, Spsr, Registers[13], Sp, Lr, Pc;
} AP6256_FW_TRAP;

typedef struct _AP6256_FW_CRASH {
    UINT32 Magic, Version, Size, Valid;
    UINT32 Mailbox, InterruptStatus, SharedAddress;
    NTSTATUS SharedStatus, TrapStatus, ConsoleStatus;
    UINT32 Command, IfIndex, Set, RequestId;
    CHAR Iovar[32];
    UCHAR MacAddress[6], TxSeq, MaxTxSeq;
    SDPCM_SHARED Shared;
    AP6256_FW_TRAP Trap;
    CHAR AssertFile[80], AssertExpression[80];
    UINT32 ConsoleLength;
    CHAR Console[320];
} AP6256_FW_CRASH;

#define AP6256_CRASH_MAGIC 0x31435241u
#define AP6256_CRASH_SHARED 1u
#define AP6256_CRASH_TRAP 2u
#define AP6256_CRASH_FILE 4u
#define AP6256_CRASH_EXPRESSION 8u
#define AP6256_CRASH_CONSOLE 16u
C_ASSERT(sizeof(AP6256_FW_CRASH) <= 1024);
