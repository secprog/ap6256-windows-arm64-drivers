/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include <ntddk.h>

static const ULONG AP6256_TLV_POOL_TAG = 0x74353641u;

void* __cdecl operator new(size_t Size) noexcept
{
    return ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, AP6256_TLV_POOL_TAG);
}

void* __cdecl operator new(size_t Size, ULONG_PTR AllocationContext) noexcept
{

    UNREFERENCED_PARAMETER(AllocationContext);
    return operator new(Size);
}

void __cdecl operator delete(void* Buffer) noexcept
{
    if (Buffer != nullptr) {
        ExFreePoolWithTag(Buffer, AP6256_TLV_POOL_TAG);
    }
}

void __cdecl operator delete[](void* Buffer) noexcept
{
    operator delete(Buffer);
}

void __cdecl operator delete(void* Buffer, size_t Size) noexcept
{

    UNREFERENCED_PARAMETER(Size);
    operator delete(Buffer);
}

void __cdecl operator delete[](void* Buffer, size_t Size) noexcept
{
    operator delete(Buffer, Size);
}
