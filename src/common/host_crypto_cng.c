/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#ifdef AP6256_HOST_CRYPTO_USER_TEST
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#else
#include <ntddk.h>
#endif
#include <bcrypt.h>
#include "host_crypto_cng.h"

#define HC_CNG_OBJECT_LIMIT 8192u

long Ap6256HostCryptoOpen(void** Provider, AP6256_HC_U32* KeyObjectBytes)
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_AUTH_TAG_LENGTHS_STRUCT tags = {0};
    ULONG bytes = 0, size = 0, flags = 0;
    NTSTATUS status;
    if (Provider) *Provider = NULL;
    if (KeyObjectBytes) *KeyObjectBytes = 0;
    if (!Provider || !KeyObjectBytes) return STATUS_INVALID_PARAMETER;
#ifndef AP6256_HOST_CRYPTO_USER_TEST
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
    flags = BCRYPT_PROV_DISPATCH;
#endif
    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM,
        MS_PRIMITIVE_PROVIDER, flags);
    if (status < 0) return status;
    status = BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0) goto fail;
    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&size, sizeof(size), &bytes, 0);
    if (status < 0) goto fail;
    if (bytes != sizeof(size) || !size || size > HC_CNG_OBJECT_LIMIT) {
        status = STATUS_NOT_SUPPORTED; goto fail;
    }
    status = BCryptGetProperty(algorithm, BCRYPT_AUTH_TAG_LENGTH,
        (PUCHAR)&tags, sizeof(tags), &bytes, 0);
    if (status < 0) goto fail;
    if (bytes != sizeof(tags) || tags.dwMinLength > 16 || tags.dwMaxLength < 16 ||
        (tags.dwIncrement && (16 - tags.dwMinLength) % tags.dwIncrement)) {
        status = STATUS_NOT_SUPPORTED; goto fail;
    }
    *Provider = algorithm; *KeyObjectBytes = size; return STATUS_SUCCESS;
fail:
    BCryptCloseAlgorithmProvider(algorithm, 0); return status;
}

long Ap6256HostCryptoClose(void* Provider)
{
#ifndef AP6256_HOST_CRYPTO_USER_TEST
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
#endif
    return Provider ? BCryptCloseAlgorithmProvider(Provider, 0) : STATUS_INVALID_PARAMETER;
}

long Ap6256HostCryptoFingerprint(const AP6256_HC_U8 Key[32], AP6256_HC_U8 Digest[32])
{
    BCRYPT_ALG_HANDLE algorithm = NULL;
    NTSTATUS status;
    if (!Key || !Digest) return STATUS_INVALID_PARAMETER;
    RtlSecureZeroMemory(Digest, 32);
#ifndef AP6256_HOST_CRYPTO_USER_TEST
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
#endif
    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM,
        MS_PRIMITIVE_PROVIDER, 0);
    if (status < 0) return status;
    status = BCryptHash(algorithm, NULL, 0, (PUCHAR)Key, 32, Digest, 32);
    (VOID)BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) RtlSecureZeroMemory(Digest, 32);
    return status;
}

long Ap6256HostCryptoCreateKey(void* Provider, const AP6256_HC_U8 Key[32],
    AP6256_HC_U8* Object, AP6256_HC_U32 ObjectBytes, void** Handle)
{
    NTSTATUS status;
    if (Handle) *Handle = NULL;
    if (!Provider || !Key || !Object || !ObjectBytes || ObjectBytes > HC_CNG_OBJECT_LIMIT ||
        !Handle) return STATUS_INVALID_PARAMETER;
#ifndef AP6256_HOST_CRYPTO_USER_TEST
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
#endif
    RtlSecureZeroMemory(Object, ObjectBytes);
    status = BCryptGenerateSymmetricKey(Provider, (BCRYPT_KEY_HANDLE*)Handle,
        Object, ObjectBytes, (PUCHAR)Key, 32, 0);
    if (status < 0) {
        *Handle = NULL; RtlSecureZeroMemory(Object, ObjectBytes);
    }
    return status;
}

long Ap6256HostCryptoDestroyKey(void* Handle, AP6256_HC_U8* Object,
    AP6256_HC_U32 ObjectBytes)
{
    NTSTATUS status;
    if (!Handle || !Object || !ObjectBytes || ObjectBytes > HC_CNG_OBJECT_LIMIT)
        return STATUS_INVALID_PARAMETER;
#ifndef AP6256_HOST_CRYPTO_USER_TEST
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_DEVICE_STATE;
#endif
    status = BCryptDestroyKey(Handle);
    if (status >= 0) RtlSecureZeroMemory(Object, ObjectBytes);
    return status;
}

int Ap6256HostCryptoCrypt(void* Context, int Encrypt,
    const AP6256_HC_U8 Nonce[12], const AP6256_HC_U8* Aad,
    AP6256_HC_U32 AadLength, const AP6256_HC_U8* Input,
    AP6256_HC_U32 InputLength, AP6256_HC_U8* Output, AP6256_HC_U8 Tag[16])
{
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    ULONG written = 0;
    NTSTATUS status;
    if (!Context || !Nonce || !Tag || (Encrypt != 0 && Encrypt != 1) ||
        AadLength > AP6256_HC_MAX_FRAME || InputLength > AP6256_HC_MAX_FRAME ||
        (AadLength && !Aad) || (InputLength && (!Input || !Output))) return 0;
#ifndef AP6256_HOST_CRYPTO_USER_TEST
    if (KeGetCurrentIrql() > DISPATCH_LEVEL) return 0;
#endif
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)Nonce; info.cbNonce = 12;
    info.pbAuthData = (PUCHAR)Aad; info.cbAuthData = AadLength;
    info.pbTag = Tag; info.cbTag = 16;
    if (Encrypt) {
        status = BCryptEncrypt(Context, (PUCHAR)Input, InputLength, &info,
            NULL, 0, Output, InputLength, &written, 0);
    } else {
        status = BCryptDecrypt(Context, (PUCHAR)Input, InputLength, &info,
            NULL, 0, Output, InputLength, &written, 0);
    }
    return status >= 0 && written == InputLength;
}
