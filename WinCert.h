/*++ BUILD Version: 0001    Increment this if a change has global effects

Copyright (c) Yaron Aronsohn. 2010, All Rights Reserved.

Module Name:

    WinCert.h

Description:

    Master include file for Windows PE/PE+ digital signature verification library.

Revision:

    Rev     Date        Programmer          Revision History

--*/
#ifndef _WIN_CERT_H_
#define _WIN_CERT_H_

#include <sal.h>

#if !defined(WINTRUST_H) && !defined(_INTERNALS_WINDOWS_NT_TYPES_H_)
typedef struct _WIN_CERTIFICATE {
    DWORD       dwLength;
    WORD        wRevision;
    WORD        wCertificateType;
    BYTE        bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE, * LPWIN_CERTIFICATE;

#define WIN_CERT_REVISION_1_0               (0x0100)
#define WIN_CERT_REVISION_2_0               (0x0200)

#define WIN_CERT_TYPE_X509                  (0x0001)   // bCertificate contains an X.509 Certificate
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA      (0x0002)   // bCertificate contains a PKCS SignedData structure
#define WIN_CERT_TYPE_RESERVED_1            (0x0003)   // Reserved
#define WIN_CERT_TYPE_TS_STACK_SIGNED       (0x0004)   // Terminal Server Protocol Stack Certificate signing
#endif // !defined(WINTRUST_H) && !defined(_INTERNALS_WINDOWS_NT_TYPES_H_)

#ifndef __WINCRYPT_H__
typedef struct _CRYPTOAPI_BLOB {
    DWORD   cbData;
    BYTE* pbData;
} CRYPT_INTEGER_BLOB, * PCRYPT_INTEGER_BLOB,
CRYPT_UINT_BLOB, * PCRYPT_UINT_BLOB,
CRYPT_OBJID_BLOB, * PCRYPT_OBJID_BLOB,
CERT_NAME_BLOB, * PCERT_NAME_BLOB,
CERT_RDN_VALUE_BLOB, * PCERT_RDN_VALUE_BLOB,
CERT_BLOB, * PCERT_BLOB,
CRL_BLOB, * PCRL_BLOB,
DATA_BLOB, * PDATA_BLOB,
CRYPT_DATA_BLOB, * PCRYPT_DATA_BLOB,
CRYPT_HASH_BLOB, * PCRYPT_HASH_BLOB,
CRYPT_DIGEST_BLOB, * PCRYPT_DIGEST_BLOB,
CRYPT_DER_BLOB, * PCRYPT_DER_BLOB,
CRYPT_ATTR_BLOB, * PCRYPT_ATTR_BLOB;
#endif // __WINCRYPT_H__

#ifdef __cplusplus
extern "C" {
#endif

extern const LARGE_INTEGER WcHalfSecond;

__drv_allocatesMem(Mem)
_Post_writable_byte_size_(Bytes)
_Must_inspect_result_
PVOID
NTAPI
WcAllocateMemory(
    _In_ SIZE_T Bytes,
    _In_opt_ ULONG Tag
    );

VOID
NTAPI
WcFreeMemory(
    _Pre_notnull_ __drv_freesMem(P) PVOID Mem,
    _In_ ULONG Tag
    );

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyImageSignatureByHandle(
    _In_ HANDLE FileHandle
    );

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyImageSignature(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ BOOLEAN MappedAsImage
    );

#ifdef __cplusplus
}
#endif

#endif // _WIN_CERT_H_
