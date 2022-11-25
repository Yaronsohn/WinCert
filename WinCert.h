/*++ BUILD Version: 0001    Increment this if a change has global effects

Copyright (c) 2022 Yaron Aronsohn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Module Name:

    WinCert.h

Description:

    Master include file for Windows signature verification library.

--*/
#ifndef _WIN_CERT_H_
#define _WIN_CERT_H_

#include <sal.h>
#include "blob.h"
#include "wcstatus.h"
#include "wcdef.h"

#ifdef __cplusplus
extern "C" {
#endif

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
Asn1DecodeValue(
    _In_ REFBLOB Data,
    _Out_ PASN1_VALUE Value
    );

_Must_inspect_result_
NTSTATUS
NTAPI
Asn1Decode(
    _In_ REFBLOB Data,
    _In_count_(DescriptorCount) const ASN1_VALUE_DECRIPTOR* Descriptors,
    _In_ ULONG DescriptorCount,
    _Out_ PASN1_VALUE Values
    );

_Must_inspect_result_
BOOLEAN
NTAPI
IsEqualAsn1Value(
    _In_ const ASN1_VALUE* Target,
    _In_ const ASN1_VALUE* Comparand
    );

#ifdef __cplusplus
#define BlobSkipAsn1Value(blob, value) \
    BlobSkipBlob(blob, (value).Raw)

FORCEINLINE
ULONG64
Asn1ReadInteger(
    _In_ REFBLOB Value
    )
{
    BLOB Data = Value;
    ULONG64 v = 0;
    while (Data.cbSize--) {
        v = (v << 8) | *Data.pBlobData++;
    }

    return v;
}

FORCEINLINE
BOOLEAN
Asn1ReadBoolean(
    _In_ REFBLOB Value
    )
{
    BLOB Data = Value;
    while (Data.cbSize--) {
        if (*Data.pBlobData++)
            return TRUE;
    }

    return FALSE;
}
#else
#define BlobSkipAsn1Value(blob, value) \
    BlobSkipBlob(blob, &(value)->Raw)

FORCEINLINE
ULONG64
Asn1ReadInteger(
    _In_ REFBLOB Value
    )
{
    BLOB Data = *((PBLOB)Value);
    ULONG64 v = 0;
    while (Data.cbSize--) {
        v = (v << 8) | *Data.pBlobData++;
    }

    return v;
}

FORCEINLINE
BOOLEAN
Asn1ReadBoolean(
    _In_ REFBLOB Value
    )
{
    BLOB Data = *((PBLOB)Value);
    while (Data.cbSize--) {
        if (*Data.pBlobData++)
            return TRUE;
    }

    return FALSE;
}
#endif

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyData(
    _In_reads_(Size) const VOID* Data,
    _In_ SIZE_T Size,
    _In_ DWORD DataType,
    _Out_opt_ PULONG ReturnedDataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyFileByHandle(
    _In_ HANDLE FileHandle,
    _In_ DWORD DataType,
    _Out_opt_ PULONG ReturnedDataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyImageSignature(
    _In_ const VOID* ImageBase,
    _In_ SIZE_T ImageSize,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyCertificate(
    _In_ const VOID* BaseAddress,
    _In_ SIZE_T Size,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );

//
// Certificate Store
//
typedef enum _STORE_CATAGORY {
    CertificateCatagry = 0,
    CRLCatagory,
    MaxCatagory
} STORE_CATAGORY;

#if defined(_NTDEF_) || defined(_WINTERNL_) 
_Must_inspect_result_
NTSTATUS
NTAPI
StoreOpen(
    _Out_ PHANDLE StoreHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ const UNICODE_STRING* Store,
    _In_ STORE_CATAGORY Catagory
    );
#endif // defined(_NTDEF_) || defined(_WINTERNL_) 

/*++
_Must_inspect_result_
NTSTATUS
NTAPI
StoreClose(
    _In_ HANDLE StoreHandle
    );
--*/
#define StoreClose(StoreHandle) ZwClose(StoreHandle)

#if defined(_NTDEF_) || defined(_WINTERNL_)
_Must_inspect_result_
NTSTATUS
NTAPI
StoreOpenCertificateByName(
    _Out_ PBLOB Certificate,
    _In_ HANDLE StoreHandle,
    _In_ const UNICODE_STRING* Name
    );
#endif // defined(_NTDEF_) || defined(_WINTERNL_)

#if defined(_NTDEF_) || defined(_WINTERNL_)
typedef
BOOLEAN
(NTAPI* PSTORE_ENUM_ROUTINE)(
    _In_ HANDLE StoreHandle,
    _In_ const VOID* Information,
    _In_ ULONG Length,
    _In_opt_ PVOID Context,
    _Out_ PNTSTATUS ReturnStatus
    );
#endif // defined(_NTDEF_) || defined(_WINTERNL_)

#if defined(_WDMDDK_)
_Must_inspect_result_
NTSTATUS
NTAPI
StoreEnum(
    _In_opt_ const UNICODE_STRING* Store,
    _In_ ULONG StoreCount,
    _In_ KEY_INFORMATION_CLASS KeyInformationClass,
    _In_ PSTORE_ENUM_ROUTINE EnumRoutine,
    _In_opt_ PVOID Context,
    _In_ STORE_CATAGORY Catagory
    );
#endif // _WDMDDK_

#ifdef __cplusplus
}
#endif

#endif // _WIN_CERT_H_
