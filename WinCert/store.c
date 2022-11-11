/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include "WinCerti.h"

/* GLOBALS ********************************************************************/

const UNICODE_STRING RootStore = RTL_CONSTANT_STRING(L"ROOT");
static const UNICODE_STRING CertificatesPath =
    RTL_CONSTANT_STRING(L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\SystemCertificates\\");
static const UNICODE_STRING CertificatesSubKey = RTL_CONSTANT_STRING(L"\\Certificates");
static const UNICODE_STRING BlobValueName = RTL_CONSTANT_STRING(L"Blob");

/* FUNCTIONS ******************************************************************/

//
// Windows stores the certificates in the registry as part of a Type/Length list
// of values in one big blob.
// Each value starts with FILE_ELEMENT_HDR structure that indicates the type and
// length of the value.
// WinCrypt.h contains most of the types for these value, with a notable omission
// of values 32 to 35 (basically what we're interested in.
//
#include <pshpack1.h>
typedef struct _FILE_ELEMENT_HDR {
    DWORD dwEleType;
    DWORD dwEncodingType;
    DWORD dwLen;
} FILE_ELEMENT_HDR, * PFILE_ELEMENT_HDR;
#include <poppack.h>

#define FILE_ELEMENT_CERT_TYPE          32
#define FILE_ELEMENT_CRL_TYPE           33
#define FILE_ELEMENT_CTL_TYPE           34
#define FILE_ELEMENT_KEYID_TYPE         35

#ifndef UNICODE_STRING_MAX_BYTES
#define UNICODE_STRING_MAX_BYTES ((WORD)65534) 
#endif

static
NTSTATUS
StoreAllocateUnicodeString(
    _Out_ PUNICODE_STRING UnicodeString,
    _In_ SIZE_T Length
    )
{
    if (Length >= UNICODE_STRING_MAX_BYTES)
        return STATUS_NAME_TOO_LONG;

    UnicodeString->Buffer = WcAllocateMemory((USHORT)Length, 'grtS');
    if (!UnicodeString->Buffer)
        return STATUS_INSUFFICIENT_RESOURCES;

    UnicodeString->Length = 0;
    UnicodeString->MaximumLength = (USHORT)Length;
    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
StoreOpen(
    _Out_ PHANDLE StoreHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ const UNICODE_STRING* Store
    )
{
    UNICODE_STRING ObjectName;
    OBJECT_ATTRIBUTES ObjectAttributes;
    NTSTATUS Status;

    if (!Store) {
        Store = &RootStore;
    }

    Status = StoreAllocateUnicodeString(&ObjectName,
                                        CertificatesPath.Length +
                                        Store->Length +
                                        CertificatesSubKey.Length +
                                        sizeof(UNICODE_NULL));
    if (!NT_SUCCESS(Status))
        return Status;

    RtlCopyUnicodeString(&ObjectName, &CertificatesPath);
    RtlAppendUnicodeStringToString(&ObjectName, Store);
    RtlAppendUnicodeStringToString(&ObjectName, &CertificatesSubKey);

    InitializeObjectAttributes(&ObjectAttributes,
                               &ObjectName,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               0,
                               NULL);
    Status = ZwOpenKey(StoreHandle,
                       DesiredAccess,
                       &ObjectAttributes);
    RtlFreeUnicodeString(&ObjectName);
    return Status;
}

static
NTSTATUS
StoreFindElement(
    _In_ REFBLOB StoreCertificate,
    _In_ DWORD ElmType,
    _Out_ PBLOB Element
    )
{
    PFILE_ELEMENT_HDR ElmHdr = (PFILE_ELEMENT_HDR)StoreCertificate->pBlobData;
    ULONG Remaining = StoreCertificate->cbSize;

    while (Remaining >= sizeof(FILE_ELEMENT_HDR)) {
        Remaining -= sizeof(FILE_ELEMENT_HDR);
        if (Remaining < ElmHdr->dwLen)
            return STATUS_BAD_DATA;

        if (ElmHdr->dwEleType == ElmType) {
            Element->cbSize = ElmHdr->dwLen;
            Element->pBlobData = (PBYTE)(ElmHdr + 1);
            return STATUS_SUCCESS;
        }

        ElmHdr = (PFILE_ELEMENT_HDR)RtlOffsetToPointer(ElmHdr, sizeof(FILE_ELEMENT_HDR) + ElmHdr->dwLen);
    }

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

#define CERT_ALLOC_TAG      'rtS'

static
NTSTATUS
StoreQueryCertificateBlobValue(
    _Out_ PKEY_VALUE_PARTIAL_INFORMATION* ValueInfo,
    _In_ HANDLE CertKeyHandle
    )
{
    NTSTATUS Status;
    ULONG Length = 0;
    ULONG ResultLength;

    *ValueInfo = NULL;

    for (;;) {
        Status = ZwQueryValueKey(CertKeyHandle,
                                 (PUNICODE_STRING)&BlobValueName,
                                 KeyValuePartialInformation,
                                 *ValueInfo,
                                 Length,
                                 &ResultLength);
        if (NT_SUCCESS(Status))
            return Status;

        if (*ValueInfo) {
            WcFreeMemory(*ValueInfo, CERT_ALLOC_TAG);
            *ValueInfo = NULL;
        }

        if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
            return Status;

        *ValueInfo = WcAllocateMemory(ResultLength, CERT_ALLOC_TAG);
        if (*ValueInfo == NULL)
            return STATUS_INSUFFICIENT_RESOURCES;

        Length = ResultLength;
    }
}

_Must_inspect_result_
NTSTATUS
NTAPI
StoreOpenCertificateByName(
    _Out_ PBLOB Certificate,
    _In_ HANDLE StoreHandle,
    _In_ const UNICODE_STRING* Name
    )
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo;
    BLOB StoreBlob;
    BLOB Elm;
    HANDLE CertKeyHandle;

    InitializeObjectAttributes(&ObjectAttributes,
                               (PUNICODE_STRING)Name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               StoreHandle,
                               NULL);
    Status = ZwOpenKey(&CertKeyHandle,
                       KEY_QUERY_VALUE,
                       &ObjectAttributes);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = StoreQueryCertificateBlobValue(&ValueInfo, CertKeyHandle);
    ZwClose(CertKeyHandle);
    if (!NT_SUCCESS(Status))
        return Status;

    StoreBlob.cbSize = ValueInfo->DataLength;
    StoreBlob.pBlobData = ValueInfo->Data;

    Status = StoreFindElement(&StoreBlob, FILE_ELEMENT_CERT_TYPE, &Elm);
    if (!NT_SUCCESS(Status))
        goto Leave;

    Status = BlobAlloc(Certificate, Elm.cbSize);
    if (!NT_SUCCESS(Status))
        goto Leave;

    RtlCopyMemory(Certificate->pBlobData, Elm.pBlobData, Elm.cbSize);

Leave:
    WcFreeMemory(ValueInfo, CERT_ALLOC_TAG);
    return Status;
}
