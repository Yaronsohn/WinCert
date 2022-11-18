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

    WinCerti.h

Description:

    Internal include file for Windows PE/PE+ digital signature verification library.

Revision:

    Rev     Date        Programmer          Revision History

--*/
#ifndef WIN_CERT_INTERNAL_H_
#define WIN_CERT_INTERNAL_H_

#include <ntifs.h>
#include <windef.h>
#include "../WinCert.h"
#include <bcrypt.h>

#ifdef __cplusplus
extern "C" {
#endif

    //////////////////////////
#include <stdio.h>

    __forceinline void printblob(REFBLOB blob) {
        int len = 0;
        char* ch = "0123456789ABCDEF";
        for (unsigned int i = 0; i < blob->cbSize; i++) {
            putchar(ch[(blob->pBlobData[i] >> 4) & 0xF]);
            putchar(ch[blob->pBlobData[i] & 0xF]);
            if (++len >= 16) {
                putchar('\n');
                len = 0;
            }
        }

        putchar('\n');
        putchar('\n');
    }
    /////////////////////////////

#ifndef LDR_IS_DATAFILE
#define LDR_IS_DATAFILE(x)      (((ULONG_PTR)(x)) &  (ULONG_PTR)1)
#endif

#ifndef LDR_DATAFILE_TO_VIEW
#define LDR_DATAFILE_TO_VIEW(x) ((PVOID)(((ULONG_PTR)(x)) & ~(ULONG_PTR)1))
#endif

NTSYSAPI
_Must_inspect_result_
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID Base
    );

NTSYSAPI
_Must_inspect_result_
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    _In_ PVOID Base,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size
    );

VOID
NTAPI
WcQuerySystemTime(
    _Out_ PLARGE_INTEGER SystemTime
    );

_Must_inspect_result_
NTSTATUS
Pkcs7Verify(
    _In_ REFBLOB Data,
    _In_count_(Count) const BLOB DataToHash[],
    _In_ ULONG Count,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );

enum {
    IndirectData_Type = 0,
    IndirectData_Algorithm,
    IndirectData_Parameters,
    IndirectData_Digest,
    IndirectData_Max
};

enum {
    SignedData_Version = 0,
    SignedData_DigestAlgorithmIdentifier,
    SignedData_ContentType,
    SignedData_Content,
    SignedData_Certificates,
    SignedData_Crls,
    SignedData_SignerInfo,
    SignedData_SignerInfo_Version,
    SignedData_SignerInfo_Issuer,
    SignedData_SignerInfo_SerialNumber,
    SignedData_SignerInfo_DigestAlgId,
    SignedData_SignerInfo_AuthAttr,
    SignedData_SignerInfo_DigestEncrAlgoId,
    SignedData_SignerInfo_EncrDigest,
    SignedData_SignerInfo_UnauthAttr,
    SignedData_Max
};

enum {
    Pkcs7_OID = 0,
    Pkcs7_SignedData,
    Pkcs7_Max
};

_Must_inspect_result_
LPCWSTR
NTAPI
HashDecodeAlgorithmIdentifier(
    _In_ REFBLOB ObjectIdentifier
    );

_Must_inspect_result_
NTSTATUS
HashData(
    _In_ LPCWSTR AlgId,
    _In_ ULONG Count,
    _In_count_(Count) const BLOB* Data,
    _Out_ PBLOB Hash
    );

_Must_inspect_result_
NTSTATUS
HashVerifySignedHash(
    _In_ LPCWSTR AlgId,
    _In_ REFBLOB Hash,
    _In_ REFBLOB Signature,
    _In_ REFBLOB PublicKeyInfo
    );

//
// Certificates routines
//
typedef enum {
    Certificate_ToBeSigned = 0,
    Certificate_Version,
    Certificate_SerialNumber,
    Certificate_AlgorithmIdentifier,
    Certificate_Issuer,
    Certificate_NotBefore,
    Certificate_NotAfter,
    Certificate_Subject,
    Certificate_SubjectPublicKeyInfo,
    Certificate_IssuerUniqueId,
    Certificate_SubjectUniqueId,
    Certificate_Extensions,
    Certificate_SignatureAlgorithm,
    Certificate_Signature,
    Certificate_Max
} CERTIFICATE_VALUE;

typedef struct _CERT_VALUES {
    BLOB Raw;
    ASN1_VALUE Values[Certificate_Max];
} CERT_VALUES, * PCERT_VALUES;

typedef struct _CERT_EXTENSION {
    BLOB Raw;
    BLOB Id;
    BOOLEAN Critical;
    BLOB Value;
} CERT_EXTENSION, *PCERT_EXTENSION;

_Must_inspect_result_
NTSTATUS
X509ParseCertificate(
    _In_ REFBLOB Data,
    _Out_ PCERT_VALUES CertValues
    );

_Must_inspect_result_
NTSTATUS
X509VerifyCertificate(
    _In_ const CERT_VALUES* Certificate,
    _In_opt_count_(Count) const CERT_VALUES* CertificateList,
    _In_ ULONG Count,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );

_Must_inspect_result_
NTSTATUS
X520Check(
    _In_ REFBLOB Data,
    _In_ const WIN_CERT_X520* Comparand,
    _In_ NTSTATUS MismatchStatus
    );

#ifndef HASH_MAX_LENGTH
#define HASH_MAX_LENGTH     64
#endif

#ifndef CERT_CHAIN_MAX
#define CERT_CHAIN_MAX      16
#endif

enum {
    PublicKeyInfo_AlgorithmId = 0,
    PublicKeyInfo_PublicKey,
    PublicKeyInfo_Max
};

_Must_inspect_result_
NTSTATUS
RSABuildPubKey(
    _In_ REFBLOB RSAPubKey,
    _Out_ PBLOB RSAKeyBlob
    );

_Must_inspect_result_
NTSTATUS
BlobAlloc(
    _Out_ PBLOB Blob,
    _In_ SIZE_T Size
    );

VOID
BlobFree(
    _Inout_ PBLOB Blob
    );

_Must_inspect_result_
NTSTATUS
Base64Decode(
    _In_ PCCHAR In,
    _In_ SIZE_T Count,
    _In_ BOOLEAN Strict,
    _Out_ PBLOB Data
    );

#ifdef __cplusplus
}
#endif

#endif // WIN_CERT_INTERNAL_H_
