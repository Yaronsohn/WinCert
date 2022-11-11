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

NTSTATUS
Pkcs7Parse(
    _In_ REFBLOB Data
    );

enum {
    IndirectData_Type = 0,
    IndirectData_Algorithm,
    IndirectData_Parameters,
    IndirectData_Hash,
    IndirectData_Max
};

enum {
    SignedData_Version = 0,
    SignedData_DigestAlgorithmIdentifier,
    SignedData_ContentType,
    SignedData_Content,
    SignedData_Certificates,
    SignedData_Crls,
    SignedData_SignerInfos,
    SignedData_SignerInfos_Version,
    SignedData_SignerInfos_Issuer,
    SignedData_SignerInfos_SerialNumber,
    SignedData_SignerInfos_DigestAlgId,
    SignedData_SignerInfos_AuthAttr,
    SignedData_SignerInfos_DigestEncrAlgoId,
    SignedData_SignerInfos_EncrDigest,
    SignedData_SignerInfos_UnauthAttr,
    SignedData_Max
};

enum {
    Authenticode_OID = 0,
    Authenticode_SignedData,
    Authenticode_Max
};

typedef enum _ALGORITHM_ID {
    InvalidAlgorithm = -1,
    SHA1,
    SHA256,
    MD2,
    MD5,
    AlgorithmMax
} ALGORITHM_ID;

LPCWSTR
NTAPI
HashGetAlgorithmName(
    _In_ ALGORITHM_ID AlgId
    );

ALGORITHM_ID
NTAPI
HashDecodeAlgorithmIdentifier(
    _In_ REFBLOB ObjectIdentifier
    );

NTSTATUS
HashData(
    _In_ ALGORITHM_ID AlgId,
    _In_ ULONG Count,
    _In_count_(Count) const BLOB* Data,
    _Out_ PBLOB Hash
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

NTSTATUS
NTAPI
CertParseCertificate(
    _In_ REFBLOB Data,
    _Out_ PCERT_VALUES CertValues
    );

const CERT_VALUES*
CertFindCertificate(
    _In_ REFBLOB Issuer,
    _In_opt_ const BLOB* SerialNumber,
    _In_count_(CertCount) const CERT_VALUES* Certificates,
    _In_ ULONG CertCount
    );

NTSTATUS
CertVerifyCertificate(
    _In_ const CERT_VALUES* Certificate,
    _In_count_(Count) const CERT_VALUES* CertificateList,
    _In_ ULONG Count
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

enum {
    RSAPublicKey_Modulus = 0,
    RSAPublicKey_Exponent,
    RSAPublicKey_Max
};

NTSTATUS
RSABuildPubKeyContent(
    _In_ REFBLOB RSAPubKey,
    _Out_ PBLOB RSAKeyBlob
    );

NTSTATUS
BlobAlloc(
    _Out_ PBLOB Blob,
    _In_ SIZE_T Size
    );

VOID
BlobFree(
    _Inout_ PBLOB Blob
    );

#ifdef __cplusplus
}
#endif

#endif // WIN_CERT_INTERNAL_H_
