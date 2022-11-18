/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#define INITBLOB

#include <ntifs.h>
#include <windef.h>
#include "WinCerti.h"

/* GLOBALS ********************************************************************/

// 1.3.14.3.2.26
DEFINE_BLOB(OID_OIWSEC_SHA1, 0x2B, 0x0E, 0x03, 0x02, 0x1A)

// 1.2.840.113549.2.2
DEFINE_BLOB(OID_RSA_MD2, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02)

// 1.2.840.113549.2.5
DEFINE_BLOB(OID_RSA_MD5, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05)

//
// Signarture Algorithm Identifier OIDs
//

// 1.2.840.113549.1.1.4
DEFINE_BLOB(OID_RSA_MD5RSA, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04)

// 1.2.840.113549.1.1.5
DEFINE_BLOB(OID_RSA_SHA1RSA, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05)

// 2.16.840.113549.1.1.11
DEFINE_BLOB(OID_OIWSEC_SHA256RSA, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b)

// 2.16.840.113549.1.1.12
DEFINE_BLOB(OID_OIWSEC_SHA384RSA, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c)

// 2.16.840.113549.1.1.13
DEFINE_BLOB(OID_OIWSEC_SHA512RSA, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d)

// 2.16.840.1.101.3.4.2.1
DEFINE_BLOB(OID_MD_SHA256, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)

// 2.16.840.1.101.3.4.2.2
DEFINE_BLOB(OID_MD_SHA384, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02)

// 2.16.840.1.101.3.4.2.2
DEFINE_BLOB(OID_MD_SHA512, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03)

// 1.3.14.3.2.29
DEFINE_BLOB(OID_OIWSEC_SHA1RSA, 0x2B, 0x0E, 0x03, 0x02, 0x1D)

// 1.3.14.3.2.15
DEFINE_BLOB(OID_OIWSEC_SHARSA, 0x2B, 0x0E, 0x03, 0x02, 0x0F)

// 1.3.14.3.2.3
DEFINE_BLOB(OID_OIWSEC_MD5RSA, 0x2B, 0x0E, 0x03, 0x02, 0x03)

// 1.2.840.113549.1.1.2
DEFINE_BLOB(OID_RSA_MD2RSA, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02)

// 1.3.14.7.2.3.1
DEFINE_BLOB(OID_OIWDIR_MD2RSA, 0x2B, 0x0E, 0x07, 0x02, 0x03, 0x01)

static const struct {
    REFBLOB Oid;
    LPCWSTR AlgId;
} HashAlgorithmTable[] = {
    &OID_OIWSEC_SHA1,       BCRYPT_SHA1_ALGORITHM,
    &OID_RSA_MD2,           BCRYPT_MD2_ALGORITHM,
    &OID_RSA_MD5,           BCRYPT_MD5_ALGORITHM,

    &OID_RSA_MD5RSA,        BCRYPT_MD5_ALGORITHM,
    &OID_RSA_SHA1RSA,       BCRYPT_SHA1_ALGORITHM,
    &OID_OIWSEC_SHA1RSA,    BCRYPT_SHA1_ALGORITHM,
    &OID_OIWSEC_SHARSA,     BCRYPT_SHA1_ALGORITHM,
    &OID_OIWSEC_MD5RSA,     BCRYPT_MD5_ALGORITHM,
    &OID_RSA_MD2RSA,        BCRYPT_MD2_ALGORITHM,
    &OID_OIWDIR_MD2RSA,     BCRYPT_MD2_ALGORITHM,
    &OID_OIWSEC_SHA256RSA,  BCRYPT_SHA256_ALGORITHM,
    &OID_OIWSEC_SHA384RSA,  BCRYPT_SHA384_ALGORITHM,
    &OID_OIWSEC_SHA512RSA,  BCRYPT_SHA512_ALGORITHM,

    &OID_MD_SHA256,         BCRYPT_SHA256_ALGORITHM,
    &OID_MD_SHA384,         BCRYPT_SHA384_ALGORITHM,
    &OID_MD_SHA512,         BCRYPT_SHA512_ALGORITHM,
};

// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1
DEFINE_BLOB(OID_RSA_ENC, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01)

/* FUNCTIONS ******************************************************************/

_Must_inspect_result_
LPCWSTR
NTAPI
HashDecodeAlgorithmIdentifier(
    _In_ REFBLOB ObjectIdentifier
    )
/*++

Routine Description:

    This function checks the given object identifier and return the name of the
    algorthm it represents.

Arguments:

    ObjectIdentifier - Describes the object identifier to check.

Return Value:

    Null-terminate string with the name of the algorithm. The string is
    compatible with the BCRYPT 

--*/
{
    ULONG id;

    for (id = 0; id < RTL_NUMBER_OF(HashAlgorithmTable); id++) {
        if (IsEqualBLOB(HashAlgorithmTable[id].Oid, ObjectIdentifier))
            return HashAlgorithmTable[id].AlgId;
    }

    return NULL;
}

_Must_inspect_result_
NTSTATUS
HashData(
    _In_ LPCWSTR AlgId,
    _In_ ULONG Count,
    _In_count_(Count) const BLOB* Data,
    _Out_ PBLOB Hash
    )
{
    NTSTATUS Status;
    BCRYPT_ALG_HANDLE AlgorithmHandle = NULL;
    PVOID HashObj = NULL;
    DWORD HashObjSize;
    DWORD ReturnedLength;
    BCRYPT_HASH_HANDLE HashHandle = NULL;

    __try {
        Status = BCryptOpenAlgorithmProvider(&AlgorithmHandle, AlgId, NULL, 0);
        if (!NT_SUCCESS(Status))
            __leave;

        Status = BCryptGetProperty(AlgorithmHandle,
                                   BCRYPT_OBJECT_LENGTH,
                                   (PCHAR)&HashObjSize,
                                   sizeof(HashObjSize),
                                   &ReturnedLength,
                                   0);
        if (!NT_SUCCESS(Status))
            __leave;

        HashObj = WcAllocateMemory(HashObjSize, 'OhsH');
        if (!HashObj)
            __leave;

        Status = BCryptCreateHash(AlgorithmHandle,
                                  &HashHandle,
                                  HashObj,
                                  HashObjSize,
                                  NULL,
                                  0,
                                  0);
        if (!NT_SUCCESS(Status))
            __leave;

        while (Count--) {
            Status = BCryptHashData(HashHandle,
                                    (PUCHAR)Data->pBlobData,
                                    (ULONG)Data->cbSize,
                                    0);
            if (!NT_SUCCESS(Status))
                __leave;

            Data++;
        }

        Status = BCryptGetProperty(AlgorithmHandle,
                                   BCRYPT_HASH_LENGTH,
                                   (PCHAR)&Hash->cbSize,
                                   sizeof(Hash->cbSize),
                                   &ReturnedLength,
                                   0);
        if (!NT_SUCCESS(Status))
            __leave;

        Status = BlobAlloc(Hash, Hash->cbSize);
        if (!NT_SUCCESS(Status))
            __leave;

        Status = BCryptFinishHash(HashHandle,
                                  Hash->pBlobData,
                                  Hash->cbSize,
                                  0);
        if (!NT_SUCCESS(Status)) {
            BlobFree(Hash);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    if (HashHandle) {
        BCryptDestroyHash(HashHandle);
    }

    if (HashObj) {
        WcFreeMemory(HashObj, 'OhsH');
    }

    if (AlgorithmHandle) {
        BCryptCloseAlgorithmProvider(AlgorithmHandle, 0);
    }

    return Status;
}

_Must_inspect_result_
NTSTATUS
HashVerifySignedHash(
    _In_ LPCWSTR AlgId,
    _In_ REFBLOB Hash,
    _In_ REFBLOB Signature,
    _In_ REFBLOB PublicKeyInfo
    )
{
    static const ASN1_VALUE_DECRIPTOR PublicKeyInfoDescription[] = {
        // 0 - SubjectPublicKeyInfo :: = SEQUENCE
        0, 0, ASN1_TAG_SEQUENCE, -1,

            // 0.0 - rsaEncryption ::= SEQUENCE 
            1, 0, ASN1_TAG_SEQUENCE, -1,

                // 0.0.0 - rsaEncryption OID
                2, 0, ASN1_TAG_OID, PublicKeyInfo_AlgorithmId,

            // 0.1 - subjectPublicKey    BITSTRING
            1, 0, ASN1_TAG_BITSTRING, PublicKeyInfo_PublicKey,
    };
    NTSTATUS Status;
    BCRYPT_ALG_HANDLE AlgorithmHandle = 0;
    BCRYPT_KEY_HANDLE KeyHandle = 0;
    BLOB ReversedSignature = { 0 };
    BCRYPT_PKCS1_PADDING_INFO PaddingInfo = { 0 };
    ASN1_VALUE PublicKeyValues[PublicKeyInfo_Max] = { 0 };
    BLOB RSAPublicKey = { 0 };

    Status = Asn1Decode(PublicKeyInfo,
                        PublicKeyInfoDescription,
                        RTL_NUMBER_OF(PublicKeyInfoDescription),
                        PublicKeyValues);
    if (!NT_SUCCESS(Status))
        return Status;

    if (!IsEqualBLOB(&OID_RSA_ENC, &PublicKeyValues[PublicKeyInfo_AlgorithmId].Data))
        return STATUS_NOT_SUPPORTED;

    Status = BCryptOpenAlgorithmProvider(&AlgorithmHandle,
                                         BCRYPT_RSA_ALGORITHM,
                                         NULL,
                                         0);
    if (!NT_SUCCESS(Status))
        return Status;

    __try {
        Status = RSABuildPubKey(&PublicKeyValues[PublicKeyInfo_PublicKey].Data,
                                &RSAPublicKey);
        if (!NT_SUCCESS(Status))
            __leave;

        if (((BCRYPT_RSAKEY_BLOB*)RSAPublicKey.pBlobData)->cbModulus == Signature->cbSize) {
            Status = BCryptImportKeyPair(AlgorithmHandle,
                                         NULL,
                                         BCRYPT_RSAPUBLIC_BLOB,
                                         &KeyHandle,
                                         RSAPublicKey.pBlobData,
                                         RSAPublicKey.cbSize,
                                         0);
        }
        else {
            Status = STATUS_ASN1_DECODING_ERROR;
        }

        if (!NT_SUCCESS(Status))
            __leave;

        PaddingInfo.pszAlgId = AlgId;

        Status = BCryptVerifySignature(KeyHandle,
                                       &PaddingInfo,
                                       Hash->pBlobData,
                                       Hash->cbSize,
                                       Signature->pBlobData,
                                       Signature->cbSize,
                                       BCRYPT_PAD_PKCS1);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    BlobFree(&RSAPublicKey);

    if (KeyHandle) {
        BCryptDestroyKey(KeyHandle);
    }

    BCryptCloseAlgorithmProvider(AlgorithmHandle, 0);

    return Status;
}