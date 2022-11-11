/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#define INITBLOB

#include <ntifs.h>
#include <windef.h>
#include "WinCerti.h"

/* GLOBALS ********************************************************************/

// 1.3.14.3.2.26
DEFINE_BLOB(SHA1_OID, 0x2B, 0x0E, 0x03, 0x02, 0x1A)

// 2.16.840.1.101.3.4.2.1
DEFINE_BLOB(SHA256_OID, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b)

// 1.2.840.113549.2.2
DEFINE_BLOB(MD2_OID, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02)

// 1.2.840.113549.2.5
DEFINE_BLOB(MD5_OID, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05)

static const BLOB* const oids[] = {
    &SHA1_OID,
    &SHA256_OID,
    &MD2_OID,
    &MD5_OID
};

static const LPCWSTR AlgorithmNames[] = {
    BCRYPT_SHA1_ALGORITHM,
    BCRYPT_SHA256_ALGORITHM,
    BCRYPT_MD2_ALGORITHM,
    BCRYPT_MD5_ALGORITHM,
};
C_ASSERT(RTL_NUMBER_OF(AlgorithmNames) == AlgorithmMax);

/* FUNCTIONS ******************************************************************/

LPCWSTR
NTAPI
HashGetAlgorithmName(
    _In_ ALGORITHM_ID AlgId
    )
{
    ASSERT(AlgId < 0 || AlgId >= AlgorithmMax);

    if (AlgId < 0 || AlgId >= AlgorithmMax)
        return NULL;

    return AlgorithmNames[AlgId];
}

ALGORITHM_ID
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
    ALGORITHM_ID id;

    for (id = 0; id < RTL_NUMBER_OF(oids); id++) {
        if (IsEqualBLOB(oids[id], ObjectIdentifier))
            return id;
    }

    return InvalidAlgorithm;
}

NTSTATUS
HashData(
    _In_ ALGORITHM_ID AlgId,
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
        Status = BCryptOpenAlgorithmProvider(&AlgorithmHandle,
                                             HashGetAlgorithmName(AlgId),
                                             NULL,
                                             0);
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
