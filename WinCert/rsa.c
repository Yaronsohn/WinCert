/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include "WinCerti.h"

/* FUNCTIONS ******************************************************************/

enum {
    RSAPublicKey_Modulus = 0,
    RSAPublicKey_Exponent,
    RSAPublicKey_Max
};

static
NTSTATUS
RSAParseRSAPublicKey(
    _In_ REFBLOB Data,
    _Out_ PASN1_VALUE Values
    )
{
    static const ASN1_VALUE_DECRIPTOR RSAPublicKeyDescription[] = {
        // 0 -RSAPublicKey ::= ASN1_TAG_SEQUENCE {
        0, 0, ASN1_TAG_SEQUENCE, -1,

            // 0.0 - modulus INTEGER,    -- n
            1, 0, ASN1_TAG_INTEGER, RSAPublicKey_Modulus,

            // 0.1 - publicExponent  INTEGER (0..4294967295) -- e
            1, 0, ASN1_TAG_INTEGER, RSAPublicKey_Exponent,
    };

    return Asn1Decode(Data,
                      RSAPublicKeyDescription,
                      RTL_NUMBER_OF(RSAPublicKeyDescription),
                      Values);
}

NTSTATUS
RSABuildPubKey(
    _In_ REFBLOB RSAPubKey,
    _Out_ PBLOB RSAKeyBlob
    )
{
    BLOB Modulus;
    BLOB Exp;
    PBYTE ptr;
    ASN1_VALUE RSAPubKeyValues[RSAPublicKey_Max] = { 0 };
    NTSTATUS Status;

    Status = RSAParseRSAPublicKey(RSAPubKey, RSAPubKeyValues);
    if (!NT_SUCCESS(Status))
        return Status;

    Modulus = RSAPubKeyValues[RSAPublicKey_Modulus].Data;
    BlobSkip(&Modulus, 0);

    if (!Modulus.cbSize)
        return STATUS_ASN1_DECODING_ERROR;

    Exp = RSAPubKeyValues[RSAPublicKey_Exponent].Data;
    BlobSkip(&Exp, 0);

    if (!Exp.cbSize)
        return STATUS_ASN1_DECODING_ERROR;

    Status = BlobAlloc(RSAKeyBlob,
                       sizeof(BCRYPT_RSAKEY_BLOB) + Exp.cbSize + Modulus.cbSize);
    if (!NT_SUCCESS(Status))
        return STATUS_INSUFFICIENT_RESOURCES;

    ptr = RSAKeyBlob->pBlobData;

    ((BCRYPT_RSAKEY_BLOB*)ptr)->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    ((BCRYPT_RSAKEY_BLOB*)ptr)->BitLength = Modulus.cbSize * 8;
    ((BCRYPT_RSAKEY_BLOB*)ptr)->cbModulus = Modulus.cbSize;
    ((BCRYPT_RSAKEY_BLOB*)ptr)->cbPublicExp = Exp.cbSize;
    ((BCRYPT_RSAKEY_BLOB*)ptr)->cbPrime1 = 0;
    ((BCRYPT_RSAKEY_BLOB*)ptr)->cbPrime2 = 0;
    ptr += sizeof(BCRYPT_RSAKEY_BLOB);

    RtlCopyMemory(ptr, Exp.pBlobData, Exp.cbSize);
    ptr += Exp.cbSize;

    RtlCopyMemory(ptr, Modulus.pBlobData, Modulus.cbSize);
    return STATUS_SUCCESS;
}