/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#define INITBLOB

#include "WinCerti.h"

// iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) 1
DEFINE_BLOB(OID_RSA_ENC, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01)

/* FUNCTIONS ******************************************************************/

#define CERT_MEM_TAG        'treC'

#ifndef CERT_CHAIN_MAX_ATTEMPTS
#define CERT_CHAIN_MAX_ATTEMPTS 16
#endif

NTSTATUS
NTAPI
CertParseCertificate(
    _In_ REFBLOB Data,
    _Out_ PCERT_VALUES CertValues
    )
{
    static const ASN1_VALUE_DECRIPTOR CertificateDescription[] = {
        // 0 - Certificate  ::=  SEQUENCE  {
        ADF_STEPIN | ADF_STEPOUT, ASN1_TAG_SEQUENCE, -1,

            // 0.0 - toBeSigned ::== SEQUENCE {
            ADF_STEPIN, ASN1_TAG_SEQUENCE, Certificate_ToBeSigned,

                // 0.0.0 - version [0] EXPLICIT CertificateVersion DEFAULT v1,
                ADF_STEPIN | ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), -1,

                    // 0.0.0.0 - version number INTEGER
                    ADF_STEPOUT, ASN1_TAG_INTEGER, Certificate_Version,

                // 0.0.1 - serialNumber CertificateSerialNumber,
                0, ASN1_TAG_INTEGER, Certificate_SerialNumber,

                // 0.0.2 - signature ::= SEQUENCE {
                ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

                    // 0.0.2.0
                    ADF_STEPOUT, ASN1_TAG_OID, Certificate_AlgorithmIdentifier,

                // 0.0.3 - issuer
                0, ASN1_TAG_SEQUENCE, Certificate_Issuer,

                // 0.0.4 - validity - Validity
                ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

                    // 0.0.4.0
                    0, ASN1_TAG_UTCTIME, Certificate_NotBefore,

                    // 0.0.4.1
                    ADF_STEPOUT, ASN1_TAG_UTCTIME, Certificate_NotAfter,

                // 0.0.5 - subject
                0, ASN1_TAG_SEQUENCE, Certificate_Subject,

                // 0.0.6 - subjectPublicKeyInfo SubjectPublicKeyInfo
                0, ASN1_TAG_SEQUENCE, Certificate_SubjectPublicKeyInfo,

                // 0.0.7 - issuerUniqueIdentifier [1] IMPLICIT BITSTRING OPTIONAL
                ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 1), Certificate_IssuerUniqueId,

                // 0.0.8 - subjectUniqueIdentifier [2] IMPLICIT BITSTRING OPTIONAL
                ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 2), Certificate_SubjectUniqueId,

                // 0.0.9 - extensions [3] EXPLICIT Extensions OPTIONAL
                ADF_OPTIONAL | ADF_STEPOUT, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 3), Certificate_Extensions,

            // 0.1 - signatureAlgorithm  AlgorithmIdentifier,
            ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

            // 0.1.0
            ADF_STEPOUT, ASN1_TAG_OID, Certificate_SignatureAlgorithm,

            // 0.2 - signature           BITSTRING
            ADF_STEPOUT, ASN1_TAG_BITSTRING, Certificate_Signature
    };

    CertValues->Raw = *Data;
    return Asn1Decode(Data,
                      CertificateDescription,
                      RTL_NUMBER_OF(CertificateDescription),
                      CertValues->Values);
}

const CERT_VALUES*
CertFindCertificateBySubject(
    _In_ REFBLOB Subject,
    _In_count_(CertCount) const CERT_VALUES* Certificates,
    _In_ ULONG CertCount
    )
{
    const CERT_VALUES* cert;

    if (Subject->cbSize == 0)
        return NULL;

    while (CertCount--) {
        cert = Certificates++;
        if (IsEqualBLOB(&cert->Values[Certificate_Subject].Data, Subject))
            return cert;
    }

    return NULL;
}

/*++
BOOLEAN
CertIsSelfSignedCertificate(
    _In_ const CERT_VALUES* Certificate
    );
--*/
#define CertIsSelfSignedCertificate(Certificate) \
    IsEqualBLOB(&Certificate->Values[Certificate_Subject].Data, \
        &Certificate->Values[Certificate_Issuer].Data)

static
NTSTATUS
CertFindRoot(
    _In_opt_ const UNICODE_STRING* Store,
    _In_ REFBLOB Comparator,
    _In_ CERTIFICATE_VALUE CertValue,
    _Out_ PCERT_VALUES Certificate
    )
{
    NTSTATUS Status;
    ULONG Index = 0;
    PKEY_BASIC_INFORMATION BasicInfo = NULL;
    ULONG Length = 0;
    ULONG ResultLength;
    UNICODE_STRING Name;
    BLOB Blob;
    HANDLE StoreHandle;

    Status = StoreOpen(&StoreHandle,
                       KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                       Store);
    if (!NT_SUCCESS(Status))
        return Status;

    for (;;) {
        Status = ZwEnumerateKey(StoreHandle,
                                Index,
                                KeyBasicInformation,
                                BasicInfo,
                                Length,
                                &ResultLength);
        if (NT_SUCCESS(Status)) {
            Name.MaximumLength = Name.Length = (USHORT)BasicInfo->NameLength;
            Name.Buffer = BasicInfo->Name;

            //
            // N.B. We do NOT fail the whole process if we failed
            // to open one certificate
            //
            Status = StoreOpenCertificateByName(&Blob, StoreHandle, &Name);
            if (NT_SUCCESS(Status)) {
                RtlZeroMemory(Certificate, sizeof(*Certificate));
                printblob(&Blob);
                Status = CertParseCertificate(&Blob, Certificate);
                if (NT_SUCCESS(Status)) {
                    if (IsEqualBLOB(Comparator, &Certificate->Values[CertValue].Data))
                        break;
                }

                BlobFree(&Blob);
            }

            Index++;
            continue;
        }

        if (BasicInfo) {
            WcFreeMemory(BasicInfo, CERT_MEM_TAG);
            BasicInfo = NULL;
        }

        if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
            break;

        BasicInfo = WcAllocateMemory(ResultLength, CERT_MEM_TAG);
        if (!BasicInfo) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        Length = ResultLength;
    }

    StoreClose(StoreHandle);
    return Status;
}

static
NTSTATUS
CertParsePublicKeyInfo(
    _In_ REFBLOB Data,
    _Out_ PASN1_VALUE Values
    )
{
    static const ASN1_VALUE_DECRIPTOR PublicKeyInfoDescription[] = {
        // 0 - SubjectPublicKeyInfo :: = SEQUENCE
        ADF_STEPIN | ADF_STEPOUT, ASN1_TAG_SEQUENCE, -1,

            // 0.0 - rsaEncryption ::= SEQUENCE 
            ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

                // 0.0.0 - rsaEncryption OID
                ADF_STEPOUT, ASN1_TAG_OID, PublicKeyInfo_AlgorithmId,

            // 0.1 - subjectPublicKey    BITSTRING
            ADF_STEPOUT, ASN1_TAG_BITSTRING, PublicKeyInfo_PublicKey,
    };

    return Asn1Decode(Data,
                      PublicKeyInfoDescription,
                      RTL_NUMBER_OF(PublicKeyInfoDescription),
                      Values);
}

NTSTATUS
CertVerifySignedHash(
    _In_ ALGORITHM_ID AlgId,
    _In_ REFBLOB Hash,
    _In_ REFBLOB Signature,
    _In_ REFBLOB PublicKeyInfo
    )
{
    NTSTATUS Status;
    BCRYPT_ALG_HANDLE AlgorithmHandle = 0;
    BCRYPT_KEY_HANDLE KeyHandle = 0;
    BLOB ReversedSignature = { 0 };
    BCRYPT_PKCS1_PADDING_INFO PaddingInfo = { 0 };
    ASN1_VALUE PublicKeyValues[PublicKeyInfo_Max] = { 0 };
    BLOB RSAPublicKey = { 0 };

    Status = CertParsePublicKeyInfo(PublicKeyInfo, PublicKeyValues);
    if (!NT_SUCCESS(Status))
        return Status;

    if (!IsEqualBLOB(&OID_RSA_ENC, &PublicKeyValues[PublicKeyInfo_AlgorithmId].Data))
        return STATUS_ALGORITHM_NOT_SUPPORTED;

    Status = BCryptOpenAlgorithmProvider(&AlgorithmHandle,
                                         BCRYPT_RSA_ALGORITHM,
                                         NULL,
                                         0);
    if (!NT_SUCCESS(Status))
        return Status;

    __try {
        Status = RSABuildPubKeyContent(&PublicKeyValues[PublicKeyInfo_PublicKey].Data,
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
            Status = STATUS_INVALID_SIGNATURE;
        }

        if (!NT_SUCCESS(Status))
            __leave;

        PaddingInfo.pszAlgId = HashGetAlgorithmName(AlgId);

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

NTSTATUS
CertVerifyCertificate(
    _In_ const CERT_VALUES* Certificate,
    _In_count_(Count) const CERT_VALUES* CertificateList,
    _In_ ULONG Count
    )
{
    ALGORITHM_ID AlgId;
    BLOB Hash;
    const CERT_VALUES* Subject = Certificate;
    NTSTATUS Status;
    const CERT_VALUES* Issuer;
    ULONG Attempts = 0;
    CERT_VALUES Root;

    for (;;) {
        AlgId = HashDecodeAlgorithmIdentifier(&Subject->Values[Certificate_SignatureAlgorithm].Data);
        if (AlgId == InvalidAlgorithm)
            return STATUS_ALGORITHM_NOT_SUPPORTED;

        if (CertIsSelfSignedCertificate(Subject)) {
            //
            // Because we've reached the end of the chain, check if this certificate
            // is a trusted root.
            //
            Status = CertFindRoot(NULL,
                                  &Subject->Values[Certificate_SubjectPublicKeyInfo].Data,
                                  Certificate_SubjectPublicKeyInfo,
                                  &Root);
            if (!NT_SUCCESS(Status)) {
                if (Status == STATUS_NO_MORE_ENTRIES)
                    return STATUS_UNTRUSTED_ROOT;

                return Status;
            }

            Issuer = &Root;
        }
        else {
            //
            // Check if the certificate is a root
            //
            Status = CertFindRoot(NULL,
                                  &Subject->Values[Certificate_Issuer].Data,
                                  Certificate_Issuer,
                                  &Root);
            if (NT_SUCCESS(Status)) {
                Issuer = &Root;
            }
            else {
                if (Status != STATUS_NO_MORE_ENTRIES)
                    return Status;

                //
                // Find the issuer certificate
                //
                Issuer = CertFindCertificateBySubject(&Subject->Values[Certificate_Issuer].Data,
                                                      CertificateList,
                                                      Count);
                if (!Issuer)
                    return STATUS_PARTIAL_CERTIFICATE_CHAIN;
            }
        }

        Status = HashData(AlgId,
                          1,
                          &Subject->Values[Certificate_ToBeSigned].Raw,
                          &Hash);
        if (NT_SUCCESS(Status)) {
            Status = CertVerifySignedHash(AlgId,
                                          &Hash,
                                          &Subject->Values[Certificate_Signature].Data,
                                          &Issuer->Values[Certificate_SubjectPublicKeyInfo].Raw);
            BlobFree(&Hash);
        }

        if (Issuer == &Root) {
            BlobFree(&Root.Raw);
            return Status;
        }

        if (!NT_SUCCESS(Status))
            return Status;

        if (Attempts++ > CERT_CHAIN_MAX_ATTEMPTS)
            return STATUS_CYCLIC_CERTIFICATE_CHAIN;

        Subject = Issuer;

        ASSERT(Subject != &Root);
    }
}
