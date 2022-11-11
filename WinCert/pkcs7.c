/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#define INITBLOB
#include "WinCerti.h"

/* GLOBALS ********************************************************************/

// 1.3.6.1.4.1.311.2.1.15
DEFINE_BLOB(SPC_PE_IMAGE_DATAOBJ, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F)

// 1.3.6.1.4.1.311.2.1.4
DEFINE_BLOB(SPC_INDIRECT_DATA_OBJID, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04)

// 1.2.840.113549.1.7.2
DEFINE_BLOB(OID_RSA_PKCS7, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02)

/* FUNCTIONS ******************************************************************/

static
NTSTATUS
Pkcs7ParseIndirectData(
    _In_ REFBLOB Data,
    _In_ REFBLOB ExpectedAlgoId,
    _Out_ PASN1_VALUE Hash
    )
{
    static const ASN1_VALUE_DECRIPTOR IndirectDataDescription[] = {
        // 0 - SpcIndirectDataContent ::= SEQUENCE {
        ADF_STEPIN | ADF_STEPOUT, ASN1_TAG_SEQUENCE, -1,

            // 0.0 - SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
            ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

                // 0.0.0 - type ObjectID
                0, ASN1_TAG_OID, IndirectData_Type,

                // 0.0.1 - value [0] EXPLICIT ANY OPTIONAL
                ADF_STEPOUT | ADF_OPTIONAL, 0/*DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0)*/, -1,


            // 0.1 - DigestInfo ::= SEQUENCE {
            ADF_STEPIN | ADF_STEPOUT, ASN1_TAG_SEQUENCE, -1,

                // 0.1.0 - AlgorithmIdentifier ::= SEQUENCE {
                ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

                    // 0.1.0.0 - algorithm ObjectID
                    0, ASN1_TAG_OID, IndirectData_Algorithm,

                    // 0.1.0.1 - parameters [0] EXPLICIT ANY OPTIONAL
                    ADF_STEPOUT | ADF_OPTIONAL, 0/*DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0)*/, IndirectData_Parameters,

                // 0.1.1 - digest OCTETSTRING
                ADF_STEPOUT, ASN1_TAG_OCTETSTRING, IndirectData_Hash,
    };

    NTSTATUS Status;
    ASN1_VALUE Values[IndirectData_Max] = { 0 };

    Status = Asn1Decode(Data,
                        IndirectDataDescription,
                        RTL_NUMBER_OF(IndirectDataDescription),
                        Values);
    if (!NT_SUCCESS(Status))
        return Status;

    if (!IsEqualBLOB(&SPC_PE_IMAGE_DATAOBJ, &Values[IndirectData_Type].Data))
        return STATUS_INVALID_SIGNATURE;

    if (Values[IndirectData_Hash].Data.cbSize == 0)
        return STATUS_INVALID_SIGNATURE;

    if (!IsEqualBLOB(ExpectedAlgoId, &Values[IndirectData_Algorithm].Data))
        return STATUS_INVALID_SIGNATURE;

    *Hash = Values[IndirectData_Hash];
    return STATUS_SUCCESS;
}

static
NTSTATUS
Pkcs7ParseSignedDataCertificates(
    _In_ REFBLOB Data,
    _Out_cap_(*Count) PCERT_VALUES Certificates,
    _Inout_ PULONG Count
    )
{
    NTSTATUS Status;
    ULONG cert = *Count;
    ASN1_VALUE value;
    ULONG processed = 0;
    BLOB LocalData = *Data;

    for (cert = 0; LocalData.cbSize && cert < *Count; cert++) {
        Status = Asn1DecodeValue(&LocalData, &value);
        if (!NT_SUCCESS(Status))
            return Status;

        Status = CertParseCertificate(&value.Raw, &Certificates[cert]);
        if (!NT_SUCCESS(Status))
            return Status;

        processed++;

        ProgressBlob(&LocalData, value.Raw.cbSize);
    }

    *Count = processed;
    return STATUS_SUCCESS;
}

const CERT_VALUES*
CertFindCertificateByIssuerAndSerialNumber(
    _In_ REFBLOB Issuer,
    _In_opt_ const BLOB* SerialNumber,
    _In_count_(CertCount) const CERT_VALUES* Certificates,
    _In_ ULONG CertCount
)
{
    const CERT_VALUES* cert;

    if (Issuer->cbSize == 0 || SerialNumber->cbSize == 0)
        return NULL;

    while (CertCount--) {
        cert = Certificates++;
        if (IsEqualBLOB(&cert->Values[Certificate_Issuer].Data, Issuer)
            &&
            IsEqualBLOB(&cert->Values[Certificate_SerialNumber].Data, SerialNumber)) {

            return cert;
        }
    }

    return NULL;
}

static
NTSTATUS
Pkcs7ParseSignedData(
    _In_ REFBLOB Data
    )
{
    static const ASN1_VALUE_DECRIPTOR SignedDataDescription[] = {
        // 0 - version Version
        0, ASN1_TAG_INTEGER, SignedData_Version,

        // 1 - digestAlgorithms DigestAlgorithmIdentifiers (SET OF DigestAlgorithmIdentifier)
        ADF_STEPIN, ASN1_TAG_SET, -1,

            // 1.0
            ADF_STEPIN | ADF_STEPOUT, ASN1_TAG_SEQUENCE, -1,

                // 1.0.0
                ADF_STEPOUT, ASN1_TAG_OID, SignedData_DigestAlgorithmIdentifier,

        // 2 - contentInfo ::= SEQUENCE {
        ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

            // 2.0 - contentType ContentType
            0, ASN1_TAG_OID, SignedData_ContentType,

            // 2.1 - content [0]
            ADF_STEPOUT | ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), SignedData_Content,

        // 3 - certificates
        ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), SignedData_Certificates,

        // 4 - crls
        ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 1), SignedData_Crls,

        // 5 - SignerInfos ::= SET OF SignerInfo
        ADF_STEPIN | ADF_STEPOUT, ASN1_TAG_SET, SignedData_SignerInfos,

            // 5.0 - SignerInfo ::= SEQUENCE {
            ADF_STEPIN | ADF_STEPOUT, ASN1_TAG_SEQUENCE, -1,

                // 5.0.0 - version Version
                0, ASN1_TAG_INTEGER, SignedData_SignerInfos_Version,

                // 5.0.1 - IssuerAndSerialNumber ::= SEQUENCE {
                ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

                    // 5.0.1.0 - issuer Name
                    0, ASN1_TAG_SEQUENCE, SignedData_SignerInfos_Issuer,

                    // 5.0.1.1 - serialNumber CertificateSerialNumber
                    ADF_STEPOUT, ASN1_TAG_INTEGER, SignedData_SignerInfos_SerialNumber,

                // 5.0.2 - digestAlgorithm DigestAlgorithmIdentifier
                ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

                    // 5.0.2.0
                    ADF_STEPOUT, ASN1_TAG_OID, SignedData_SignerInfos_DigestAlgId,

                // 5.0.3 - authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL
                ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), SignedData_SignerInfos_AuthAttr,

                // 5.0.4 - digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier
                ADF_STEPIN, ASN1_TAG_SEQUENCE, -1,

                    // 5.0.4.0 
                    ADF_STEPOUT, ASN1_TAG_OID, SignedData_SignerInfos_DigestEncrAlgoId,

                // 5.0.5 - encryptedDigest EncryptedDigest
                0, ASN1_TAG_OCTETSTRING, SignedData_SignerInfos_EncrDigest,

                // 5.0.6 - unauthenticatedAttributes   [1] IMPLICIT Attributes OPTIONAL
                ADF_STEPOUT | ADF_OPTIONAL, SignedData_SignerInfos_UnauthAttr,
    };

    NTSTATUS Status;
    ASN1_VALUE Values[SignedData_Max] = { 0 };
    CERT_VALUES Certificates[16] = { 0 };
    ULONG CertCount;
    ASN1_VALUE Hash;
    const CERT_VALUES *Cert;

    Status = Asn1Decode(Data,
                        SignedDataDescription,
                        RTL_NUMBER_OF(SignedDataDescription),
                        Values);
    if (NT_ERROR(Status))
        return Status;

    //
    // We only support v1
    //
    if (!Values[SignedData_Version].Data.cbSize || Values[SignedData_Version].Data.pBlobData[0] != 1)
        return STATUS_INVALID_SIGNATURE;

    //
    // Make sure it is not an empty message
    //
    if (Values[SignedData_Content].Data.cbSize == 0)
        return STATUS_INVALID_SIGNATURE;

    if (!IsEqualBLOB(&SPC_INDIRECT_DATA_OBJID, &Values[SignedData_ContentType].Data))
        return STATUS_INVALID_SIGNATURE;

    if (Values[SignedData_DigestAlgorithmIdentifier].Data.cbSize == 0)
        return STATUS_INVALID_SIGNATURE;

    Status = Pkcs7ParseIndirectData(&Values[SignedData_Content].Data,
                                    &Values[SignedData_DigestAlgorithmIdentifier].Data,
                                    &Hash);
    if (!NT_SUCCESS(Status))
        return Status;

    CertCount = RTL_NUMBER_OF(Certificates);
    Status = Pkcs7ParseSignedDataCertificates(&Values[SignedData_Certificates].Data,
                                              Certificates,
                                              &CertCount);
    if (!NT_SUCCESS(Status))
        return Status;

    //
    // Find the certificate that was used for signing
    //
    Cert = CertFindCertificateByIssuerAndSerialNumber(&Values[SignedData_SignerInfos_Issuer].Data,
                                                      &Values[SignedData_SignerInfos_SerialNumber].Data,
                                                      Certificates,
                                                      CertCount);
    if (!Cert)
        return STATUS_INVALID_SIGNATURE;

    //
    // Verify the certificate
    //
    Status = CertVerifyCertificate(Cert, Certificates, CertCount);
    if (!NT_SUCCESS(Status))
        return Status;

    return STATUS_SUCCESS;
}

NTSTATUS
Pkcs7Parse(
    _In_ REFBLOB Data
    )
{
    static const ASN1_VALUE_DECRIPTOR AuthenticodeDescription[] = {
        // 0
        ADF_STEPIN | ADF_STEPOUT, ASN1_TAG_SEQUENCE, -1,

            // 0.0 (== OID_RSA_signedData)
            0, ASN1_TAG_OID, Authenticode_OID,

            // 0.1
            ADF_STEPIN | ADF_STEPOUT, 0, -1,

                // 0.1.0
                ADF_STEPOUT, ASN1_TAG_SEQUENCE, Authenticode_SignedData,
    };

    NTSTATUS Status;
    ASN1_VALUE Values[Authenticode_Max] = { 0 };

    //
    // Parse the authenticode block
    //
    Status = Asn1Decode(Data,
                        AuthenticodeDescription,
                        RTL_NUMBER_OF(AuthenticodeDescription),
                        Values);
    if (!NT_SUCCESS(Status))
        return Status;

    //
    // Make sure we're dealing with ASN.1 PKCS #7
    //
    if (!IsEqualBLOB(&OID_RSA_PKCS7, &Values[Authenticode_OID].Data))
        return STATUS_INVALID_SIGNATURE;

    Status = Pkcs7ParseSignedData(&Values[Authenticode_SignedData].Data);
    if (!NT_SUCCESS(Status))
        return Status;

    return STATUS_SUCCESS;
}
