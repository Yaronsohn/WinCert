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

// 1.2.840.113549.1.9.4
DEFINE_BLOB(OID_messageDigest, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04)

/* FUNCTIONS ******************************************************************/

static
NTSTATUS
Pkcs7ParseIndirectData(
    _In_ REFBLOB Data,
    _Out_cap_(IndirectData_Max) ASN1_VALUE Values[]
    )
{
    static const ASN1_VALUE_DECRIPTOR IndirectDataDescription[] = {
        // 0 - SpcIndirectDataContent ::= SEQUENCE {
        0, 0, ASN1_TAG_SEQUENCE, -1,

            // 0.0 - SpcAttributeTypeAndOptionalValue ::= SEQUENCE {
            1, 0, ASN1_TAG_SEQUENCE, -1,

                // 0.0.0 - type ObjectID
                2, 0, ASN1_TAG_OID, IndirectData_Type,

                // 0.0.1 - value [0] EXPLICIT ANY OPTIONAL
                2, ADF_OPTIONAL, 0/*DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0)*/, -1,


            // 0.1 - DigestInfo ::= SEQUENCE {
            1, 0, ASN1_TAG_SEQUENCE, -1,

                // 0.1.0 - AlgorithmIdentifier ::= SEQUENCE {
                2, 0, ASN1_TAG_SEQUENCE, -1,

                    // 0.1.0.0 - algorithm ObjectID
                    3, 0, ASN1_TAG_OID, IndirectData_Algorithm,

                    // 0.1.0.1 - parameters [0] EXPLICIT ANY OPTIONAL
                    3, ADF_OPTIONAL, 0/*DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0)*/, IndirectData_Parameters,

                // 0.1.1 - digest OCTETSTRING
                2, 0, ASN1_TAG_OCTETSTRING, IndirectData_Digest,
    };

    NTSTATUS Status;

    RtlZeroMemory(Values, sizeof(ASN1_VALUE) * IndirectData_Max);
    Status = Asn1Decode(Data,
                        IndirectDataDescription,
                        RTL_NUMBER_OF(IndirectDataDescription),
                        Values);
    if (!NT_SUCCESS(Status))
        return Status;

    if (!IsEqualBLOB(&SPC_PE_IMAGE_DATAOBJ, &Values[IndirectData_Type].Data))
        return STATUS_INVALID_SIGNATURE;

    if (Values[IndirectData_Digest].Data.cbSize == 0)
        return STATUS_INVALID_SIGNATURE;

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
    ULONG cert;
    ASN1_VALUE value;
    ULONG processed = 0;
    BLOB LocalData = *Data;

    for (cert = 0; LocalData.cbSize && cert < *Count; cert++) {
        Status = Asn1DecodeValue(&LocalData, &value);
        if (!NT_SUCCESS(Status))
            return Status;

        Status = X509ParseCertificate(&value.Raw, &Certificates[cert]);
        if (!NT_SUCCESS(Status))
            return Status;

        processed++;

        BlobSkipAsn1Value(&LocalData, &value);
    }

    *Count = processed;
    return STATUS_SUCCESS;
}

static
const CERT_VALUES*
CertFindCertificateByIssuerAndSerialNumber(
    _In_ REFBLOB Issuer,
    _In_ REFBLOB SerialNumber,
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

enum {
    Attr_Root = 0,
    Attr_AttributeType,
    Attr_Value,
    Attr_Max
};

typedef struct {
    ASN1_VALUE Values[Attr_Max];
} PKCS_ATTRIBUTE, *PPKCS_ATTRIBUTE;

static
NTSTATUS
Pkcs7ParseSignerInfoAttributes(
    _In_ REFBLOB RawAuthAttr,
    _Out_cap_(*Count) PPKCS_ATTRIBUTE Attributes,
    _Inout_ PULONG Count
    )
{
    NTSTATUS Status;
    ULONG processed = 0;
    ULONG attr;
    BLOB LocalData;
    ASN1_VALUE Root;
    static const ASN1_VALUE_DECRIPTOR Descriptions[] = {
        // 0 - Attribute ::= SEQUENCE {
        0, 0, ASN1_TAG_SEQUENCE, Attr_Root,

            // 0.0 - attributeType       ObjectID,
            1, 0, ASN1_TAG_OID, Attr_AttributeType,

            // 0.1 - attributeValue      SET OF
            1, 0, ASN1_TAG_SET, -1,

                // 0.1.0 - value 
                2, ADF_OPTIONAL, 0, Attr_Value
    };

    Status = Asn1DecodeValue(RawAuthAttr, &Root);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Root.Tag != DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0))
        return STATUS_INVALID_SIGNATURE;

    LocalData = Root.Data;

    RtlZeroMemory(Attributes, sizeof(PKCS_ATTRIBUTE) * *Count);

    for (attr = 0; LocalData.cbSize && attr < *Count; attr++) {
        Status = Asn1Decode(&LocalData,
                            Descriptions,
                            RTL_NUMBER_OF(Descriptions),
                            Attributes[attr].Values);
        if (!NT_SUCCESS(Status))
            return Status;

        processed++;
        BlobSkipAsn1Value(&LocalData, &Attributes[attr].Values[Attr_Root]);
    }

    *Count = processed;
    return STATUS_SUCCESS;
}

static
const PKCS_ATTRIBUTE*
Pkcs7FindAttribute(
    _In_count_(Count) const PKCS_ATTRIBUTE* Attributes,
    _In_ ULONG Count,
    _In_ REFBLOB Type
    )
{
    ULONG i;

    for (i = 0; i < Count; i++) {
        if (IsEqualBLOB(Type, &Attributes[i].Values[Attr_AttributeType].Data))
            return &Attributes[i];
    }

    return NULL;
}

static
NTSTATUS
Pkcs7VerifyAuthenticatedAttributes(
    _In_ LPCWSTR AlgId,
    _In_ REFBLOB RawAuthAttr,
    _Inout_ PBLOB Hash
    )
{
    NTSTATUS Status;
    PKCS_ATTRIBUTE Attributes[10];
    ULONG Count = RTL_NUMBER_OF(Attributes);
    const PKCS_ATTRIBUTE* attr;
    BLOB ToHash[2];
    BLOB NewHash;
    static const BYTE SetTag = ASN1_TAG_SET;

    Status = Pkcs7ParseSignerInfoAttributes(RawAuthAttr,
                                            Attributes,
                                            &Count);
    if (!NT_SUCCESS(Status))
        return Status;

    attr = Pkcs7FindAttribute(Attributes, Count, &OID_messageDigest);
    if (!attr)
        return STATUS_INVALID_SIGNATURE;

    if (!IsEqualBLOB(&attr->Values[Attr_Value].Data, Hash))
        return STATUS_INVALID_SIGNATURE;

    ToHash[0].cbSize = 1;
    ToHash[0].pBlobData = (PBYTE)&SetTag;
    ToHash[1].cbSize = RawAuthAttr->cbSize - 1;
    ToHash[1].pBlobData = RawAuthAttr->pBlobData + 1;

    Status = HashData(AlgId,
                      RTL_NUMBER_OF(ToHash),
                      ToHash,
                      &NewHash);
    if (!NT_SUCCESS(Status))
        return Status;

    BlobFree(Hash);
    *Hash = NewHash;
    return STATUS_SUCCESS;
}

static
_Must_inspect_result_
NTSTATUS
Pkcs7VerifySignedData(
    _In_ REFBLOB Data,
    _Out_cap_(SignedData_Max) ASN1_VALUE Values[],
    _In_opt_ const WIN_CERT_OPTIONS* Options
    )
{
    static const ASN1_VALUE_DECRIPTOR SignedDataDescription[] = {
        // 0 - signedData
        0, 0, ASN1_TAG_SEQUENCE, -1,

            // 0.0 - version Version
            1, 0, ASN1_TAG_INTEGER, SignedData_Version,

            // 0.1 - digestAlgorithms DigestAlgorithmIdentifiers (SET OF DigestAlgorithmIdentifier)
            1, 0, ASN1_TAG_SET, -1,

                // 0.1.0
                2, 0, ASN1_TAG_SEQUENCE, -1,

                    // 0.1.0.0
                    3, 0, ASN1_TAG_OID, SignedData_DigestAlgorithmIdentifier,

            // 0.2 - contentInfo ::= SEQUENCE {
            1, 0, ASN1_TAG_SEQUENCE, -1,

                // 0.2.0 - contentType ContentType
                2, 0, ASN1_TAG_OID, SignedData_ContentType,

                // 0.2.1 - content [0]
                2, ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), -1,

                    // 0.2.1.0 - SpcIndirectDataContent ::= SEQUENCE {
                    3, 0, ASN1_TAG_SEQUENCE, SignedData_Content,

            // 0.3 - certificates
            1, ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), SignedData_Certificates,

            // 0.4 - crls
            1, ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 1), SignedData_Crls,

            // 0.5 - SignerInfo ::= SET OF SignerInfo
            1, 0, ASN1_TAG_SET, SignedData_SignerInfo,

                // 0.5.0 - SignerInfo ::= SEQUENCE {
                2, 0, ASN1_TAG_SEQUENCE, -1,

                    // 0.5.0.0 - version Version
                    3, 0, ASN1_TAG_INTEGER, SignedData_SignerInfo_Version,

                    // 0.5.0.1 - IssuerAndSerialNumber ::= SEQUENCE {
                    3, 0, ASN1_TAG_SEQUENCE, -1,

                        // 0.5.0.1.0 - issuer Name
                        4, 0, ASN1_TAG_SEQUENCE, SignedData_SignerInfo_Issuer,

                        // 0.5.0.1.1 - serialNumber CertificateSerialNumber
                        4, 0, ASN1_TAG_INTEGER, SignedData_SignerInfo_SerialNumber,

                    // 0.5.0.2 - digestAlgorithm DigestAlgorithmIdentifier
                    3, 0, ASN1_TAG_SEQUENCE, -1,

                        // 0.5.0.2.0
                        4, 0, ASN1_TAG_OID, SignedData_SignerInfo_DigestAlgId,

                    // 0.5.0.3 - authenticatedAttributes [0] IMPLICIT Attributes OPTIONAL
                    3, ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), SignedData_SignerInfo_AuthAttr,

                    // 0.5.0.4 - digestEncryptionAlgorithm DigestEncryptionAlgorithmIdentifier
                    3, 0, ASN1_TAG_SEQUENCE, -1,

                        // 0.5.0.4.0 
                        4, 0, ASN1_TAG_OID, SignedData_SignerInfo_DigestEncrAlgoId,

                    // 0.5.0.5 - encryptedDigest EncryptedDigest
                    3, 0, ASN1_TAG_OCTETSTRING, SignedData_SignerInfo_EncrDigest,

                    // 0.5.0.6 - unauthenticatedAttributes   [1] IMPLICIT Attributes OPTIONAL
                    3, ADF_OPTIONAL, SignedData_SignerInfo_UnauthAttr,
    };
    NTSTATUS Status;
    CERT_VALUES Certificates[16] = { 0 };
    ULONG CertCount;
    BLOB Hash;
    const CERT_VALUES *Cert;
    LPCWSTR AlgId;

    RtlZeroMemory(Values, sizeof(Values) * SignedData_Max);
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
    if (Values[SignedData_ContentType].Data.cbSize == 0 ||  Values[SignedData_Content].Data.cbSize == 0)
        return STATUS_INVALID_SIGNATURE;

    CertCount = RTL_NUMBER_OF(Certificates);
    Status = Pkcs7ParseSignedDataCertificates(&Values[SignedData_Certificates].Data,
                                              Certificates,
                                              &CertCount);
    if (!NT_SUCCESS(Status))
        return Status;

    //
    // Find the certificate that was used for signing
    //
    Cert = CertFindCertificateByIssuerAndSerialNumber(&Values[SignedData_SignerInfo_Issuer].Data,
                                                      &Values[SignedData_SignerInfo_SerialNumber].Data,
                                                      Certificates,
                                                      CertCount);
    if (!Cert)
        return STATUS_INVALID_SIGNATURE;

    //
    // Verify the certificate
    //
    Status = X509VerifyCertificate(Cert, Certificates, CertCount, Options);
    if (!NT_SUCCESS(Status))
        return Status;

    //
    // We need to confirm that the following two match
    //
    if (!IsEqualBLOB(&Values[SignedData_SignerInfo_DigestAlgId].Data,
                     &Values[SignedData_DigestAlgorithmIdentifier].Data)) {

        return STATUS_INVALID_SIGNATURE;
    }

    AlgId = HashDecodeAlgorithmIdentifier(&Values[SignedData_SignerInfo_DigestAlgId].Data);
    if (AlgId == NULL)
        return STATUS_NOT_SUPPORTED;

    Status = HashData(AlgId,
                      1,
                      &Values[SignedData_Content].Data,
                      &Hash);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Values[SignedData_SignerInfo_AuthAttr].Data.cbSize) {
        Status = Pkcs7VerifyAuthenticatedAttributes(AlgId,
                                                    &Values[SignedData_SignerInfo_AuthAttr].Raw,
                                                    &Hash);
    }

    if (NT_SUCCESS(Status)) {
        Status = HashVerifySignedHash(AlgId,
                                      &Hash,
                                      &Values[SignedData_SignerInfo_EncrDigest].Data,
                                      &Cert->Values[Certificate_SubjectPublicKeyInfo].Raw);
    }

    BlobFree(&Hash);
    return Status;
}

_Must_inspect_result_
NTSTATUS
Pkcs7Verify(
    _In_ REFBLOB Data,
    _In_count_(Count) const BLOB DataToHash[],
    _In_ ULONG Count,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    )
{
    static const ASN1_VALUE_DECRIPTOR Pkcs7Description[] = {
        // 0
        0, 0, ASN1_TAG_SEQUENCE, -1,

            // 0.0 (== OID_RSA_signedData)
            1, 0, ASN1_TAG_OID, Pkcs7_OID,

            // 0.1
            1, 0, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), Pkcs7_SignedData,
    };

    NTSTATUS Status;
    ASN1_VALUE Values[Pkcs7_Max] = { 0 };
    ASN1_VALUE SignedData[SignedData_Max];
    ASN1_VALUE IndirectData[IndirectData_Max];
    LPCWSTR AlgId;
    BLOB Hash;
    BOOLEAN Equal;

    //
    // Parse the authenticode block
    //
    Status = Asn1Decode(Data,
                        Pkcs7Description,
                        RTL_NUMBER_OF(Pkcs7Description),
                        Values);
    if (!NT_SUCCESS(Status))
        return Status;

    //
    // Make sure we're dealing with ASN.1 PKCS #7
    //
    if (!IsEqualBLOB(&OID_RSA_PKCS7, &Values[Pkcs7_OID].Data))
        return STATUS_INVALID_SIGNATURE;

    Status = Pkcs7VerifySignedData(&Values[Pkcs7_SignedData].Data, SignedData, Options);
    if (!NT_SUCCESS(Status))
        return Status;

    if (!IsEqualBLOB(&SPC_INDIRECT_DATA_OBJID, &SignedData[SignedData_ContentType].Data))
        return STATUS_INVALID_SIGNATURE;

    Status = Pkcs7ParseIndirectData(&SignedData[SignedData_Content].Raw,
                                    IndirectData);
    if (!NT_SUCCESS(Status))
        return Status;

    if (!IsEqualBLOB(&SignedData[SignedData_DigestAlgorithmIdentifier].Data,
                     &IndirectData[IndirectData_Algorithm].Data)) {

        return STATUS_INVALID_SIGNATURE;
    }

    AlgId = HashDecodeAlgorithmIdentifier(&IndirectData[IndirectData_Algorithm].Data);
    if (!AlgId)
        return STATUS_NOT_SUPPORTED;

    Status = HashData(AlgId, Count, DataToHash, &Hash);
    if (!NT_SUCCESS(Status))
        return Status;

    Equal = IsEqualBLOB(&Hash, &IndirectData[IndirectData_Digest].Data);
    BlobFree(&Hash);

    return Equal ? STATUS_SUCCESS : STATUS_INVALID_SIGNATURE;
}

