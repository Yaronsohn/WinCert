/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#define INITBLOB

#include "WinCerti.h"
#include "../wcoid.h"

#pragma warning(disable:4996)

/* GLOBALS ********************************************************************/

static const BLOB* const KnownExtensions[] = {
    &OID_EXT_SUBJECT_DIR_ATTR,
    &OID_EXT_SUBJECT_KEY_ID,
    &OID_EXT_KEY_USAGE,
    &OID_EXT_SUBJECT_ALT_NAME,
    &OID_EXT_ISSUER_ALT_NAME,
    &OID_EXT_BASIC_CONST,
    &OID_EXT_NAME_CONST,
    &OID_EXT_CRL_DIST_POINT,
    &OID_EXT_CERT_POLICY,
    &OID_EXT_POLICY_MAPPINGS,
    &OID_EXT_AUTH_KEY_ID,
    &OID_EXT_POLICY_CONST,
    &OID_EXT_EX_KEY_USAGE,
    &OID_EXT_FRESHEST_CRL,
    &OID_EXT_INHIBIT_ANY_POLICY
};

static const struct {
    REFBLOB Id;
    WORD KeyUsageBits;
} ExKeyUsageTable[] = {
    { &OID_EXT_EKU_ANY_EXT_KEY_USAGE,   0x80FF, },
    { &OID_EXT_EKU_SERVER_AUTH,         KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_KEY_AGREEMENT },
    { &OID_EXT_EKU_CLIENT_AUTH,         KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_KEY_AGREEMENT },
    { &OID_EXT_EKU_CODE_SIGNING,        KEY_USAGE_DIGITAL_SIGNATURE },
    { &OID_EXT_EKU_EMAIL_PROT,          KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_NON_REPUDIATION | KEY_USAGE_KEY_AGREEMENT },
    { &OID_EXT_EKU_TIME_STAMPING,       KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_NON_REPUDIATION },
    { &OID_EXT_EKU_OCSP_SIGNING,        KEY_USAGE_DIGITAL_SIGNATURE | KEY_USAGE_NON_REPUDIATION },
};

static const KEY_USAGE_BITS GenericDefaultKeyUsage[ChainMax] = {
    0,
    KEY_USAGE_DIGITAL_SIGNATURE,
    KEY_USAGE_DIGITAL_SIGNATURE
};

/* FUNCTIONS ******************************************************************/

#ifdef CERT_CHAIN_MAX_LENGTH
#if CERT_CHAIN_MAX_LENGTH >= MAXWORD
#error ERROR! CERT_CHAIN_MAX_LENGTH Must must be less than MAXWORD.
#endif
#else
#define CERT_CHAIN_MAX_LENGTH   16
#endif

typedef struct _CERT_VERIFICATION_CONTEXT {
    WORD ChainLength;
    WORD MaxChainLength;
    ULONG Flags;
    WIN_CERT_CHAIN_OPTIONS ChainOptions[ChainMax];
} CERT_VERIFICATION_CONTEXT, *PCERT_VERIFICATION_CONTEXT;

_Must_inspect_result_
NTSTATUS
X509ParseCertificate(
    _In_ REFBLOB Data,
    _Out_ PCERT_VALUES CertValues
    )
{
    static const ASN1_VALUE_DECRIPTOR CertificateDescription[] = {
        // 0 - Certificate  ::=  SEQUENCE  {
        0, 0, ASN1_TAG_SEQUENCE, -1,

            // 0.0 - toBeSigned ::== SEQUENCE {
            1, 0, ASN1_TAG_SEQUENCE, Certificate_ToBeSigned,

                // 0.0.0 - version [0] EXPLICIT CertificateVersion DEFAULT v1,
                2, ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), -1,

                    // 0.0.0.0 - version number INTEGER
                    3, 0, ASN1_TAG_INTEGER, Certificate_Version,

                // 0.0.1 - serialNumber CertificateSerialNumber,
                2, 0, ASN1_TAG_INTEGER, Certificate_SerialNumber,

                // 0.0.2 - signature ::= SEQUENCE {
                2, 0, ASN1_TAG_SEQUENCE, -1,

                    // 0.0.2.0
                    3, 0, ASN1_TAG_OID, Certificate_AlgorithmIdentifier,

                // 0.0.3 - issuer
                2, 0, ASN1_TAG_SEQUENCE, Certificate_Issuer,

                // 0.0.4 - validity - Validity
                2, 0, ASN1_TAG_SEQUENCE, -1,

                    // 0.0.4.0 - notBefore      Time (UTCTime or GeneralizedTime)
                    3, 0, 0/*ASN1_TAG_UTCTIME*/ , Certificate_NotBefore,

                    // 0.0.4.1 - notAfter       Time (UTCTime or GeneralizedTime)
                    3, 0, 0/*ASN1_TAG_UTCTIME*/, Certificate_NotAfter,

                // 0.0.5 - subject
                2, 0, ASN1_TAG_SEQUENCE, Certificate_Subject,

                // 0.0.6 - subjectPublicKeyInfo SubjectPublicKeyInfo
                2, 0, ASN1_TAG_SEQUENCE, Certificate_SubjectPublicKeyInfo,

                // 0.0.7 - issuerUniqueIdentifier [1] IMPLICIT BITSTRING OPTIONAL
                2, ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 1), Certificate_IssuerUniqueId,

                // 0.0.8 - subjectUniqueIdentifier [2] IMPLICIT BITSTRING OPTIONAL
                2, ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 2), Certificate_SubjectUniqueId,

                // 0.0.9 - extensions [3] EXPLICIT Extensions OPTIONAL
                2, ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_CONSTRUCTED, ASN1_DER_CLASS_CONTEXT_DEFINED, 3), -1,

                    // 0.0.9.0 -
                    3, 0, ASN1_TAG_SEQUENCE, Certificate_Extensions,

            // 0.1 - signatureAlgorithm  AlgorithmIdentifier,
            1, 0, ASN1_TAG_SEQUENCE, -1,

                // 0.1.0
                2, 0, ASN1_TAG_OID, Certificate_SignatureAlgorithm,

            // 0.2 - signature           BITSTRING
            1, 0, ASN1_TAG_BITSTRING, Certificate_Signature
    };

    RtlZeroMemory(CertValues->Values, sizeof(CertValues->Values));
    CertValues->Raw = *Data;
    return Asn1Decode(Data,
                      CertificateDescription,
                      RTL_NUMBER_OF(CertificateDescription),
                      CertValues->Values);
}

static
NTSTATUS
X509NextExtension(
    _In_ const CERT_VALUES* Certificate,
    _Inout_ PCERT_EXTENSION Ext
    )
{
    BLOB Tmp = Certificate->Values[Certificate_Extensions].Data;
    NTSTATUS Status;
    ASN1_VALUE Value;

    if (!IsNilBlob(&Ext->Raw)) {
        ProgressBlob(&Tmp,
                     RtlPointerToOffset(Tmp.pBlobData, Ext->Raw.pBlobData) + Ext->Raw.cbSize);
    }

    RtlZeroMemory(Ext, sizeof(CERT_EXTENSION));
    if (Tmp.cbSize == 0)
        return STATUS_NO_MORE_ENTRIES;

    //
    // Extension  ::=  SEQUENCE  {
    //     extnID      OBJECT IDENTIFIER,
    //     critical    BOOLEAN DEFAULT FALSE,
    //     extnValue   OCTET STRING
    // }
    //
    Status = Asn1DecodeValue(&Tmp, &Value);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Value.Tag != ASN1_TAG_SEQUENCE)
        return STATUS_CERT_MALFORMED;

    Ext->Raw = Value.Raw;

    Tmp = Value.Data;
    Status = Asn1DecodeValue(&Tmp, &Value);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Value.Tag != ASN1_TAG_OID)
        return STATUS_CERT_MALFORMED;

    Ext->Id = Value.Data;

    BlobSkipAsn1Value(&Tmp, &Value);

    Status = Asn1DecodeValue(&Tmp, &Value);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Value.Tag == ASN1_TAG_BOOLEAN) {
        Ext->Critical = Asn1ReadBoolean(&Value.Data);

        BlobSkipAsn1Value(&Tmp, &Value);
    }

    Status = Asn1DecodeValue(&Tmp, &Value);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Value.Tag != ASN1_TAG_OCTETSTRING)
        return STATUS_CERT_MALFORMED;

    Ext->Value = Value.Data;
    return STATUS_SUCCESS;
}

static
FORCEINLINE
NTSTATUS
X509FindExtension(
    _In_ const CERT_VALUES* Certificate,
    _In_ REFBLOB ExtId,
    _Out_ PCERT_EXTENSION Ext
    )
{
    NTSTATUS Status;

    RtlZeroMemory(Ext, sizeof(*Ext));

    while (NT_SUCCESS(Status = X509NextExtension(Certificate, Ext))) {
        if (IsEqualBLOB(ExtId, &Ext->Id))
            return STATUS_SUCCESS;
    }

    return Status;
}

FORCEINLINE
const CERT_VALUES*
X509FindCertificateBySubject(
    _In_ REFBLOB Subject,
    _In_opt_count_(CertCount) const CERT_VALUES* Certificates,
    _In_ ULONG CertCount
    )
{
    if (Subject->cbSize) {
        const CERT_VALUES* cert;

        while (CertCount--) {
            cert = Certificates++;
            if (IsEqualBLOB(&cert->Values[Certificate_Subject].Data, Subject))
                return cert;
        }
    }

    return NULL;
}

/*++
BOOLEAN
X509IsSelfSignedCertificate(
    _In_ const CERT_VALUES* Certificate
    );
--*/
#define X509IsSelfSignedCertificate(Certificate) \
    IsEqualBLOB(&Certificate->Values[Certificate_Subject].Data, \
        &Certificate->Values[Certificate_Issuer].Data)

typedef struct {
    REFBLOB Comparator;
    CERTIFICATE_VALUE CertValue;
    ASN1_VALUE KeyIdentifier;
    PCERT_VALUES Certificate;
    CERT_VALUES SavedCertificate;
} FIND_ROOT_ENUM_CONTEXT;

static
BOOLEAN
NTAPI
X509FindRootEnumRoutine(
    _In_ HANDLE StoreHandle,
    _In_ const VOID* Information,
    _In_ ULONG Length,
    _In_opt_ FIND_ROOT_ENUM_CONTEXT* Context,
    _Out_ PNTSTATUS ReturnStatus
    )
{
    PKEY_BASIC_INFORMATION BasicInfo = (PKEY_BASIC_INFORMATION)Information;
    PCERT_VALUES Certificate = Context->Certificate;
    UNICODE_STRING Name;
    BLOB CertBlob;
    CERT_EXTENSION Ext;
    ASN1_VALUE SubjectKeyId;
    NTSTATUS Status;

    Name.MaximumLength = Name.Length = (USHORT)BasicInfo->NameLength;
    Name.Buffer = BasicInfo->Name;

    //
    // N.B. We do not fail the whole process if we failed
    // to process one certificate
    //
    Status = StoreOpenCertificateByName(&CertBlob, StoreHandle, &Name);
    if (!NT_SUCCESS(Status))
        return TRUE;

    Status = X509ParseCertificate(&CertBlob, Certificate);
    if (NT_SUCCESS(Status)) {

        //
        // Did the caller specify an Authorization Key Id?
        //
        if (!IsNilBlob(&Context->KeyIdentifier.Data)) {

            //
            // Yup, we have an Auth Key Id - this suppose to match
            // the certificate's Subject Key Id
            //
            Status = X509FindExtension(Certificate,
                                       &OID_EXT_SUBJECT_KEY_ID,
                                       &Ext);
            if (NT_SUCCESS(Status)) {
                Status = Asn1DecodeValue(&Ext.Value, &SubjectKeyId);
                if (NT_SUCCESS(Status)
                    &&
                    SubjectKeyId.Tag == ASN1_TAG_OCTETSTRING
                    &&
                    IsEqualBLOB(&Context->KeyIdentifier.Data, &SubjectKeyId.Data)) {

                    *ReturnStatus = STATUS_SUCCESS;
                    return FALSE;
                }
            }
        }

        //
        // Check only if we didn't find one already
        //
        if (IsNilBlob(&Context->SavedCertificate.Raw)) {
            if (IsEqualBLOB(Context->Comparator, &Certificate->Values[Context->CertValue].Data)) {

                //
                // Save the matched certificate and try to find a better match.
                // (e.g. with the Auth Key Id.)
                //
                Context->SavedCertificate = *Certificate;
                return TRUE;
            }
        }
    }

    BlobFree(&CertBlob);
    return TRUE;
}

static
NTSTATUS
X509FindRoot(
    _In_opt_ const UNICODE_STRING* Store,
    _In_ ULONG StoreCount,
    _In_ REFBLOB Comparator,
    _In_ CERTIFICATE_VALUE CertValue,
    _In_opt_ const CERT_EXTENSION* AuthKeyId,
    _Out_ PCERT_VALUES Certificate
    )
{
    NTSTATUS Status;
    FIND_ROOT_ENUM_CONTEXT Context = { 0 };
    static const ASN1_VALUE_DECRIPTOR Description[] = {
        // AuthorityKeyIdentifier :: = SEQUENCE {
        0, 0, ASN1_TAG_SEQUENCE, -1,

            // keyIdentifier             [0] KeyIdentifier           OPTIONAL,
            1, ADF_OPTIONAL, DEFTAG(ASN1_DER_FORM_PRIMITIVE, ASN1_DER_CLASS_CONTEXT_DEFINED, 0), 0,
    };

    if (AuthKeyId) {
        Status = Asn1Decode(&AuthKeyId->Value,
                            Description,
                            RTL_NUMBER_OF(Description),
                            &Context.KeyIdentifier);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    Context.Comparator = Comparator;
    Context.CertValue = CertValue;
    Context.Certificate = Certificate;

    Status = StoreEnum(Store,
                       StoreCount,
                       KeyBasicInformation,
                       X509FindRootEnumRoutine,
                       &Context,
                       CertificateCatagry);
    if (!NT_SUCCESS(Status))
        return Status;

    if (!IsNilBlob(&Context.SavedCertificate.Raw)) {
        ASSERT(AuthKeyId);

        //
        // Did we actually find a match for the Auth Key Id?
        //
        if (IsNilBlob(&Context.Certificate->Raw)) {
            ASSERT(!NT_SUCCESS(Status));
            *Certificate = Context.SavedCertificate;
            Status = STATUS_SUCCESS;
        }
        else {
            ASSERT(NT_SUCCESS(Status));
            BlobFree(&Context.SavedCertificate.Raw);
        }
    }

    return Status;
}

static
NTSTATUS
X509DecodeTime(
    _Out_ PLARGE_INTEGER Time,
    _In_ const ASN1_VALUE* Value
    )
{
    TIME_FIELDS TimeFields;
    PCHAR pc;

#define DIGIT(d)                ((d) - '0')
#define TWO_DIGITS_NUM(h, l)    ((DIGIT(h) * 10) + DIGIT(l))

    TimeFields.Weekday = 0;
    TimeFields.Milliseconds = 0;

    pc = Value->Data.pBlobData;

    if (Value->Data.cbSize < 13)
        return STATUS_ASN1_DECODING_ERROR;

    TimeFields.Year = TWO_DIGITS_NUM(pc[0], pc[1]);
    pc += 2;

    if (Value->Tag == ASN1_TAG_UTCTIME) {
        //
        // YYMMDDHHMMSSZ
        //
        TimeFields.Year += (TimeFields.Year >= 50 ? 1900 : 2000);
    }
    else if (Value->Tag == ASN1_TAG_GENERALIZEDTIME) {
        //
        // YYYYMMDDHHMMSSZ
        //
        if (Value->Data.cbSize < 15)
            return STATUS_ASN1_DECODING_ERROR;

        TimeFields.Year = (TimeFields.Year * 100) + TWO_DIGITS_NUM(pc[0], pc[1]);
        pc += 2;
    }
    else {
        return STATUS_ASN1_DECODING_ERROR;
    }

    TimeFields.Month = TWO_DIGITS_NUM(pc[0], pc[1]);
    TimeFields.Day = TWO_DIGITS_NUM(pc[2], pc[3]);
    TimeFields.Hour = TWO_DIGITS_NUM(pc[4], pc[5]);
    TimeFields.Minute = TWO_DIGITS_NUM(pc[6], pc[7]);
    TimeFields.Second = TWO_DIGITS_NUM(pc[8], pc[9]);

    if (!RtlTimeFieldsToTime(&TimeFields, Time))
        return STATUS_ASN1_DECODING_ERROR;

    return STATUS_SUCCESS;
}

static
NTSTATUS
X509ResolveKeyUsage(
    _In_ const CERT_VALUES* Cert,
    _Out_ PKEY_USAGE_BITS Flags,
    _Out_ PBLOB OidList
    )
{
    CERT_EXTENSION Ext;
    NTSTATUS Status;
    ASN1_VALUE ExtValue;

    Flags->Combined = 0;

    Status = X509FindExtension(Cert, &OID_EXT_KEY_USAGE, &Ext);
    if (NT_SUCCESS(Status)) {
        Status = Asn1DecodeValue(&Ext.Value, &ExtValue);
        if (!NT_SUCCESS(Status))
            return Status;

        if (ExtValue.Tag != ASN1_TAG_BITSTRING)
            return STATUS_CERT_MALFORMED;

        RtlCopyMemory(&Flags->Combined,
                      ExtValue.Data.pBlobData,
                      min(ExtValue.Data.cbSize, sizeof(Flags->Combined)));
    }

    Status = X509FindExtension(Cert, &OID_EXT_EX_KEY_USAGE, &Ext);
    if (NT_SUCCESS(Status)) {
        ULONG i;
        ASN1_VALUE Oid;

        Status = Asn1DecodeValue(&Ext.Value, &ExtValue);
        if (!NT_SUCCESS(Status))
            return Status;

        if (ExtValue.Tag != ASN1_TAG_SEQUENCE)
            return STATUS_CERT_MALFORMED;

        *OidList = ExtValue.Data;

        while (ExtValue.Data.cbSize) {
            Status = Asn1DecodeValue(&ExtValue.Data, &Oid);
            if (!NT_SUCCESS(Status))
                return Status;

            if (Oid.Tag != ASN1_TAG_OID) {
                Status = STATUS_CERT_MALFORMED;
                break;
            }

            for (i = 0; i < RTL_NUMBER_OF(ExKeyUsageTable); i++) {
                if (IsEqualBLOB(&Oid.Data, ExKeyUsageTable[i].Id)) {
                    Flags->Combined |= ExKeyUsageTable[i].KeyUsageBits;
                }
            }

            BlobSkipAsn1Value(&ExtValue.Data, &Oid);
        }
    }

    return STATUS_SUCCESS;
}

FORCEINLINE
NTSTATUS
X509InOidInList(
    _In_ REFBLOB Oid,
    _In_ REFBLOB OidList
    )
{
    BLOB Data = *OidList;
    NTSTATUS Status;
    ASN1_VALUE Value;

    while (Data.cbSize) {
        Status = Asn1DecodeValue(&Data, &Value);
        if (!NT_SUCCESS(Status))
            return Status;

        if (Value.Tag != ASN1_TAG_OID)
            return STATUS_CERT_MALFORMED;

        if (IsEqualBLOB(Oid, &Value.Data))
            return STATUS_SUCCESS;

        BlobSkipAsn1Value(&Data, &Value);
    }

    return STATUS_OBJECT_NAME_NOT_FOUND;
}

static
NTSTATUS
X509ValidityCheck(
    _In_ const CERT_VALUES* Cert,
    _In_ CERT_CHAIN_HIERARCHY Hierarchy,
    _In_ PCERT_VERIFICATION_CONTEXT Context
    )
{
    NTSTATUS Status;
    LARGE_INTEGER TestTime;
    ULONG i;
    PWIN_CERT_CHAIN_OPTIONS opt = &Context->ChainOptions[Hierarchy];

    //
    // Do we need to confirm the subject?
    //
    if (opt->Subject) {
        Status = X520Check(&Cert->Values[Certificate_Subject].Raw,
                           opt->Issuer,
                           STATUS_SUBJECT_NOT_TRUSTED);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    //
    // Do we need to confirm the issuer?
    //
    if (opt->Issuer) {
        Status = X520Check(&Cert->Values[Certificate_Issuer].Raw,
                           opt->Issuer,
                           STATUS_CN_NO_MATCH);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    //
    // Do we need to check the Validity field?
    //
    if (!FlagOn(opt->Flags, WCHF_NO_LIFETIME_CHECK)) {
        Status = X509DecodeTime(&TestTime,
                                &Cert->Values[Certificate_NotBefore]);
        if (!NT_SUCCESS(Status))
            return Status;

        if (opt->Time.QuadPart < TestTime.QuadPart)
            return STATUS_CERT_EXPIRED;

        Status = X509DecodeTime(&TestTime,
                                &Cert->Values[Certificate_NotAfter]);
        if (!NT_SUCCESS(Status))
            return Status;

        if (opt->Time.QuadPart > TestTime.QuadPart)
            return STATUS_CERT_EXPIRED;
    }

    //
    // Do we need to check for unknown critical extensions?
    //
    if (!FlagOn(opt->Flags, WCHF_NO_CRITICAL_EXT_CHECK)) {
        CERT_EXTENSION ext = { 0 };
        while (NT_SUCCESS(Status = X509NextExtension(Cert, &ext))) {
            if (ext.Critical) {
                for (i = 0; i < RTL_NUMBER_OF(KnownExtensions); i++) {
                    if (IsEqualBLOB(KnownExtensions[i], &ext.Id))
                        break;
                }

                if (i == RTL_NUMBER_OF(KnownExtensions))
                    return STATUS_CERT_CRITICAL;
            }
        }
    }

    if (!FlagOn(opt->Flags, WCHF_NO_KEY_USAGE_CHECK)) {
        KEY_USAGE_BITS KeyUsageBits;
        BLOB OidList;

        Status = X509ResolveKeyUsage(Cert, &KeyUsageBits, &OidList);
        if (!NT_SUCCESS(Status))
            return Status;

#define ARE_ALL_SET(bitmap, flags) (((bitmap) & (flags)) == (flags))

        if (!ARE_ALL_SET(KeyUsageBits.Combined, opt->KeyUsage.Combined))
            return STATUS_CERT_PURPOSE;

        for (i = 0; i < opt->ExtKeyUsageCount; i++) {
            if (!X509InOidInList(&opt->ExtKeyUsageList[i], &OidList))
                return STATUS_CERT_PURPOSE;
        }

        if (!FlagOn(opt->Flags, WCHF_NO_BASIC_CONSTRAINTS_CHECK)
            &&
            KeyUsageBits.KeyCertSign) {

            CERT_EXTENSION ext;
            ASN1_VALUE Values[2] = { 0 };
            static const ASN1_VALUE_DECRIPTOR Description[] = {
                // BasicConstraints ::= SEQUENCE {
                0, 0, ASN1_TAG_SEQUENCE, -1,

                // cA BOOLEAN DEFAULT FALSE,
                1, ADF_OPTIONAL, ASN1_TAG_BOOLEAN, 0,

                // pathLenConstraint       INTEGER (0..MAX) OPTIONAL
                1, ADF_OPTIONAL, ASN1_TAG_INTEGER, 1,
            };

            Status = X509FindExtension(Cert, &OID_EXT_BASIC_CONST, &ext);
            if (NT_SUCCESS(Status)) {
                Status = Asn1Decode(&ext.Value,
                                    Description,
                                    RTL_NUMBER_OF(Description),
                                    Values);
                if (!NT_SUCCESS(Status))
                    return Status;

                if (Asn1ReadBoolean(&Values[0].Data)
                    &&
                    Asn1ReadInteger(&Values[1].Data) > Context->ChainLength) {

                    return STATUS_CERT_CHAINING;
                }
            }
        }
    }

    return STATUS_SUCCESS;
}

_Must_inspect_result_
NTSTATUS
X509VerifyCertificate(
    _In_ const CERT_VALUES* Certificate,
    _In_opt_count_(Count) const CERT_VALUES* CertificateList,
    _In_ ULONG Count,
    _In_opt_ const WIN_CERT_OPTIONS* Options,
    _In_ const KEY_USAGE_BITS DefaultKeyUsage[]
    )
{
    LPCWSTR AlgId;
    BLOB Hash;
    const CERT_VALUES* Subject = Certificate;
    NTSTATUS Status;
    const CERT_VALUES* Issuer;
    ULONG Attempts = 0;
    CERT_VALUES Root;
    CERT_VERIFICATION_CONTEXT Context = { 0 };
    CERT_EXTENSION AuthKeyId;
    PCERT_EXTENSION pAuthKeyId;
    CERT_CHAIN_HIERARCHY Hierarchy = ChainIntermediate;
    ULONG i;
    LARGE_INTEGER Time;
    const UNICODE_STRING* Stores = NULL;
    ULONG StoreCount = 0;

    if (Options) {
        if (Options->Size != sizeof(WIN_CERT_OPTIONS_1))
            return STATUS_INVALID_PARAMETER;

        Context.Flags = Options->Flags;

        RtlCopyMemory(Context.ChainOptions,
                      Options->ChainOptions,
                      sizeof(Context.ChainOptions));

        Stores = Options->Stores;
        StoreCount = Options->StoreCount;
    }

    //
    // Capture the clock so we'll use one common timestamp
    //
    WcQuerySystemTime(&Time);

    //
    // Check if we need to use the default
    //
    for (i = 0; i < ChainMax; i++) {
        if (Context.ChainOptions[i].Time.QuadPart == 0) {
            Context.ChainOptions[i].Time = Time;
        }

        if (Context.ChainOptions[i].KeyUsage.Combined == 0) {
            Context.ChainOptions[i].KeyUsage = DefaultKeyUsage[i];
        }
    }

    Status = X509ValidityCheck(Subject, ChainEnd, &Context);
    if (!NT_SUCCESS(Status))
        return Status;

    for (;;) {
        AlgId = HashDecodeAlgorithmIdentifier(&Subject->Values[Certificate_SignatureAlgorithm].Data);
        if (!AlgId)
            return STATUS_NOT_SUPPORTED;

        if (FlagOn(Context.Flags, WCOF_DISABLE_MD2) && _wcsicmp(AlgId, BCRYPT_MD2_ALGORITHM) == 0)
            return STATUS_NOT_SUPPORTED;

        //
        // Check for the Authority Key Identifier extension
        //
        Status = X509FindExtension(Subject, &OID_EXT_AUTH_KEY_ID, &AuthKeyId);
        if (NT_ERROR(Status))
            return Status;

        pAuthKeyId = NT_SUCCESS(Status) ? &AuthKeyId : NULL;

        if (X509IsSelfSignedCertificate(Subject)) {
            //
            // Because we've reached the end of the chain, check if this certificate
            // is a trusted root.
            //
            Status = X509FindRoot(Stores,
                                  StoreCount,
                                  &Subject->Values[Certificate_SubjectPublicKeyInfo].Data,
                                  Certificate_SubjectPublicKeyInfo,
                                  pAuthKeyId,
                                  &Root);
            if (!NT_SUCCESS(Status)) {
                if (Status == STATUS_NO_MORE_ENTRIES)
                    return STATUS_UNTRUSTED_ROOT;

                return Status;
            }

            Issuer = &Root;
            Hierarchy = ChainRoot;
        }
        else {
            //
            // Check if the certificate is a trusted root
            //
            Status = X509FindRoot(Stores,
                                  StoreCount,
                                  &Subject->Values[Certificate_Issuer].Data,
                                  Certificate_Issuer,
                                  pAuthKeyId,
                                  &Root);
            if (NT_SUCCESS(Status)) {
                Issuer = &Root;
                Hierarchy = ChainRoot;
            }
            else {
                if (Status != STATUS_NO_MORE_ENTRIES)
                    return Status;

                //
                // Find the issuer certificate
                // 
                Issuer = X509FindCertificateBySubject(&Subject->Values[Certificate_Issuer].Data,
                                                      CertificateList,
                                                      Count);
                if (!Issuer) {


                    // TODO: check for Authority Information Access
                    // and fetch info from the issuing authority - which means through the network...
                    return STATUS_CERT_CHAINING;
                }
            }
        }

        Status = X509ValidityCheck(Issuer, Hierarchy, &Context);
        if (!NT_SUCCESS(Status))
            return Status;

        Status = HashData(AlgId,
                          1,
                          &Subject->Values[Certificate_ToBeSigned].Raw,
                          &Hash);
        if (NT_SUCCESS(Status)) {
            Status = HashVerifySignedHash(AlgId,
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

        if (Context.ChainLength++ > CERT_CHAIN_MAX_LENGTH)
            return STATUS_CERT_CHAINING;

        Subject = Issuer;

        ASSERT(Subject != &Root);
    }
}

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyCertificate(
    _In_ const VOID* BaseAddress,
    _In_ SIZE_T Size,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    )
{
    NTSTATUS Status;
    CERT_VALUES Cert;
    BLOB Data;

    Data.cbSize = (DWORD)Size;
    Data.pBlobData = (PBYTE)BaseAddress;

    __try {
        Status = X509ParseCertificate(&Data, &Cert);
        if (!NT_SUCCESS(Status))
            return Status;

        return X509VerifyCertificate(&Cert, NULL, 0, Options, GenericDefaultKeyUsage);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}
