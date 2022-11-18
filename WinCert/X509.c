/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#define INITBLOB

#include "WinCerti.h"

#pragma warning(disable:4996)

/* GLOBALS ********************************************************************/

// 2.5.29.9
DEFINE_BLOB(OID_EXT_SUBJECT_DIR_ATTR, 0x55, 0x1D, 0x09)

// 2.5.29.14
DEFINE_BLOB(OID_EXT_SUBJECT_KEY_ID, 0x55, 0x1D, 0x0E)

// 2.5.29.15
DEFINE_BLOB(OID_EXT_KEY_USAGE, 0x55, 0x1D, 0x0F)

// 2.5.29.17
DEFINE_BLOB(OID_EXT_SUBJECT_ALT_NAME, 0x55, 0x1D, 0x11)

// 2.5.29.18
DEFINE_BLOB(OID_EXT_ISSUER_ALT_NAME, 0x55, 0x1D, 0x12)

// 2.5.29.19
DEFINE_BLOB(OID_EXT_BASIC_CONST, 0x55, 0x1D, 0x13)

// 2.5.29.30
DEFINE_BLOB(OID_EXT_NAME_CONST, 0x55, 0x1D, 0x1E)

// 2.5.29.31
DEFINE_BLOB(OID_EXT_CRL_DIST_POINT, 0x55, 0x1D, 0x1F)

// 2.5.29.32
DEFINE_BLOB(OID_EXT_CERT_POLICY, 0x55, 0x1D, 0x20)

// 2.5.29.33
DEFINE_BLOB(OID_EXT_POLICY_MAPPINGS, 0x55, 0x1D, 0x21)

// 2.5.29.35
DEFINE_BLOB(OID_EXT_AUTH_KEY_ID, 0x55, 0x1D, 0x23)

// 2.5.29.36
DEFINE_BLOB(OID_EXT_POLICY_CONST, 0x55, 0x1D, 0x24)

// 2.5.29.37
DEFINE_BLOB(OID_EXT_EX_KEY_USAGE, 0x55, 0x1D, 0x25)

// 2.5.29.46
DEFINE_BLOB(OID_EXT_FRESHEST_CRL, 0x55, 0x1D, 0x2E)

// 2.5.29.54
DEFINE_BLOB(OID_EXT_INHIBIT_ANY_POLICY, 0x55, 0x1D, 0x36)

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

/* FUNCTIONS ******************************************************************/

#define CERT_MEM_TAG        'treC'

#ifndef CERT_CHAIN_MAX_ATTEMPTS
#define CERT_CHAIN_MAX_ATTEMPTS 16
#endif

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

    if (Tmp.cbSize == 0)
        return STATUS_NO_MORE_ENTRIES;

    //
    // Extension  ::=  SEQUENCE  {
    //     extnID      OBJECT IDENTIFIER,
    //     critical    BOOLEAN DEFAULT FALSE,
    //     extnValue   OCTET STRING
    // }
    //

    RtlZeroMemory(Ext, sizeof(CERT_EXTENSION));
    Status = Asn1DecodeValue(&Tmp, &Value);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Value.Tag != ASN1_TAG_SEQUENCE)
        return STATUS_ASN1_DECODING_ERROR;

    Ext->Raw = Value.Raw;

    Tmp = Value.Data;
    Status = Asn1DecodeValue(&Tmp, &Value);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Value.Tag != ASN1_TAG_OID)
        return STATUS_ASN1_DECODING_ERROR;

    Ext->Id = Value.Data;

    BlobSkipAsn1Value(&Tmp, &Value);

    Status = Asn1DecodeValue(&Tmp, &Value);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Value.Tag == ASN1_TAG_BOOLEAN) {
        while (Value.Data.cbSize--) {
            Ext->Critical = Ext->Critical || *Value.Data.pBlobData++;
        }

        BlobSkipAsn1Value(&Tmp, &Value);
    }

    Status = Asn1DecodeValue(&Tmp, &Value);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Value.Tag != ASN1_TAG_OCTETSTRING)
        return STATUS_ASN1_DECODING_ERROR;

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

__forceinline
const CERT_VALUES*
X509FindCertificateBySubject(
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
X509IsSelfSignedCertificate(
    _In_ const CERT_VALUES* Certificate
    );
--*/
#define X509IsSelfSignedCertificate(Certificate) \
    IsEqualBLOB(&Certificate->Values[Certificate_Subject].Data, \
        &Certificate->Values[Certificate_Issuer].Data)

static
NTSTATUS
X509FindRoot(
    _In_opt_ const UNICODE_STRING* Store,
    _In_ REFBLOB Comparator,
    _In_ CERTIFICATE_VALUE CertValue,
    _In_opt_ const CERT_EXTENSION* AuthKeyId,
    _Out_ PCERT_VALUES Certificate
    )
{
    NTSTATUS Status;
    ULONG Index;
    PKEY_BASIC_INFORMATION BasicInfo;
    ULONG Length;
    ULONG ResultLength;
    UNICODE_STRING Name;
    BLOB Blob;
    HANDLE StoreHandle;
    PCUNICODE_STRING NextStore;
    CERT_EXTENSION Ext;
    ASN1_VALUE keyIdentifier = { 0 };
    ASN1_VALUE SubjectKeyId;
    CERT_VALUES SavedCertificate = { 0 };
    static const UNICODE_STRING Roots[] = {
        RTL_CONSTANT_STRING(L"ROOT"),
        RTL_CONSTANT_STRING(L"AuthRoot"),
        RTL_CONSTANT_STRING(L"CA"),
    };
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
                            &keyIdentifier);
        if (!NT_SUCCESS(Status))
            return Status;
    }

    NextStore = Store ? Store : Roots;

    do {
        Status = StoreOpen(&StoreHandle,
                           KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS,
                           NextStore);
        if (NT_SUCCESS(Status)) {
            Index = 0;
            Length = 0;
            BasicInfo = NULL;
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
                    // N.B. We do not fail the whole process if we failed
                    // to process one certificate
                    //
                    Status = StoreOpenCertificateByName(&Blob, StoreHandle, &Name);
                    if (NT_SUCCESS(Status)) {
                        RtlZeroMemory(Certificate, sizeof(*Certificate));
                        Status = X509ParseCertificate(&Blob, Certificate);
                        if (NT_SUCCESS(Status)) {
                            //
                            // Did the caller specify an Authorization Key Id?
                            //
                            if (AuthKeyId) {

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
                                        IsEqualBLOB(&keyIdentifier.Data, &SubjectKeyId.Data)) {

                                       // Status = STATUS_SUCCESS;
                                       // goto FreeBasicInfo;
                                    }
                                }
                            }

                            if (!AuthKeyId || IsNilBlob(&SavedCertificate.Raw)) {
                                if (IsEqualBLOB(Comparator, &Certificate->Values[CertValue].Data)) {

                                    if (AuthKeyId) {
                                        ASSERT(IsNilBlob(&SavedCertificate.Raw));

                                        //
                                        // Save the matched certificate and try to find a better match.
                                        // (e.g. with the Auth Key Id.)
                                        //
                                        SavedCertificate = *Certificate;
                                        RtlZeroMemory(&Blob, sizeof(BLOB));
                                    }
                                    else {
                                        Status = STATUS_SUCCESS;
                                        goto FreeBasicInfo;
                                    }
                                }
                            }
                        }

                        BlobFree(&Blob);
                    }

                    Index++;
                    continue;
                }

FreeBasicInfo:  if (BasicInfo) {
                    WcFreeMemory(BasicInfo, CERT_MEM_TAG);
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
        }

        //
        // Did we find a match?
        //
        if (NT_SUCCESS(Status))
            break;

        //
        // Did the caller ask for an explicit store?
        //
        if (Store)
            break;

    } while (++NextStore < &Roots[RTL_NUMBER_OF(Roots)]);

    if (!IsNilBlob(&SavedCertificate.Raw)) {
        ASSERT(AuthKeyId);

        //
        // Did we actually find a match for the Auth Key Id?
        //
        if (IsNilBlob(&Blob)) {
            ASSERT(!NT_SUCCESS(Status));
            *Certificate = SavedCertificate;
            Status = STATUS_SUCCESS;
        }
        else {
            ASSERT(NT_SUCCESS(Status));
            BlobFree(&SavedCertificate.Raw);
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
X509ValidityCheck(
    _In_ const CERT_VALUES* Cert,
    _In_ CERT_CHAIN_HIERARCHY Hierarchy,
    _In_ const LARGE_INTEGER* SystemTime,
    _In_ ULONG Flags
    )
{
    NTSTATUS Status;
    LARGE_INTEGER TestTime;
    ULONG i;

    //
    // Do we need to check the Validity field?
    //
    if (!FlagOn(Flags, WCOF_NO_LIFETIME_CHECK(Hierarchy))) {
        Status = X509DecodeTime(&TestTime,
                                &Cert->Values[Certificate_NotBefore]);
        if (!NT_SUCCESS(Status))
            return Status;

        if (SystemTime->QuadPart < TestTime.QuadPart)
            return STATUS_CERT_EXPIRED;

        Status = X509DecodeTime(&TestTime,
                                &Cert->Values[Certificate_NotAfter]);
        if (!NT_SUCCESS(Status))
            return Status;

        if (SystemTime->QuadPart > TestTime.QuadPart)
            return STATUS_CERT_EXPIRED;
    }

    if (!FlagOn(Flags, WCOF_NO_CRITICAL_EXT(Hierarchy))) {
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

    return STATUS_SUCCESS;
}

_Must_inspect_result_
NTSTATUS
X509VerifyCertificate(
    _In_ const CERT_VALUES* Certificate,
    _In_opt_count_(Count) const CERT_VALUES* CertificateList,
    _In_ ULONG Count,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    )
{
    LPCWSTR AlgId;
    BLOB Hash;
    const CERT_VALUES* Subject = Certificate;
    NTSTATUS Status;
    const CERT_VALUES* Issuer;
    ULONG Attempts = 0;
    CERT_VALUES Root;
    ULONG Flags = 0;
    LARGE_INTEGER SystemTime = { 0 };
    CERT_EXTENSION AuthKeyId;
    PCERT_EXTENSION pAuthKeyId;

    if (Options) {
        Flags = Options->Flags;

        //
        // Does the caller wish to use a specific time?
        //
        if (Options->Time) {
            SystemTime = *Options->Time;
        }

        if (Options->Subject) {
            Status = X520Check(&Subject->Values[Certificate_Subject].Raw,
                               Options->Subject,
                               STATUS_SUBJECT_NOT_TRUSTED);
            if (!NT_SUCCESS(Status))
                return Status;
        }
    }

    if (SystemTime.QuadPart == 0) {
        WcQuerySystemTime(&SystemTime);
    }

    Status = X509ValidityCheck(Subject, CertChainEnd, &SystemTime, Flags);
    if (!NT_SUCCESS(Status))
        return Status;

    for (;;) {
        AlgId = HashDecodeAlgorithmIdentifier(&Subject->Values[Certificate_SignatureAlgorithm].Data);
        if (!AlgId)
            return STATUS_NOT_SUPPORTED;

        if (FlagOn(Flags, WCOF_DISABLE_MD2) && wcsicmp(AlgId, BCRYPT_MD2_ALGORITHM) == 0)
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
            Status = X509FindRoot(NULL,
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
        }
        else {
            //
            // Check if the certificate is a trusted root
            //
            Status = X509FindRoot(NULL,
                                  &Subject->Values[Certificate_Issuer].Data,
                                  Certificate_Issuer,
                                  pAuthKeyId,
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

        Status = X509ValidityCheck(Issuer,
                                   Issuer == &Root ? CertChainRoot : CertChainChain,
                                   &SystemTime,
                                   Flags);
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

            if (NT_SUCCESS(Status) && Options && Options->Issuer) {
                Status = X520Check(&Subject->Values[Certificate_Issuer].Raw,
                                   Options->Issuer,
                                   STATUS_CN_NO_MATCH);
            }

            return Status;
        }

        if (!NT_SUCCESS(Status))
            return Status;

        if (Attempts++ > CERT_CHAIN_MAX_ATTEMPTS)
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

        return X509VerifyCertificate(&Cert, NULL, 0, Options);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}