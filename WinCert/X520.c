/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#define INITBLOB

#include "WinCerti.h"
#include "../wcoid.h"

/* GLOBALS ********************************************************************/

static const BLOB* const AttributeOIDs[] =
{
    &OID_CommonName,
    &OID_Surname,
    &OID_SerialNumber,
    &OID_CountryName,
    &OID_LocalityName,
    &OID_ProvinceName,
    &OID_StreetAddress,
    &OID_OrganizationName,
    &OID_OrganizationalUnitName,
    &OID_Title,
    &OID_Description,
    &OID_BusinessCatagory,
    &OID_GivenName,
    &OID_Initials,
    &OID_GenerationQualifier,
    &OID_DistinguishedName,
    &OID_Pseudonym,
};

C_ASSERT(RTL_NUMBER_OF(AttributeOIDs) == X520_Max);

/* FUNCTIONS ******************************************************************/

static
X520_ATTR
X520DecodeObjectIdentifier(
    _In_ REFBLOB Data
    )
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(AttributeOIDs); i++) {
        if (IsEqualBLOB(Data, AttributeOIDs[i]))
            return (X520_ATTR)i;
    }

    return X520_Max;
}

_Must_inspect_result_
NTSTATUS
X520Parse(
    _In_ REFBLOB Data,
    _Out_ PWIN_CERT_X520 X520
    )
{
    enum {
        Attr_Root = 0,
        Attr_Type,
        Attr_Value,
        Attr_Max
    };
    ASN1_VALUE Outer;
    NTSTATUS Status;
    ASN1_VALUE values[Attr_Max];
    X520_ATTR attr;
    static const ASN1_VALUE_DECRIPTOR Description[] = {
        // 0.0 - AttributeTypeAndValue :: = SET SIZE (1..MAX) OF AttributeTypeAndValue
        0, 0, ASN1_TAG_SET, Attr_Root,

            // 0.0 - AttributeTypeAndValue ::= SEQUENCE {
            1, 0, ASN1_TAG_SEQUENCE, -1,

                // 0.0 - type AttributeType ::= OBJECT IDENTIFIER
                2, 0, ASN1_TAG_OID, Attr_Type,

                // 0.1 - AttributeValue ::= CHOICE {
                2, 0, 0, Attr_Value,
    };

    RtlZeroMemory(X520, sizeof(*X520));

    //
    // Decode the encapsulating value
    //
    Status = Asn1DecodeValue(Data, &Outer);
    if (!NT_SUCCESS(Status))
        return Status;

    if (Outer.Tag != ASN1_TAG_SEQUENCE)
        return STATUS_ASN1_DECODING_ERROR;

    while (Outer.Data.cbSize) {
        Status = Asn1Decode(&Outer.Data,
                            Description,
                            RTL_NUMBER_OF(Description),
                            values);
        if (!NT_SUCCESS(Status))
            return Status;

        attr = X520DecodeObjectIdentifier(&values[Attr_Type].Data);

        //
        // Check if support this attribute.
        //
        // N.B. We don't fail if we don't to allow more flexible handling of
        // any future update.
        //
        if (attr != X520_Max) {
            switch (values[Attr_Value].Tag) {
            case ASN1_TAG_TELETEXSTRING:
            case ASN1_TAG_PRINTABLESTRING:
            case ASN1_TAG_UNIVERSALSTRING:
            case ASN1_TAG_UTF8STRING:
            case ASN1_TAG_BMPSTRING:
                break;

            default:
                return STATUS_ASN1_DECODING_ERROR;
            }

            X520->Attributes[attr] = values[Attr_Value];
        }

        BlobSkipAsn1Value(&Outer.Data, &values[Attr_Root]);
    }

    return STATUS_SUCCESS;
}

_Must_inspect_result_
NTSTATUS
X520Check(
    _In_ REFBLOB Data,
    _In_ const WIN_CERT_X520* Comparand,
    _In_ NTSTATUS MismatchStatus
    )
{
    NTSTATUS Status;
    WIN_CERT_X520 Target;
    ULONG i;

    Status = X520Parse(Data, &Target);
    if (!NT_SUCCESS(Status))
        return Status;

    for (i = 0; i < X520_Max; i++) {
        if (Comparand->Attributes[i].Data.pBlobData
            &&
            !IsEqualAsn1Value(&Target.Attributes[i], &Comparand->Attributes[i])) {

            return MismatchStatus;
        }
    }

    return STATUS_SUCCESS;
}
