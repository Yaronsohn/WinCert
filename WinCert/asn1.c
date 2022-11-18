/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <windef.h>
#include "../WinCert.h"
#include <bcrypt.h>

/* FUNCTIONS ******************************************************************/

#define DESCEND_STACK_LENGTH        16

NTSTATUS
NTAPI
Asn1DecodeValue(
    _In_ REFBLOB Data,
    _Out_ PASN1_VALUE Value
    )
/*++

Routine Description:

    This function decodes and validates the ASN1 value at the given location.

Arguments:

    Data - The data blob descriptor.

    ImageSize - The length of the buffer. This can be larger than the value if
                the buffer has more values following this one.

    Value - Location where the information about the value is returned. This
            function decodes and returns a single value.

Return Value:

    NTSTATUS.

--*/
{
    BYTE* Ptr = Data->pBlobData;
    ULONG Length = Data->cbSize;

    if (Length < 2)
        return STATUS_ASN1_DECODING_ERROR;

    //
    // Save the raw pointer
    //
    Value->Raw.pBlobData = Ptr;

    //
    // For now, assume that the whole length is the Tag and Length fields and
    // deduct it from the length we have left.
    //
    Value->Raw.cbSize = 2;
    Length -= 2;

    //
    // Get the Tag
    //
    Value->Tag = *Ptr++;

    //
    // Get the length field
    //
    Value->Data.cbSize = *Ptr++;
    if (Value->Data.cbSize & 0x80) {
        //
        // The data length is more than 127 bytes so the value we have
        // is actualy the length of the length - so let's read the length
        // of the data
        //
        ULONG LengthOfLength = Value->Data.cbSize & 0x7F;
        ULONG i;

        //
        // Make sure we have that many bytes left
        //
        if (LengthOfLength > Length)
            return STATUS_ASN1_DECODING_ERROR;

        //
        // We only support sizeof(DWORD) number of bytes to hold the length
        //
        if (LengthOfLength > sizeof(Value->Data.cbSize))
            return STATUS_ASN1_DECODING_ERROR;

        //
        // The length is stored MSB first, so we need to 
        //
        Value->Data.cbSize = 0;
        for (i = 0; i < LengthOfLength; i++) {
            Value->Data.cbSize = (Value->Data.cbSize << 8) + *Ptr++;
        }

        Length -= LengthOfLength;

        //
        // Update the overall length of the value to account for the
        // variadic length
        //
        Value->Raw.cbSize += LengthOfLength;
    }

    if (Length < Value->Data.cbSize)
        return STATUS_ASN1_DECODING_ERROR;

    Value->Data.pBlobData = Ptr;
    Value->Raw.cbSize += Value->Data.cbSize;

    //
    // If we're dealing with a bitstring, skip the first
    // octet as it tells the number of unused bits
    //
    if (Value->Tag == ASN1_TAG_BITSTRING) {
        ProgressBlob(&Value->Data, 1);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
Asn1Decode(
    _In_ REFBLOB Data,
    _In_count_(DescriptorCount) const ASN1_VALUE_DECRIPTOR* Descriptors,
    _In_ ULONG DescriptorCount,
    _Out_ PASN1_VALUE Values
    )
/*++

Routine Description:

    This function decodes a sequence of values according to the descriptor list.

Arguments:

    Data - The data blob descriptor.

    Descriptors - An array of descriptor that specifies how to decode the value
                  stream and where to store the required information.

    DescriptorCount - The number of descriptors in the array pointed to by the
                      Descriptors parameter.

    Values - An array where the needed value information is returned. The
             function assumes this array is large enough to hold all the values
             as specified by the Descriptors parameter.
             The function might not return all values as requested of the value
             stream is not large enough - but never more.

Return Value:

    NTSTATUS.

--*/
{
    BLOB Stack[DESCEND_STACK_LENGTH];
    LONG StackPtr = 0;
    NTSTATUS Status = STATUS_SUCCESS;
    ULONG NextDesc = 0;
    ULONG ValueIndex;
    ASN1_VALUE value;
    BLOB State = *Data;

    while (State.cbSize) {
        Status = Asn1DecodeValue(&State, &value);
        if (!NT_SUCCESS(Status))
            return Status;

        BlobSkipAsn1Value(&State, &value);

        //
        // Skip nil tags
        //
        if (value.Tag) {
            if (NextDesc == DescriptorCount)
                return STATUS_MORE_ENTRIES;

            if (Descriptors[NextDesc].Tag) {
                while (Descriptors[NextDesc].Tag != value.Tag) {
                    if (!Descriptors[NextDesc].Optional)
                        return STATUS_ASN1_DECODING_ERROR;

                    do {
                        if (++NextDesc >= DescriptorCount)
                            return State.cbSize ? STATUS_MORE_ENTRIES : STATUS_SUCCESS;

                    } while (Descriptors[NextDesc].Level > StackPtr);   
                }
            }

            ValueIndex = Descriptors[NextDesc].ValueIndex;
            if (ValueIndex != -1) {
                Values[ValueIndex] = value;
            }

            if ((NextDesc + 1) < DescriptorCount) {
                NextDesc++;
                if (Descriptors[NextDesc].Level > StackPtr) {
                    if (TAG_TO_FORM(value.Tag) != ASN1_DER_FORM_CONSTRUCTED)
                        return STATUS_ASN1_DECODING_ERROR;

                    if (++StackPtr >= DESCEND_STACK_LENGTH)
                        return STATUS_ASN1_DECODING_ERROR;

                    Stack[StackPtr] = State;
                    State = value.Data;
                    continue;
                }
            }
        }

        while (StackPtr > 0) {
            if (Descriptors[NextDesc].Level == StackPtr) {
                if (State.cbSize)
                    break;

                while (++NextDesc < DescriptorCount) {
                    if (Descriptors[NextDesc].Level < StackPtr) {
                        break;
                    }
                }
            }

            State = Stack[StackPtr--];
        }
    }

    return NextDesc == DescriptorCount ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
}

_Must_inspect_result_
BOOLEAN
NTAPI
IsEqualAsn1Value(
    _In_ const ASN1_VALUE* Target,
    _In_ const ASN1_VALUE* Comparand
    )
{
    if (Comparand->Tag && (Comparand->Tag != Target->Tag))
        return FALSE;

    return IsEqualBLOB(&Comparand->Data, &Target->Data);
}
