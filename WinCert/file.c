/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include "WinCerti.h"
#include <ntimage.h>

/* FUNCTIONS ******************************************************************/

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyFileByHandle(
    _In_ HANDLE FileHandle,
    _In_ DWORD DataType,
    _Out_opt_ PULONG ReturnedDataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    )
/*++

Routine Description:

    This function creates a section object for the specified file, maps it to
    the system address space and checks the digital signature (if one exists).

Arguments:

    FileObject - A handl to the file to check.

    DataType - The type of the data in the file specified by FileHandle.

    ReturnedDataType - Optionaly returns the value of the actual data type
                       checked.

    Options - Set of options that control how the check is done.

Return Value:

    NTSTATUS.

--*/
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION FileStdInfo;
    HANDLE SectionHandle;
    PVOID BaseAddress;
    SIZE_T ViewSize;

    Status = ZwQueryInformationFile(FileHandle,
                                    &IoStatusBlock,
                                    &FileStdInfo,
                                    sizeof(FileStdInfo),
                                    FileStandardInformation);
    if (NT_ERROR(Status))
        return Status;

    Status = ZwCreateSection(&SectionHandle,
                             SECTION_MAP_READ,
                             NULL,
                             NULL,
                             PAGE_READONLY,
                             SEC_COMMIT,
                             FileHandle);
    if (!NT_SUCCESS(Status))
        return Status;

    BaseAddress = NULL;
    ViewSize = 0;
    Status = ZwMapViewOfSection(SectionHandle,
                                ZwCurrentProcess(),
                                &BaseAddress,
                                0,
                                0,
                                NULL,
                                &ViewSize,
                                ViewUnmap,
                                0,
                                PAGE_READONLY);
    if (!NT_SUCCESS(Status))
        return Status;

    if (FileStdInfo.EndOfFile.QuadPart > (LONGLONG)ViewSize) {
        Status = STATUS_INVALID_BLOCK_LENGTH;
    }
    else {
        Status = WcVerifyData(BaseAddress,
                              (SIZE_T)FileStdInfo.EndOfFile.QuadPart,
                              DataType,
                              ReturnedDataType,
                              Options);
    }

    ZwUnmapViewOfSection(ZwCurrentProcess(), BaseAddress);
    ZwClose(SectionHandle);
    return Status;
}

static
_Must_inspect_result_
NTSTATUS
_WcVerifyData(
    _In_ const VOID* Data,
    _In_ SIZE_T Size,
    _In_ DWORD DataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    )
{
    BLOB Tmp = { 0 };
    NTSTATUS Status;

    __try {
        switch (DataType) {
        case DATA_TYPE_IMAGE:
            Status = WcVerifyImageSignature(Data, Size, Options);
            break;

        case DATA_TYPE_CERT_BASE64_HDR:
        {
            PCHAR ptr;

            ptr = Base64Header((PCCHAR)Data, Size, TRUE, NULL);
            if (!ptr)
                return STATUS_BAD_DATA;

            Size -= RtlPointerToOffset(Data, ptr);
            Data = ptr;

            if (!Base64Header((PCCHAR)Data, Size, FALSE, &ptr))
                return STATUS_BAD_DATA;

            Size = RtlPointerToOffset(Data, ptr);
        }

        case DATA_TYPE_CERT_BASE64:
            Status = Base64Decode((PCCHAR)Data,
                                  Size,
                                  !!(DataType & DATA_TYPE_STRICT),
                                  &Tmp);
            if (!NT_SUCCESS(Status))
                return Status;

            Data = Tmp.pBlobData;
            Size = Tmp.cbSize;

        case DATA_TYPE_CERT_BINARY:
            Status = WcVerifyCertificate(Data, Size, Options);
            break;

        default:
            return STATUS_INVALID_PARAMETER;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = GetExceptionCode();
    }

    BlobFree(&Tmp);
    return Status;
}

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyData(
    _In_reads_(Size) const VOID* Data,
    _In_ SIZE_T Size,
    _In_ DWORD DataType,
    _Out_opt_ PULONG ReturnedDataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    )
{
    ULONG Count;
    ULONG i;
    NTSTATUS Status;
    const DWORD* DataTypePtr;
    ULONG LocalReturnedDataType;
    static const DWORD TypeOrder[] = {
        DATA_TYPE_IMAGE,
        DATA_TYPE_CERT_BASE64_HDR,
        DATA_TYPE_CERT_BASE64,
        DATA_TYPE_CERT_BINARY
    };

    if (!ReturnedDataType) {
        ReturnedDataType = &LocalReturnedDataType;
    }

    switch (DataType) {
    case DATA_TYPE_ANY:
        DataTypePtr = TypeOrder;
        Count = RTL_NUMBER_OF(TypeOrder);
        break;

    case DATA_TYPE_CERT_ANY:
        DataTypePtr = &TypeOrder[1];
        Count = RTL_NUMBER_OF(TypeOrder) - 1;
        break;

    default:
        //
        // Simply call the internal function directly
        //
        *ReturnedDataType = DataType;
        return _WcVerifyData(Data, Size, DataType, Options);
    }

    for (i = 0; i < Count; i++) {
        Status = _WcVerifyData(Data, Size, *DataTypePtr, Options);
        *ReturnedDataType = *DataTypePtr;

        if (Status != STATUS_BAD_DATA && Status != STATUS_INVALID_IMAGE_FORMAT)
            return Status;

        DataTypePtr++;
    }

    return Status;
}
