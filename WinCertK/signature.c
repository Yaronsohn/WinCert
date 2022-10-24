/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include "../ntrtl.h"
#include <bcrypt.h>

/* FUNCTIONS ******************************************************************/

NTSTATUS
NTAPI
RtlVerifyImageSignatureByHandle(
    _In_ HANDLE FileHandle
    )
{
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatusBlock;
    FILE_STANDARD_INFORMATION FileStdInfo;
    HANDLE SectionHandle;
    PVOID ImageBase;
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

    ImageBase = NULL;
    ViewSize = 0;
    Status = ZwMapViewOfSection(SectionHandle,
                                ZwCurrentProcess(),
                                &ImageBase,
                                0,
                                0,
                                NULL,
                                &ViewSize,
                                ViewUnmap,
                                0,
                                PAGE_READONLY);
    ZwClose(FileHandle);
    if (!NT_SUCCESS(Status))
        return Status;

    if (FileStdInfo.EndOfFile.QuadPart > (LONGLONG)ViewSize) {
        Status = STATUS_INVALID_BLOCK_LENGTH;
    }
    else {
        Status = RtlVerifyImageSignature(ImageBase, ViewSize, TRUE);
    }

    ZwUnmapViewOfSection(ZwCurrentProcess(), ImageBase);
    ZwClose(SectionHandle);
    return Status;
}

static
NTSTATUS
RtlpHashImage(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ LPCWSTR AlgorithmId
    )
{
    NTSTATUS Status;
    BCRYPT_ALG_HANDLE AlgorithmHandle = NULL;
    BCRYPT_HASH_HANDLE HashHandle = NULL;
    DWORD HashObjSize;
    DWORD ReturnedLength;
    PVOID HashObj = NULL;
    DWORD HashSize;
    PVOID Hash = NULL;

    Status = BCryptOpenAlgorithmProvider(&AlgorithmHandle,
                                         AlgorithmId,
                                         NULL,
                                         0);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = BCryptGetProperty(AlgorithmHandle,
                               BCRYPT_OBJECT_LENGTH,
                               (PCHAR)&HashObjSize,
                               sizeof(HashObjSize),
                               &ReturnedLength,
                               0);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    HashObj = RtlpAllocateMemory(HashObjSize, 'OhsH');
    if (!HashObj)
        goto Cleanup;

    Status = BCryptGetProperty(AlgorithmHandle,
                               BCRYPT_HASH_LENGTH,
                               (PCHAR)&HashSize,
                               sizeof(HashSize),
                               &ReturnedLength,
                               0);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    Hash = RtlpAllocateMemory(HashSize, 'hsaH');
    if (!Hash)
        goto Cleanup;

    Status = BCryptCreateHash(AlgorithmHandle,
                              &HashHandle,
                              HashObj,
                              HashObjSize,
                              NULL,
                              0,
                              0);
    if (!NT_SUCCESS(Status))
        goto Cleanup;



Cleanup:
    if (Hash) {
        RtlpFreeMemory(HashObj, 'OhsH');
    }

    if (HashObj) {
        RtlpFreeMemory(HashObj, 'OhsH');
    }

    BCryptCloseAlgorithmProvider(AlgorithmHandle, 0);
    return Status;
}

NTSTATUS
NTAPI
RtlVerifyImageSignature(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ BOOLEAN MappedAsImage
    )
{
    PIMAGE_NT_HEADERS NtHeaders;
    CONST WIN_CERTIFICATE *CertTable;
    ULONG CertTableSize;

    if (LDR_IS_DATAFILE(ImageBase)) {
        MappedAsImage = TRUE;
        ImageBase = LDR_DATAFILE_TO_VIEW(ImageBase);
    }

    __try {
        NtHeaders = RtlImageNtHeader(ImageBase);
        if (!NtHeaders)
            return STATUS_INVALID_IMAGE_FORMAT;

        CertTable = RtlImageDirectoryEntryToData(ImageBase,
                                                 MappedAsImage,
                                                 IMAGE_DIRECTORY_ENTRY_SECURITY,
                                                 &CertTableSize);
        if (!CertTable)
            return STATUS_INVALID_SIGNATURE;


    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}
