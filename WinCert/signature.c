/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <windef.h>
#include "../WinCert.h"
#include <bcrypt.h>
#include <ntimage.h>

/* FUNCTIONS ******************************************************************/

#ifndef LDR_IS_DATAFILE
#define LDR_IS_DATAFILE(x)      (((ULONG_PTR)(x)) &  (ULONG_PTR)1)
#endif

#ifndef LDR_DATAFILE_TO_VIEW
#define LDR_DATAFILE_TO_VIEW(x) ((PVOID)(((ULONG_PTR)(x)) & ~(ULONG_PTR)1))
#endif

NTSYSAPI
_Must_inspect_result_
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
    _In_ PVOID Base
    );

NTSYSAPI
_Must_inspect_result_
PVOID
NTAPI
RtlImageDirectoryEntryToData(
    _In_ PVOID Base,
    _In_ BOOLEAN MappedAsImage,
    _In_ USHORT DirectoryEntry,
    _Out_ PULONG Size
    );

NTSTATUS
NTAPI
WcVerifyImageSignatureByHandle(
    _In_ HANDLE FileHandle
    )
/*++

Routine Description:

    This function creates a section object for the specified file, mapps it to
    the system address space and checks the digital signature (if one exists).

Arguments:

    FileObject - A handl to the file to check.

Return Value:

    NTSTATUS.

--*/
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
        Status = WcVerifyImageSignature(ImageBase, ViewSize, TRUE);
    }

    ZwUnmapViewOfSection(ZwCurrentProcess(), ImageBase);
    ZwClose(SectionHandle);
    return Status;
}

static
NTSTATUS
WcpHashImage(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ LPCWSTR AlgorithmId,
    _Out_ PCRYPT_DATA_BLOB HashBlob
    )
/*++

Routine Description:

    This function hashes the mapped image using the requested algorithm.

Arguments:

    ImageBase - Base address of the image to hash.

    ImageSize - The size (in bytes) of the image.

    AlgorithmId - The algorithm to use for the hashing process.
                  See BCryptOpenAlgorithmProvider for possible values.

    HashBlob - On successfull return, this will hold a pointer to the calculated hash
               and it's length.
               On failure the value is undefined.

Return Value:

    NTSTATUS.

--*/
{
    NTSTATUS Status;
    BCRYPT_ALG_HANDLE AlgorithmHandle = NULL;
    BCRYPT_HASH_HANDLE HashHandle = NULL;
    DWORD HashObjSize;
    DWORD ReturnedLength;
    PVOID HashObj = NULL;
    DWORD HashSize;
    PVOID Hash = NULL;
    PIMAGE_NT_HEADERS NtHeaders;
    ULONG ChecksumOffset;
    PIMAGE_DATA_DIRECTORY SecurityDir;
    ULONG SizeOfHeaders;
    ULONG SecDirOffset;
    ULONG SecDirSize;
    ULONG SectionTableOffset;
    ULONG NumOfSections;
    PIMAGE_SECTION_HEADER SectionTableEntry;
    PVOID After;
    PIMAGE_SECTION_HEADER *SectionTable = NULL;
    ULONG ValidSections;
    ULONG NextSec;
    ULONG BytesHashed;
    ULONG ExtraData;

    __try {
        //
        // Gather all the information we need and perform all checks now
        // before we start with the crypto API - this will simplifies the
        // cleanup in case an error.
        //
        NtHeaders = RtlImageNtHeader(ImageBase);
        if (!NtHeaders)
            return STATUS_INVALID_IMAGE_FORMAT;

        switch (NtHeaders->OptionalHeader.Magic) {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            ChecksumOffset = RtlPointerToOffset(ImageBase, &((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.CheckSum);
            SecurityDir = &((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            SizeOfHeaders = ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.SizeOfHeaders;
            break;

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            ChecksumOffset = RtlPointerToOffset(ImageBase, &((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.CheckSum);
            SecurityDir = &((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            SizeOfHeaders = ((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.SizeOfHeaders;
            break;

        default:
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        SectionTableOffset = FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
            NtHeaders->FileHeader.SizeOfOptionalHeader;

        SecDirOffset = SecurityDir->VirtualAddress;
        SecDirSize = SecurityDir->Size;
        if (SecDirOffset && SecDirSize) {
            //
            // The start of the security dir cannot be past the end-of-image
            //
            if (SecDirOffset > ImageSize)
                return STATUS_INVALID_IMAGE_FORMAT;

            //
            // The security dir needs to be at the very end of the file
            //
            if ((SecDirOffset + SecDirSize) != ImageSize)
                return STATUS_INVALID_IMAGE_FORMAT;

            //
            // Check against invalid values
            //
            if ((SecDirOffset + SecDirSize) != SecDirOffset)
                return STATUS_INVALID_IMAGE_FORMAT;

            //
            // Security dir is in the header space
            //
            if (SecDirOffset < SizeOfHeaders)
                return STATUS_INVALID_IMAGE_FORMAT;

            //
            // Check if the security dir is in the section data
            //
            NumOfSections = NtHeaders->FileHeader.NumberOfSections;
            SectionTableEntry = (PIMAGE_SECTION_HEADER)RtlOffsetToPointer(NtHeaders, SectionTableOffset);
            while (NumOfSections > 0) {
                if (SectionTableEntry->PointerToRawData
                    &&
                    (SectionTableEntry->PointerToRawData + SectionTableEntry->SizeOfRawData) > SecDirOffset) {

                    return STATUS_INVALID_IMAGE_FORMAT;
                }

                SectionTableEntry++;
                NumOfSections--;
            }
        }

        Status = BCryptOpenAlgorithmProvider(&AlgorithmHandle,
                                             AlgorithmId,
                                             NULL,
                                             0);
        if (!NT_SUCCESS(Status))
            __leave;

        Status = BCryptGetProperty(AlgorithmHandle,
                                   BCRYPT_OBJECT_LENGTH,
                                   (PCHAR)&HashObjSize,
                                   sizeof(HashObjSize),
                                   &ReturnedLength,
                                   0);
        if (!NT_SUCCESS(Status))
            __leave;

        HashObj = WcAllocateMemory(HashObjSize, 'OhsH');
        if (!HashObj)
            __leave;

        Status = BCryptGetProperty(AlgorithmHandle,
                                   BCRYPT_HASH_LENGTH,
                                   (PCHAR)&HashSize,
                                   sizeof(HashSize),
                                   &ReturnedLength,
                                   0);
        if (!NT_SUCCESS(Status))
            __leave;

        Hash = WcAllocateMemory(HashSize, 'hsaH');
        if (!Hash)
            __leave;

        Status = BCryptCreateHash(AlgorithmHandle,
                                  &HashHandle,
                                  HashObj,
                                  HashObjSize,
                                  NULL,
                                  0,
                                  0);
        if (!NT_SUCCESS(Status))
            __leave;

        //
        // Hash everything up to the checksum
        //
        Status = BCryptHashData(HashHandle,
                                ImageBase,
                                ChecksumOffset,
                                0);
        if (!NT_SUCCESS(Status))
            __leave;

        //
        // Skip the checksum and hash everything up until the security directory
        //
        After = RtlOffsetToPointer(ImageBase,
                                   ChecksumOffset + sizeof(NtHeaders->OptionalHeader.CheckSum));
        Status = BCryptHashData(HashHandle,
                                After,
                                RtlPointerToOffset(After, SecurityDir),
                                0);
        if (!NT_SUCCESS(Status))
            __leave;

        //
        // Skip the security directory and hash until the end of the image header
        //
        After = SecurityDir + 1;
        Status = BCryptHashData(HashHandle,
                                After,
                                SizeOfHeaders - RtlPointerToOffset(ImageBase, After),
                                0);
        if (!NT_SUCCESS(Status))
            __leave;

        //
        // Hash the sections
        //
        SectionTable = WcAllocateMemory(sizeof(PIMAGE_SECTION_HEADER) * NtHeaders->FileHeader.NumberOfSections,
                                        'ThsH');
        if (!SectionTable) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        //
        // Create a list of all section to be hashed
        //
        ValidSections = 0;
        NumOfSections = NtHeaders->FileHeader.NumberOfSections;
        SectionTableEntry = (PIMAGE_SECTION_HEADER)RtlOffsetToPointer(NtHeaders, SectionTableOffset);
        while (NumOfSections > 0) {

            //
            // Use only section with non-zero size
            //
            if (SectionTableEntry->SizeOfRawData) {

                //
                // Put the section in the table sorted
                //
                NextSec = 0;
                while (NextSec < ValidSections) {
                    if (SectionTable[NextSec]->PointerToRawData > SectionTableEntry->PointerToRawData) {
                        RtlMoveMemory(&SectionTable[NextSec + 1],
                                      &SectionTable[NextSec],
                                      sizeof(PIMAGE_SECTION_HEADER) * (ValidSections - NextSec));
                        break;
                    }

                    NextSec++;
                }

                SectionTable[NextSec] = SectionTableEntry;
                ValidSections++;
            }

            SectionTableEntry++;
            NumOfSections--;
        }

        BytesHashed = SizeOfHeaders;
        for (NextSec = 0; NextSec < ValidSections; NextSec++) {
            Status = BCryptHashData(HashHandle,
                                    RtlOffsetToPointer(ImageBase, SectionTable[NextSec]->PointerToRawData),
                                    SectionTable[NextSec]->SizeOfRawData,
                                    0);
            if (!NT_SUCCESS(Status))
                __leave;

            BytesHashed += SectionTable[NextSec]->SizeOfRawData;
        }

        ExtraData = (ULONG)ImageSize - (SecurityDir->Size + BytesHashed);
        if (ExtraData) {
            Status = BCryptHashData(HashHandle,
                                    RtlOffsetToPointer(ImageBase, BytesHashed),
                                    ExtraData,
                                    0);
            if (!NT_SUCCESS(Status))
                __leave;
        }

        Status = BCryptFinishHash(HashHandle,
                                  Hash,
                                  HashSize,
                                  0);
        if (!NT_SUCCESS(Status))
            __leave;

        HashBlob->cbData = HashSize;
        HashBlob->pbData = Hash;

        Hash = NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = STATUS_INVALID_IMAGE_FORMAT;
    }

    if (SectionTable) {
        WcFreeMemory(SectionTable, 'ThsH');
    }

    if (Hash) {
        WcFreeMemory(HashObj, 'hsaH');
    }

    if (HashObj) {
        WcFreeMemory(HashObj, 'OhsH');
    }

    if (AlgorithmHandle) {
        BCryptCloseAlgorithmProvider(AlgorithmHandle, 0);
    }

    return Status;
}

static
NTSTATUS
WcpCheckCertificate(
    _In_ CONST WIN_CERTIFICATE* Cert
    )
{
    ULONG EncodedDataLength;
    CONST VOID *EncodedData;

    //
    // We only support version 2
    //
    if (Cert->wRevision != WIN_CERT_REVISION_2_0)
        return STATUS_INVALID_SIGNATURE;

    //
    // We only support Authenticode signatures
    //
    if (Cert->wCertificateType != WIN_CERT_TYPE_PKCS_SIGNED_DATA)
        return STATUS_INVALID_SIGNATURE;

    //
    // Sanity check
    //
    if (Cert->dwLength < (ULONG)FIELD_OFFSET(WIN_CERTIFICATE, bCertificate))
        return STATUS_INVALID_SIGNATURE;

    EncodedDataLength = Cert->dwLength - FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);
    EncodedData = Cert->bCertificate;




    return STATUS_SUCCESS;
}

NTSTATUS
NTAPI
WcVerifyImageSignature(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _In_ BOOLEAN MappedAsImage
    )
/*++

Routine Description:

    This function checks the digital signature of the mapped image.

Arguments:

    ImageBase - Base address of the image to hash.

    ImageSize - The size (in bytes) of the image.

    MappedAsImage - FALSE if the file is mapped as a data file.
                    TRUE if the file is mapped as an image.

Return Value:

    NTSTATUS.

--*/
{
    PIMAGE_NT_HEADERS NtHeaders;
    PVOID CertTable;
    ULONG CertTableSize;
    LPWIN_CERTIFICATE NextCert, CertEnd;

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

        NextCert = (LPWIN_CERTIFICATE)CertTable;
        CertEnd = (LPWIN_CERTIFICATE)RtlOffsetToPointer(CertTable, CertTableSize);
        while (NextCert < CertEnd) {


            NextCert = (LPWIN_CERTIFICATE)RtlOffsetToPointer(NextCert, NextCert->dwLength);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}
