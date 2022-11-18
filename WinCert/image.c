/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include "WinCerti.h"
#include <ntimage.h>

/* FUNCTIONS ******************************************************************/

static
_Must_inspect_result_
NTSTATUS
ImgBuildHashBlobArray(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize,
    _Out_ PBLOB *HashBlobArray,
    _Out_ PULONG HashBlobArrayLength
    )
{
    NTSTATUS Status;
    PIMAGE_NT_HEADERS NtHeaders;
    PULONG Checksum;
    PIMAGE_DATA_DIRECTORY SecurityDir;
    ULONG SizeOfHeaders;
    ULONG SecDirOffset;
    ULONG SecDirSize;
    ULONG SectionTableOffset;
    ULONG NumOfSections;
    PIMAGE_SECTION_HEADER SectionTableEntry;
    PIMAGE_SECTION_HEADER *SectionTable = NULL;
    ULONG ValidSections;
    ULONG NextSec;
    ULONG BytesHashed;
    ULONG ExtraData;
    PBLOB Blobs = NULL;
    ULONG BlobCount = 0;
    PVOID ImageEnd = RtlOffsetToPointer(ImageBase, ImageSize);
    ULONG NextBlob;

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
            Checksum = &((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.CheckSum;
            SecurityDir = &((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            SizeOfHeaders = ((PIMAGE_NT_HEADERS32)NtHeaders)->OptionalHeader.SizeOfHeaders;
            break;

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            Checksum = &((PIMAGE_NT_HEADERS64)NtHeaders)->OptionalHeader.CheckSum;
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
            if ((SecDirOffset + SecDirSize) < SecDirOffset)
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

        //
        // Create a list of all section to be hashed
        //
        SectionTable = WcAllocateMemory(sizeof(PIMAGE_SECTION_HEADER) * NtHeaders->FileHeader.NumberOfSections, 0);
        if (!SectionTable) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        BytesHashed = SizeOfHeaders;
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

                BytesHashed += SectionTableEntry->SizeOfRawData;
                SectionTable[NextSec] = SectionTableEntry;
                ValidSections++;
            }

            SectionTableEntry++;
            NumOfSections--;
        }

        ExtraData = (ULONG)ImageSize - (SecurityDir->Size + BytesHashed);

        BlobCount = (ExtraData ? 4 : 3) + ValidSections;

        Blobs = WcAllocateMemory(sizeof(BLOB) * BlobCount, 0);
        if (!Blobs) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        NextBlob = 0;

        //
        // #3
        //
        Blobs[NextBlob].pBlobData = ImageBase;
        Blobs[NextBlob].cbSize = RtlPointerToOffset(ImageBase, Checksum);
        NextBlob++;

        //
        // #5
        Blobs[NextBlob].pBlobData = RtlOffsetToPointer(Checksum, sizeof(NtHeaders->OptionalHeader.CheckSum));
        Blobs[NextBlob].cbSize = RtlPointerToOffset(Blobs[1].pBlobData, SecurityDir);
        NextBlob++;

        //
        // #7
        //
        Blobs[NextBlob].pBlobData = RtlOffsetToPointer(SecurityDir, sizeof(*SecurityDir));
        Blobs[NextBlob].cbSize = SizeOfHeaders - RtlPointerToOffset(ImageBase, Blobs[2].pBlobData);
        NextBlob++;

        NextSec = 0;
        for (NextSec = 0; NextSec < ValidSections; NextSec++) {
            Blobs[NextBlob].pBlobData = RtlOffsetToPointer(ImageBase, SectionTable[NextSec]->PointerToRawData);
            Blobs[NextBlob].cbSize = SectionTable[NextSec]->SizeOfRawData;
            NextBlob++;
        }

        if (ExtraData) {
            Blobs[NextBlob].pBlobData = RtlOffsetToPointer(ImageBase, BytesHashed);
            Blobs[NextBlob].cbSize = ExtraData;
            NextBlob++;
        }

        ASSERT(NextBlob == BlobCount);

        *HashBlobArray = Blobs;
        *HashBlobArrayLength = BlobCount;

        Status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (Blobs) {
            WcFreeMemory(Blobs, 0);
        }

        Status = STATUS_INVALID_IMAGE_FORMAT;
    }

    if (SectionTable) {
        WcFreeMemory(SectionTable, 'ThsH');
    }

    return Status;
}

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyImageSignature(
    _In_ const VOID* ImageBase,
    _In_ SIZE_T ImageSize,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    )
/*++

Routine Description:

    This function checks the digital signature of the mapped image.

    WARNING! Because this code is compatible between user mode and kernel mode,
    the function does NOT probe the buffer pointed to by ImageBase before
    accessing it - If the code is executed in kernel mode, it is the
    responsibility of the caller to ensure the validity of the buffer -
    including probing the whole ImageSize bytes, BEFORE calling this function.

Arguments:

    ImageBase - Base address of the image to hash.

    ImageSize - The size (in bytes) of the image.

    Options - Set of options that control how the check is done.

Return Value:

    NTSTATUS.

--*/
{
    PVOID CertTable;
    ULONG CertTableSize;
    LPWIN_CERTIFICATE Cert, CertEnd;
    NTSTATUS Status;
    PBLOB HashBlobArray;
    ULONG HashBlobArrayLength;
    BLOB Pkcs7;

    if (LDR_IS_DATAFILE(ImageBase)) {
        ImageBase = LDR_DATAFILE_TO_VIEW(ImageBase);
    }

    __try {
        Status = ImgBuildHashBlobArray((PVOID)ImageBase,
                                       ImageSize,
                                       &HashBlobArray,
                                       &HashBlobArrayLength);
        if (!NT_SUCCESS(Status))
            return Status;

        CertTable = RtlImageDirectoryEntryToData((PVOID)ImageBase,
                                                 TRUE,
                                                 IMAGE_DIRECTORY_ENTRY_SECURITY,
                                                 &CertTableSize);
        if (!CertTable) {
            Status = STATUS_NO_SIGNATURE;
            __leave;
        }

        Cert = (LPWIN_CERTIFICATE)CertTable;
        CertEnd = (LPWIN_CERTIFICATE)RtlOffsetToPointer(CertTable, CertTableSize);
        while (Cert < CertEnd) {
            if (Cert->wRevision == WIN_CERT_REVISION_2_0
                &&
                Cert->wCertificateType == WIN_CERT_TYPE_PKCS_SIGNED_DATA
                &&
                Cert->dwLength >= (ULONG)FIELD_OFFSET(WIN_CERTIFICATE, bCertificate)) {

                Pkcs7.cbSize = Cert->dwLength - FIELD_OFFSET(WIN_CERTIFICATE, bCertificate);
                Pkcs7.pBlobData = (PBYTE)Cert->bCertificate;
                Status = Pkcs7Verify(&Pkcs7,
                                     HashBlobArray,
                                     HashBlobArrayLength,
                                     Options);
                if (NT_SUCCESS(Status))
                    __leave;
            }

            //
            // Get the next certificate
            //
            Cert = (LPWIN_CERTIFICATE)RtlOffsetToPointer(Cert, Cert->dwLength);

            //
            // Align to 8 bytes
            //
            Cert = (LPWIN_CERTIFICATE)ALIGN_UP_POINTER_BY(Cert, 8);
        }

        Status = STATUS_INVALID_SIGNATURE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = STATUS_INVALID_IMAGE_FORMAT;
    }

    WcFreeMemory(HashBlobArray, 0);
    return Status;
}
