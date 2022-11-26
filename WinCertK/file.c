/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include <ntifs.h>
#include <windef.h>
#include "../WinCertK.h"

/* GLOBALS ********************************************************************/

const LARGE_INTEGER WcHalfSecond = { (ULONG)(-5 * 100 * 1000 * 10), -1 };

/* FUNCTIONS ******************************************************************/

NTSYSAPI
NTSTATUS
NTAPI
MmCreateSection(
    _Out_ PVOID* SectionObject,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER InputMaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle,
    _In_opt_ PFILE_OBJECT FileObject
    );

NTSYSAPI
NTSTATUS
NTAPI
MmMapViewOfSection(
    _In_ PVOID SectionToMap,
    _In_ PEPROCESS Process,
    _Inout_ PVOID* CapturedBase,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T CapturedViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    );

NTSYSAPI
NTSTATUS
NTAPI
MmUnmapViewOfSection(
    _In_ PEPROCESS Process,
    _In_ PVOID BaseAddress
    );

#pragma alloc_text(PAGED, WcVerifyFileByFileObject)

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyFileByFileObject(
    _In_ PFILE_OBJECT FileObject,
    _In_ DWORD DataType,
    _Out_opt_ PULONG ReturnedDataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    )
/*++

Routine Description:

    This function creates a section object for the specified file, maps it to
    the system address space and checks the digital signature (if one exists).

Arguments:

    FileObject - A pointer to the file object to check.

    DataType - The type of the data in the file specified by FileObject.
               See WcVerifyData.

    ReturnedDataType - Optionaly returns the value of the actual data type
                       checked.

    Options - Set of options that control how the check is done.

Return Value:

    NTSTATUS.

--*/
{
    BOOLEAN Attached = FALSE;
    KAPC_STATE ApcState;
    NTSTATUS Status;
    PVOID SectionObject;
    FILE_STANDARD_INFORMATION FileStdInfo;
    ULONG ReturnedLength;
    PVOID ImageBase;
    SIZE_T ViewSize;
    ULONG RetryCount;
    LARGE_INTEGER MaximumSize;
    LARGE_INTEGER Offset;
    
    PAGED_CODE();

    Status = IoQueryFileInformation(FileObject,
                                    FileStandardInformation,
                                    sizeof(FileStdInfo),
                                    &FileStdInfo,
                                    &ReturnedLength);
    if (NT_ERROR(Status))
        return Status;

    RetryCount = 0;
    for (;;) {
        MaximumSize = FileStdInfo.EndOfFile;
        Status = MmCreateSection(&SectionObject,
                                 SECTION_MAP_READ,
                                 NULL,
                                 &MaximumSize,
                                 PAGE_READONLY,
                                 SEC_COMMIT,
                                 NULL,
                                 FileObject);
        if (NT_SUCCESS(Status))
            break;

        if (Status != STATUS_FILE_LOCK_CONFLICT || RetryCount >= 3)
            return Status;

        //
        // The filesystem may have rejected the request for various
        // reasons - try again.
        //
        RetryCount++;
        KeDelayExecutionThread(KernelMode,
                               FALSE,
                               (PLARGE_INTEGER)&WcHalfSecond);
    }

    ViewSize = 0;
    ImageBase = NULL;
    Offset.QuadPart = 0;
    Status = MmMapViewOfSection(SectionObject,
                                PsInitialSystemProcess,
                                &ImageBase,
                                0,
                                0,
                                &Offset,
                                &ViewSize,
                                ViewUnmap,
                                0,
                                PAGE_READONLY);
    if (NT_SUCCESS(Status)) {
        if (FileStdInfo.EndOfFile.QuadPart > (LONGLONG)ViewSize) {
            Status = STATUS_INVALID_BLOCK_LENGTH;
        }
        else {
            if (PsGetCurrentProcess() != PsInitialSystemProcess) {
                Attached = TRUE;
                KeStackAttachProcess(PsInitialSystemProcess, &ApcState);
            }

            Status = WcVerifyData(ImageBase,
                                  (SIZE_T)FileStdInfo.EndOfFile.QuadPart,
                                  DataType,
                                  ReturnedDataType,
                                  Options);

            if (Attached) {
                KeUnstackDetachProcess(&ApcState);
            }
        }

        MmUnmapViewOfSection(PsInitialSystemProcess, ImageBase);
    }

    ObDereferenceObject(SectionObject);
    return Status;
}