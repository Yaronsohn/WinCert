/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#include "WinCerti.h"

/* FUNCTIONS ******************************************************************/

NTSTATUS
BlobAlloc(
    _Out_ PBLOB Blob,
    _In_ SIZE_T Size
    )
{
    PBYTE mem;

    if (Size > MAXULONG)
        return STATUS_INVALID_PARAMETER;

    mem = WcAllocateMemory(Size, 0);
    if (!mem)
        return STATUS_INSUFFICIENT_RESOURCES;

    Blob->cbSize = (ULONG)Size;
    Blob->pBlobData = mem;
    return STATUS_SUCCESS;
}

VOID
BlobFree(
    _Inout_ PBLOB Blob
    )
{
    if (Blob->pBlobData) {
        WcFreeMemory(Blob->pBlobData, 0);
    }

    RtlZeroMemory(Blob, sizeof(BLOB));
}
