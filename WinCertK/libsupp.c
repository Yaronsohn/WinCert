/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#pragma warning(disable:4996)

#include <ntifs.h>
#include <windef.h>
#include "../WinCertK.h"

/* FUNCTIONS ******************************************************************/

#pragma alloc_text(PAGED, WcAllocateMemory)
#pragma alloc_text(PAGED, WcFreeMemory)

PVOID
NTAPI
WcAllocateMemory(
    _In_ SIZE_T Bytes,
    _In_opt_ ULONG Tag
    )
{
    PAGED_CODE();

    return ExAllocatePoolWithTag(NonPagedPool, Bytes, Tag);
}

VOID
NTAPI
WcFreeMemory(
    _Pre_notnull_ __drv_freesMem(P) PVOID Mem,
    _In_ ULONG Tag
    )
{
    PAGED_CODE();

    ExFreePoolWithTag(Mem, Tag);
}

VOID
NTAPI
WcQuerySystemTime(
    _Out_ PLARGE_INTEGER SystemTime
    )
{
    KeQuerySystemTime(SystemTime);
}

BOOLEAN
NTAPI
WcAttachToSystem(
    _Inout_ KAPC_STATE* ApcState
    )
{
    if (PsGetCurrentProcess() == PsInitialSystemProcess)
        return FALSE;

    KeStackAttachProcess(PsInitialSystemProcess, ApcState);
    return TRUE;
}

VOID
NTAPI
WcDetachFromSystem(
    _Inout_ KAPC_STATE* ApcState
    )
{
    KeUnstackDetachProcess(ApcState);
}
