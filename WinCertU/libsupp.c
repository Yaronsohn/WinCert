/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#pragma warning(disable:4996)

#include <Windows.h>
#include <winternl.h>
#include "../WinCert.h"

/* FUNCTIONS ******************************************************************/

#ifndef NtCurrentPeb
#define NtCurrentPeb() NtCurrentTeb()->ProcessEnvironmentBlock
#endif

#define RtlGetProcessHeap() (NtCurrentPeb()->Reserved4[1])

NTSYSAPI
_Must_inspect_result_
_Ret_maybenull_
_Post_writable_byte_size_(Size)
PVOID
NTAPI
RtlAllocateHeap(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _In_ SIZE_T Size
    );

_Success_(return != 0)
NTSYSAPI
BOOL
NTAPI
RtlFreeHeap(
    _In_ PVOID HeapHandle,
    _In_opt_ ULONG Flags,
    _Frees_ptr_opt_ PVOID BaseAddress
    );

PVOID
NTAPI
WcAllocateMemory(
    _In_ SIZE_T Bytes,
    _In_opt_ ULONG Tag
    )
{
    UNREFERENCED_PARAMETER(Tag);

    //
    // N.B. We do not zero the memory - the caller can do it if necessary
    //
    return RtlAllocateHeap(RtlGetProcessHeap(), 0, Bytes);
}

VOID
NTAPI
WcFreeMemory(
    _Pre_notnull_ __drv_freesMem(P) PVOID Mem,
    _In_ ULONG Tag
    )
{
    UNREFERENCED_PARAMETER(Tag);

    RtlFreeHeap(RtlGetProcessHeap(), 0, Mem);
}

VOID
NTAPI
WcQuerySystemTime(
    _Out_ PLARGE_INTEGER SystemTime
    )
{
    GetSystemTimeAsFileTime((LPFILETIME)SystemTime);
}

BOOLEAN
NTAPI
WcAttachToSystem(
    _Inout_ struct KAPC_STATE* ApcState
    )
{
    return FALSE;
}

VOID
NTAPI
WcDetachFromSystem(
    _Inout_ struct KAPC_STATE* ApcState
    )
{
}