// test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <winternl.h>
#include "../WinCert.h"

#pragma comment(lib, "WinCertU")
#pragma comment(lib, "ntdll")
#pragma comment(lib, "bcrypt")

int main()
{
    HANDLE FileHandle;
    NTSTATUS Status;
    WIN_CERT_X520 X520 = { 0 };
    WIN_CERT_OPTIONS options = { 0 };
    DWORD DataType;
    IO_STATUS_BLOCK IoStatusBlock;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING NameString;
    static const BYTE CommonName[] = { 'A','d','o','b','e',' ','I','n','c','.' };

    RtlInitUnicodeString(&NameString, L"\\SystemRoot\\system32\\ntdll.dll");
    InitializeObjectAttributes(&ObjectAttributes,
                               &NameString,
                               OBJ_CASE_INSENSITIVE,
                               0,
                               NULL);
    Status = NtOpenFile(&FileHandle,
                        GENERIC_READ | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_DELETE,
                        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
        return Status;

    //
    // Initialize the size field
    //
    options.Size = sizeof(options);

    Status = WcVerifyFileByHandle(FileHandle, 0, &DataType, &options);

    CloseHandle(FileHandle);
    return Status;
}
