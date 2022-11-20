// test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include <winternl.h>
#include "../WinCert.h"
#include <ntstatus.h>

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

    //
    // Open the test DLL.
    //
    // N.B. There is nothing special about the handle. You can use the Win32
    // CreateFile function if you are more familiar with it.
    //
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
    if (NT_SUCCESS(Status)) {

        //
        // Initialize the size field.
        //
        // N.B. For now, we don't realy use the options variable so we can simply
        // pass a NULL value. It is here for visibility.
        //
        options.Size = sizeof(options);

        //
        // N.B. While we do know that file is of type DATA_TYPE_IMAGE, we pass
        // DATA_TYPE_ANY to challenge the function.
        //
        Status = WcVerifyFileByHandle(FileHandle,
                                      DATA_TYPE_ANY,
                                      &DataType,
                                      &options);
        if (Status != STATUS_UNSUCCESSFUL) {

            //
            // N.B. In most cases, the function might be able to identify the
            // type of the data even if the veritifcation fails.
            //
            if (DataType != DATA_TYPE_IMAGE) {
                Status = STATUS_UNSUCCESSFUL;
            }
        }
        NtClose(FileHandle);
    }
    return Status;
}
