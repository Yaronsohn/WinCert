// test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>
#include "../WinCert.h"
#include <WinTrust.h>

#pragma comment(lib, "bcrypt")

int main()
{
    HANDLE FileHandle;
    NTSTATUS Status;

    FileHandle = CreateFileW(L"c:\\windows\\system32\\ntdll.dll",
                             //L"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
                             GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_DELETE,
                             NULL,
                             OPEN_EXISTING,
                             0,
                             NULL);
    if (FileHandle == INVALID_HANDLE_VALUE)
        return NULL;

    Status = WcVerifyImageSignatureByHandle(FileHandle);

    CloseHandle(FileHandle);
    return Status;
}
