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
    static const BYTE CommonName[] = { 'A','d','o','b','e',' ','I','n','c','.' };

    FileHandle = CreateFileW(L"\\\\?\\GlobalRoot\\SystemRoot\\system32\\ntdll.dll",
                             //L"C:\\Program Files\\Adobe\\Acrobat DC\\Acrobat\\Acrobat.exe",
                             GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_DELETE,
                             NULL,
                             OPEN_EXISTING,
                             0,
                             NULL);
    if (FileHandle == INVALID_HANDLE_VALUE)
        return NULL;

    X520.Attributes[X520_CommonName].Data.pBlobData = (PBYTE)CommonName;
    X520.Attributes[X520_CommonName].Data.cbSize = sizeof(CommonName);

    options.Size = sizeof(options);
    //options.Subject = &X520;

    Status = WcVerifyFileByHandle(FileHandle, 0, &DataType, &options);

    CloseHandle(FileHandle);
    return Status;
}
