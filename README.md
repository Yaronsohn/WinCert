# WinCert
WinCert is a package for verifying certificates and digital signatures for Microsoft's Windows.

## Features
- Applicable for both _User-mode_ and _Kernel-mode_ code.
- Doesn't require any third party libraries (except for what comes with the OS).
- Provides the caller great deal of control over the certificate verification process:
  - You can control which kind of tests the library performs on certificates in the chain.
  - You can enforce certain requirements from the certificates like who must be the Issuer or who the Subject is, the time limitations and more.
  - You can limit the accepted cryptographic algorithms.
-Requires Windows Vista and above.
- The whole certificate chain is verified up to the root which is verified against the OS's root certificate database.

## Limitations
- The library does **not** performs a check against the revocation lists.
- The library does **not** go out to the network to fetch any additional data.

## Structure
The package includes three libraries:
- WinCert: This is a mode-agnostic library that is shared between user mode and kernel mode - you should not use this library directly.
- WinCertU: This is the *User mode* wrapper that provides the needed services needed by the WinCert library. Use this library when creating a user mode application and/or library.
- WinCertK: This is the *Kernel mode* wrapper that provides the needed services needed by the WinCert library. Use this library when creating a kernel mode driver.

## Usage
In order to use the library you need to call one of the functions below.
The library provides more functions for a more specific need.

WinCert.h (user mode and kernel mode):
```c
_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyData(
    _In_reads_(Size) const VOID* Data,
    _In_ SIZE_T Size,
    _In_ DWORD DataType,
    _Out_opt_ PULONG ReturnedDataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyFileByHandle(
    _In_ HANDLE FileHandle,
    _In_ DWORD DataType,
    _Out_opt_ PULONG ReturnedDataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );
```

WinCertK.h (kernel mode only):
```c
_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyFileByFileObject(
    _In_ PFILE_OBJECT FileObject,
    _In_ DWORD DataType,
    _Out_opt_ PULONG ReturnedDataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );
```

## Compiling the libraries
The package requires that the DDK or the WDK be installed on your computer. You might need to update the project's
include and lib directories according to where you installed the DDK/WDK.

## Linking
You will need to link with BCRYPT.LIB when building you project for user mode and CNG.LIB when building for kernel mode.

If you build a user mode executable/DLL, you will also need NTDLL.LIB (available from the DDK/WDK).
