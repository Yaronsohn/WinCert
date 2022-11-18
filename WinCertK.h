/*++ BUILD Version: 0001    Increment this if a change has global effects

Copyright (c) Yaron Aronsohn. 2010, All Rights Reserved.

Module Name:

    WinCertK.h

Description:

    Master include file for Windows PE/PE+ digital signature verification library.
    (Kernel mode only)

Revision:

    Rev     Date        Programmer          Revision History

--*/
#ifndef _WIN_CERT_KM_H_
#define _WIN_CERT_KM_H_

#include "WinCert.h"

#ifdef __cplusplus
extern "C" {
#endif

NTSTATUS
NTAPI
WcVerifyFileSignatureByFileObject(
    _In_ PFILE_OBJECT FileObject,
    _In_ DWORD DataType,
    _Out_opt_ PULONG ReturnedDataType,
    _In_opt_ const WIN_CERT_OPTIONS* Options
    );

#ifdef __cplusplus
}
#endif

#endif // _WIN_CERT_KM_H_
