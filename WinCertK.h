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
    _In_ PFILE_OBJECT FileObject
    );

#ifdef __cplusplus
}
#endif

#endif // _WIN_CERT_KM_H_
