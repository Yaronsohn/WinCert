/*++ BUILD Version: 0001    Increment this if a change has global effects

Copyright (c) 2022 Yaron Aronsohn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Module Name:

    WinCert.h

Description:

    Master include file for Windows PE/PE+ digital signature verification library.

Revision:

    Rev     Date        Programmer          Revision History

--*/
#ifndef _WIN_CERT_H_
#define _WIN_CERT_H_

#include <sal.h>
#include "blob.h"

//
// Some error codes used in the library.
// N.B. Since NT does not provide suitable codes for these error,
// these are used in the code.
// All the code are mapped to the generic STATUS_INVALID_SIGNATURE.
// If you need the extra error information, define these macros from
// the command line when building the library.
//
#ifndef STATUS_ALGORITHM_NOT_SUPPORTED
#define STATUS_ALGORITHM_NOT_SUPPORTED STATUS_INVALID_SIGNATURE
#endif

#ifndef STATUS_ISSUER_SIGNATURE_NOT_FOUND
#define STATUS_ISSUER_SIGNATURE_NOT_FOUND STATUS_INVALID_SIGNATURE
#endif

#ifndef STATUS_UNTRUSTED_ROOT
#define STATUS_UNTRUSTED_ROOT STATUS_INVALID_SIGNATURE
#endif

#ifndef STATUS_PARTIAL_CERTIFICATE_CHAIN
#define STATUS_PARTIAL_CERTIFICATE_CHAIN STATUS_INVALID_SIGNATURE
#endif

#ifndef STATUS_CYCLIC_CERTIFICATE_CHAIN
#define STATUS_CYCLIC_CERTIFICATE_CHAIN STATUS_INVALID_SIGNATURE
#endif

#ifndef STATUS_INVALID_RSA_INFORMATION
#define STATUS_INVALID_RSA_INFORMATION STATUS_INVALID_SIGNATURE
#endif

#if !defined(WINTRUST_H) && !defined(_INTERNALS_WINDOWS_NT_TYPES_H_)
#include <pshpack1.h>
typedef struct _WIN_CERTIFICATE {
    DWORD       dwLength;
    WORD        wRevision;
    WORD        wCertificateType;
    BYTE        bCertificate[ANYSIZE_ARRAY];
} WIN_CERTIFICATE, * LPWIN_CERTIFICATE;
#include <poppack.h>

#define WIN_CERT_REVISION_1_0               (0x0100)
#define WIN_CERT_REVISION_2_0               (0x0200)

#define WIN_CERT_TYPE_X509                  (0x0001)   // bCertificate contains an X.509 Certificate
#define WIN_CERT_TYPE_PKCS_SIGNED_DATA      (0x0002)   // bCertificate contains a PKCS SignedData structure
#define WIN_CERT_TYPE_RESERVED_1            (0x0003)   // Reserved
#define WIN_CERT_TYPE_TS_STACK_SIGNED       (0x0004)   // Terminal Server Protocol Stack Certificate signing
#endif // !defined(WINTRUST_H) && !defined(_INTERNALS_WINDOWS_NT_TYPES_H_)

#ifdef __cplusplus
extern "C" {
#endif

extern const LARGE_INTEGER WcHalfSecond;

__drv_allocatesMem(Mem)
_Post_writable_byte_size_(Bytes)
_Must_inspect_result_
PVOID
NTAPI
WcAllocateMemory(
    _In_ SIZE_T Bytes,
    _In_opt_ ULONG Tag
    );

VOID
NTAPI
WcFreeMemory(
    _Pre_notnull_ __drv_freesMem(P) PVOID Mem,
    _In_ ULONG Tag
    );

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyImageSignatureByHandle(
    _In_ HANDLE FileHandle
    );

_Must_inspect_result_
NTSTATUS
NTAPI
WcVerifyImageSignature(
    _In_ PVOID ImageBase,
    _In_ SIZE_T ImageSize
    );

//
// ASN1 DER Tags Classes
//
#define ASN1_DER_CLASS_UNIVERSAL        (0x00)
#define ASN1_DER_CLASS_APPLICATION      (0x40)
#define ASN1_DER_CLASS_CONTEXT_DEFINED  (0x80)
#define ASN1_DER_CLASS_PRIVATE          (0xC0)

#define TAG_TO_CLASS(tag) ((UCHAR)(tag) & 0xC0)

//
// ASN1 DER Forms
//
#define ASN1_DER_FORM_PRIMITIVE         (0x00)
#define ASN1_DER_FORM_CONSTRUCTED       (0x20)

#define TAG_TO_FORM(tag) ((UCHAR)(tag) & 0x20)

#define DEFTAG(class, form, x) \
    ((class) | (form) | (x))

typedef enum _ASN1_TAG {
    ASN1_TAG_RESERVED0        = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 0),
    ASN1_TAG_BOOLEAN          = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 1),
    ASN1_TAG_INTEGER          = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 2),
    ASN1_TAG_BITSTRING        = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 3),
    ASN1_TAG_OCTETSTRING      = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 4),
    ASN1_TAG_NULL             = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 5),
    ASN1_TAG_OID              = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 6),
    ASN1_TAG_OBJDESCRIPTOR    = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 7),
    ASN1_TAG_EXTERNAL         = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 8),
    ASN1_TAG_REAL             = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 9),
    ASN1_TAG_ENUMERATED       = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 10),
    ASN1_TAG_EMBEDDEDPDV      = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 11),
    ASN1_TAG_UTF8STRING       = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 12),
    ASN1_TAG_RELATIVEOID      = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 13),
    ASN1_TAG_TIME             = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 14),
    ASN1_TAG_RESERVED15       = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 15),
    ASN1_TAG_SEQUENCE         = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_CONSTRUCTED, 16),
    ASN1_TAG_SEQUENCE_OF      = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_CONSTRUCTED, 16),
    ASN1_TAG_SET              = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_CONSTRUCTED, 17),
    ASN1_TAG_SET_OF           = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_CONSTRUCTED, 17),
    ASN1_TAG_NUMERICSTRING    = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 18),
    ASN1_TAG_PRINTABLESTRING  = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 19),
    ASN1_TAG_TELETEXSTRING    = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 20),
    ASN1_TAG_T61STRING        = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 20),
    ASN1_TAG_VIDEOTEXSTRING   = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 21),
    ASN1_TAG_IA5STRING        = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 22),
    ASN1_TAG_UTCTIME          = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 23),
    ASN1_TAG_GENERALIZEDTIME  = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 24),
    ASN1_TAG_GRAPHICSTRING    = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 25),
    ASN1_TAG_VISIBLESTRING    = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 26),
    ASN1_TAG_GENERALSTRING    = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 27),
    ASN1_TAG_UNIVERSALSTRING  = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 28),
    ASN1_TAG_CHARACTERSTRING  = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 29),
    ASN1_TAG_BMPSTRING        = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 30),
    ASN1_TAG_DATE             = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 31),
    ASN1_TAG_TIMEOFDAY        = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 32),
    ASN1_TAG_DATETIME         = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 33),
    ASN1_TAG_DURATION         = DEFTAG(ASN1_DER_CLASS_UNIVERSAL, ASN1_DER_FORM_PRIMITIVE, 34),
} ASN1_TAG, *PASN1_TAG;

typedef struct _ASN1_VALUE_DECRIPTOR {
    union {

#define ADF_STEPIN      (0x00000001L)
#define ADF_STEPOUT     (0x00000002L)
#define ADF_OPTIONAL    (0x00000004L)

        ULONG Flags;

        struct {
            ULONG StepIn : 1;
            ULONG StepOut : 1;
            ULONG Optional : 1;
            ULONG ReservedFlags : 29;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;
    ASN1_TAG Tag;
    ULONG ValueIndex;
} ASN1_VALUE_DECRIPTOR, *PASN1_VALUE_DECRIPTOR;

typedef struct _ASN1_VALUE {
    BLOB Raw;
    ASN1_TAG Tag;
    BLOB Data;
} ASN1_VALUE, *PASN1_VALUE;

_Must_inspect_result_
NTSTATUS
NTAPI
Asn1DecodeValue(
    _In_ REFBLOB Data,
    _Out_ PASN1_VALUE Value
    );

_Must_inspect_result_
NTSTATUS
NTAPI
Asn1Decode(
    _In_ REFBLOB Data,
    _In_count_(DescriptorCount) const ASN1_VALUE_DECRIPTOR* Descriptors,
    _In_ ULONG DescriptorCount,
    _Out_ PASN1_VALUE Values
    );

//
// Certificate Store
//
#if defined(_NTDEF_) || defined(_WINTERNL_) 
_Must_inspect_result_
NTSTATUS
NTAPI
StoreOpen(
    _Out_ PHANDLE StoreHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ const UNICODE_STRING* Store
    );
#endif // defined(_NTDEF_) || defined(_WINTERNL_) 

_Must_inspect_result_
NTSTATUS
NTAPI
StoreClose(
    _In_ HANDLE StoreHandle
    );
#if defined (_M_IX86)   
#pragma comment(linker, "/alternatename:_StoreClose@4=_ZwClose@4")   
#elif defined (_M_IA64) || defined (_M_AMD64)   
#pragma comment(linker, "/alternatename:StoreClose=ZwClose")   
#else  /* defined (_M_IA64) || defined (_M_AMD64) */   
#error Unsupported platform   
#endif  /* defined (_M_IA64) || defined (_M_AMD64) */

#if defined(_NTDEF_) || defined(_WINTERNL_)
_Must_inspect_result_
NTSTATUS
NTAPI
StoreOpenCertificateByName(
    _Out_ PBLOB Certificate,
    _In_ HANDLE StoreHandle,
    _In_ const UNICODE_STRING* Name
    );
#endif // defined(_NTDEF_) || defined(_WINTERNL_) 

#ifdef __cplusplus
}
#endif

#endif // _WIN_CERT_H_
