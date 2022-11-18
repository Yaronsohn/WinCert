#ifndef _WIN_CERT_STATUS_H_
#define _WIN_CERT_STATUS_H_

//
//  Values are 32 bit values laid out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_WINCERT                 0x100


//
// Define the severity codes
//
#define STATUS_SEVERITY_SUCCESS          0x0
#define STATUS_SEVERITY_INFORMATIONAL    0x1
#define STATUS_SEVERITY_WARNING          0x2
#define STATUS_SEVERITY_ERROR            0x3


//
// MessageId: FACILITY_WINCERT_NAME
//
// MessageText:
//
// WinCert.
//
#define FACILITY_WINCERT_NAME            ((NTSTATUS)0x61000000L)


//
// The values in this file are valid NTSTATUS values that map user mode HRESULT
// values for the FACILITY_CERT facility.
// To get the HRESULT value from these status codes use CERT_STATUS_TO_HRESULT.
//

#ifndef NT_FACILITY
#define NT_FACILITY(x) (((x) >> 16) & 0x1FFF)
#endif

#define NT_IS_CERT(x)  (NT_FACILITY(x) == FACILITY_WINCERT)

#if !defined(__midl) && defined(_WINERROR_)
__forceinline HRESULT CERT_NT_TO_HRESULT(unsigned long x) { return NT_IS_CERT(x) ? (((x) & 0xFFFF) | (FACILITY_CERT << 16) | (0x80000000)) : HRESULT_FROM_NT(x); }
#endif

//
// MessageId: STATUS_SUBJECT_NOT_TRUSTED
//
// MessageText:
//
// The subject is not trusted for the specified action.
//
#define STATUS_SUBJECT_NOT_TRUSTED       ((NTSTATUS)0xE1000004L)

//
// MessageId: STATUS_ASN1_DECODING_ERROR
//
// MessageText:
//
// Error due to problem in ASN.1 decoding process.
//
#define STATUS_ASN1_DECODING_ERROR       ((NTSTATUS)0xE1000006L)

//
// MessageId: STATUS_CRYPTO_ERROR
//
// MessageText:
//
// Unspecified cryptographic failure.
//
#define STATUS_CRYPTO_ERROR              ((NTSTATUS)0xE1000008L)

//
// MessageId: STATUS_NO_SIGNATURE
//
// MessageText:
//
// No signature was present in the subject.
//
#define STATUS_NO_SIGNATURE              ((NTSTATUS)0xE1000100L)

//
// MessageId: STATUS_CERT_EXPIRED
//
// MessageText:
//
// A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file.
//
#define STATUS_CERT_EXPIRED              ((NTSTATUS)0xE1000101L)

//
// MessageId: STATUS_CERT_ROLE
//
// MessageText:
//
// A certificate that can only be used as an end-entity is being used as a CA or vice versa.
//
#define STATUS_CERT_ROLE                 ((NTSTATUS)0xE1000103L)

//
// MessageId: STATUS_CERT_CRITICAL
//
// MessageText:
//
// A certificate contains an unknown extension that is marked 'critical'.
//
#define STATUS_CERT_CRITICAL             ((NTSTATUS)0xE1000105L)

//
// MessageId: STATUS_CERT_PURPOSE
//
// MessageText:
//
// A certificate being used for a purpose other than the ones specified by its CA.
//
#define STATUS_CERT_PURPOSE              ((NTSTATUS)0xE1000106L)

//
// MessageId: STATUS_CERT_ISSUER_CHAINING
//
// MessageText:
//
// A parent of a given certificate in fact did not issue that child certificate.
//
#define STATUS_CERT_ISSUER_CHAINING      ((NTSTATUS)0xE1000107L)

//
// MessageId: STATUS_CERT_MALFORMED
//
// MessageText:
//
// A certificate is missing or has an empty value for an important field, such as a subject or issuer name.
//
#define STATUS_CERT_MALFORMED            ((NTSTATUS)0xE1000108L)

//
// MessageId: STATUS_UNTRUSTED_ROOT
//
// MessageText:
//
// A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.
//
#define STATUS_UNTRUSTED_ROOT            ((NTSTATUS)0xE1000109L)

//
// MessageId: STATUS_CERT_CHAINING
//
// MessageText:
//
// A certificate chain could not be built to a trusted root authority.
//
#define STATUS_CERT_CHAINING             ((NTSTATUS)0xE100010AL)

//
// MessageId: STATUS_CERT_REVOKED
//
// MessageText:
//
// A certificate was explicitly revoked by its issuer.
//
#define STATUS_CERT_REVOKED              ((NTSTATUS)0xE100010CL)

//
// MessageId: STATUS_REVOCATION_FAILURE
//
// MessageText:
//
// The revocation process could not continue - the certificate(s) could not be checked.
//
#define STATUS_REVOCATION_FAILURE        ((NTSTATUS)0xE100010EL)

//
// MessageId: STATUS_CN_NO_MATCH
//
// MessageText:
//
// The certificate's CN name does not match the passed value.
//
#define STATUS_CN_NO_MATCH               ((NTSTATUS)0xE100010FL)

 #endif _WIN_CERT_STATUS_H_
