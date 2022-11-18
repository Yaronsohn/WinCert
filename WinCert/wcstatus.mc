;#ifndef _WIN_CERT_STATUS_H_
;#define _WIN_CERT_STATUS_H_
;

MessageIdTypedef=NTSTATUS

SeverityNames = (
    Success          = 0x0:STATUS_SEVERITY_SUCCESS
    Informational    = 0x1:STATUS_SEVERITY_INFORMATIONAL
    Warning          = 0x2:STATUS_SEVERITY_WARNING
    Error            = 0x3:STATUS_SEVERITY_ERROR
    )

FacilityNames = (
    WinCert = 0x100:FACILITY_WINCERT
    )

LanguageNames = (
    English         = 0x0409:MSG00409
    )

MessageId           = 0x0000
Facility            = WinCert
Severity            = Informational
SymbolicName        = FACILITY_WINCERT_NAME
Language            = English
WinCert.
.

;
;//
;// The values in this file are valid NTSTATUS values that map user mode HRESULT
;// values for the FACILITY_CERT facility.
;// To get the HRESULT value from these status codes use CERT_STATUS_TO_HRESULT.
;//
;
;#ifndef NT_FACILITY
;#define NT_FACILITY(x) (((x) >> 16) & 0x1FFF)
;#endif
;
;#define NT_IS_CERT(x)  (NT_FACILITY(x) == FACILITY_WINCERT)
;
;#if !defined(__midl) && defined(_WINERROR_)
;__forceinline HRESULT CERT_NT_TO_HRESULT(unsigned long x) { return NT_IS_CERT(x) ? (((x) & 0xFFFF) | (FACILITY_CERT << 16) | (0x80000000)) : HRESULT_FROM_NT(x); }
;#endif
;
MessageId           = 0x0004
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_SUBJECT_NOT_TRUSTED
Language            = English
The subject is not trusted for the specified action.
.

MessageId           = 0x0006
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_ASN1_DECODING_ERROR
Language            = English
Error due to problem in ASN.1 decoding process.
.

MessageId           = 0x0008
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CRYPTO_ERROR
Language            = English
Unspecified cryptographic failure.
.

MessageId           = 0x0100
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_NO_SIGNATURE
Language            = English
No signature was present in the subject.
.

MessageId           = 0x0101
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CERT_EXPIRED
Language            = English
A required certificate is not within its validity period when verifying against the current system clock or the timestamp in the signed file.
.

MessageId           = 0x0103
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CERT_ROLE
Language            = English
A certificate that can only be used as an end-entity is being used as a CA or vice versa.
.

MessageId           = 0x0105
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CERT_CRITICAL
Language            = English
A certificate contains an unknown extension that is marked 'critical'.
.

MessageId           = 0x0106
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CERT_PURPOSE
Language            = English
A certificate being used for a purpose other than the ones specified by its CA.
.

MessageId           = 0x0107
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CERT_ISSUER_CHAINING
Language            = English
A parent of a given certificate in fact did not issue that child certificate.
.

MessageId           = 0x0108
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CERT_MALFORMED
Language            = English
A certificate is missing or has an empty value for an important field, such as a subject or issuer name.
.

MessageId           = 0x0109
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_UNTRUSTED_ROOT
Language            = English
A certificate chain processed, but terminated in a root certificate which is not trusted by the trust provider.
.

MessageId           = 0x010A
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CERT_CHAINING
Language            = English
A certificate chain could not be built to a trusted root authority.
.

MessageId           = 0x010C
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CERT_REVOKED
Language            = English
A certificate was explicitly revoked by its issuer.
.

MessageId           = 0x010E
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_REVOCATION_FAILURE
Language            = English
The revocation process could not continue - the certificate(s) could not be checked.
.

MessageId           = 0x010F
Facility            = WinCert
Severity            = Error
SymbolicName        = STATUS_CN_NO_MATCH
Language            = English
The certificate's CN name does not match the passed value.
.

; #endif _WIN_CERT_STATUS_H_
