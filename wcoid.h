#ifndef _WC_OIDS_H_
#define _WC_OIDS_H_

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                           Certificate Extensions                           //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

// 2.5.29.9
DEFINE_BLOB(OID_EXT_SUBJECT_DIR_ATTR, 0x55, 0x1D, 0x09)

// 2.5.29.14
DEFINE_BLOB(OID_EXT_SUBJECT_KEY_ID, 0x55, 0x1D, 0x0E)

// 2.5.29.15
DEFINE_BLOB(OID_EXT_KEY_USAGE, 0x55, 0x1D, 0x0F)

// 2.5.29.17
DEFINE_BLOB(OID_EXT_SUBJECT_ALT_NAME, 0x55, 0x1D, 0x11)

// 2.5.29.18
DEFINE_BLOB(OID_EXT_ISSUER_ALT_NAME, 0x55, 0x1D, 0x12)

// 2.5.29.19
DEFINE_BLOB(OID_EXT_BASIC_CONST, 0x55, 0x1D, 0x13)

// 2.5.29.30
DEFINE_BLOB(OID_EXT_NAME_CONST, 0x55, 0x1D, 0x1E)

// 2.5.29.31
DEFINE_BLOB(OID_EXT_CRL_DIST_POINT, 0x55, 0x1D, 0x1F)

// 2.5.29.32
DEFINE_BLOB(OID_EXT_CERT_POLICY, 0x55, 0x1D, 0x20)

// 2.5.29.33
DEFINE_BLOB(OID_EXT_POLICY_MAPPINGS, 0x55, 0x1D, 0x21)

// 2.5.29.35
DEFINE_BLOB(OID_EXT_AUTH_KEY_ID, 0x55, 0x1D, 0x23)

// 2.5.29.36
DEFINE_BLOB(OID_EXT_POLICY_CONST, 0x55, 0x1D, 0x24)

// 2.5.29.37
DEFINE_BLOB(OID_EXT_EX_KEY_USAGE, 0x55, 0x1D, 0x25)

// 2.5.29.46
DEFINE_BLOB(OID_EXT_FRESHEST_CRL, 0x55, 0x1D, 0x2E)

// 2.5.29.54
DEFINE_BLOB(OID_EXT_INHIBIT_ANY_POLICY, 0x55, 0x1D, 0x36)

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                        Extended Key Usage Purposes                         //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

// 2.5.29.37.0
DEFINE_BLOB(OID_EXT_EKU_ANY_EXT_KEY_USAGE, 0x55, 0x1D, 0x25, 0x00)

// 1.3.6.1.5.5.7.3.1
DEFINE_BLOB(OID_EXT_EKU_SERVER_AUTH, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01)

// 1.3.6.1.5.5.7.3.2
DEFINE_BLOB(OID_EXT_EKU_CLIENT_AUTH, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02)

// 1.3.6.1.5.5.7.3.3
DEFINE_BLOB(OID_EXT_EKU_CODE_SIGNING, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03)

// 1.3.6.1.5.5.7.3.4
DEFINE_BLOB(OID_EXT_EKU_EMAIL_PROT, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04)

// 1.3.6.1.5.5.7.3.8
DEFINE_BLOB(OID_EXT_EKU_TIME_STAMPING, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08)

// 1.3.6.1.5.5.7.3.9
DEFINE_BLOB(OID_EXT_EKU_OCSP_SIGNING, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09)

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                                   X.520                                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

// 2.5.4.3
DEFINE_BLOB(OID_CommonName, 0x55, 0x04, 0x03)

// 2.5.4.4
DEFINE_BLOB(OID_Surname, 0x55, 0x04, 0x04)

// 2.5.4.5
DEFINE_BLOB(OID_SerialNumber, 0x55, 0x04, 0x05)

// 2.5.4.6
DEFINE_BLOB(OID_CountryName, 0x55, 0x04, 0x06)

// 2.5.4.7
DEFINE_BLOB(OID_LocalityName, 0x55, 0x04, 0x07)

// 2.5.4.8
DEFINE_BLOB(OID_ProvinceName, 0x55, 0x04, 0x08)

// 2.5.4.9
DEFINE_BLOB(OID_StreetAddress, 0x55, 0x04, 0x09)

// 2.5.4.10
DEFINE_BLOB(OID_OrganizationName, 0x55, 0x04, 0x0A)

// 2.5.4.11
DEFINE_BLOB(OID_OrganizationalUnitName, 0x55, 0x04, 0x0B)

// 2.5.4.12
DEFINE_BLOB(OID_Title, 0x55, 0x04, 0x0C)

// 2.5.4.13
DEFINE_BLOB(OID_Description, 0x55, 0x04, 0x0D)

// 2.5.4.15
DEFINE_BLOB(OID_BusinessCatagory, 0x55, 0x04, 0x0F)

// 2.5.4.42
DEFINE_BLOB(OID_GivenName, 0x55, 0x04, 0x2A)

// 2.5.4.43
DEFINE_BLOB(OID_Initials, 0x55, 0x04, 0x2B)

// 2.5.4.44
DEFINE_BLOB(OID_GenerationQualifier, 0x55, 0x04, 0x2C)

// 2.5.4.49
DEFINE_BLOB(OID_DistinguishedName, 0x55, 0x04, 0x31)

// 2.5.4.65
DEFINE_BLOB(OID_Pseudonym, 0x55, 0x04, 0x41)

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                                  PKCS #7                                   //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

// 1.3.6.1.4.1.311.2.1.15
DEFINE_BLOB(SPC_PE_IMAGE_DATAOBJ, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x0F)

// 1.3.6.1.4.1.311.2.1.4
DEFINE_BLOB(SPC_INDIRECT_DATA_OBJID, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x01, 0x04)

// 1.2.840.113549.1.7.2
DEFINE_BLOB(OID_RSA_PKCS7, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02)

// 1.2.840.113549.1.9.4
DEFINE_BLOB(OID_messageDigest, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x04)

////////////////////////////////////////////////////////////////////////////////
//                                                                            //
//                                    Hash                                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

// 1.3.14.3.2.26
DEFINE_BLOB(OID_OIWSEC_SHA1, 0x2B, 0x0E, 0x03, 0x02, 0x1A)

// 1.2.840.113549.2.2
DEFINE_BLOB(OID_RSA_MD2, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x02)

// 1.2.840.113549.2.5
DEFINE_BLOB(OID_RSA_MD5, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05)

//
// Signarture Algorithm Identifier OIDs
//

// 1.2.840.113549.1.1.4
DEFINE_BLOB(OID_RSA_MD5RSA, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04)

// 1.2.840.113549.1.1.5
DEFINE_BLOB(OID_RSA_SHA1RSA, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05)

// 2.16.840.113549.1.1.11
DEFINE_BLOB(OID_OIWSEC_SHA256RSA, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b)

// 2.16.840.113549.1.1.12
DEFINE_BLOB(OID_OIWSEC_SHA384RSA, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c)

// 2.16.840.113549.1.1.13
DEFINE_BLOB(OID_OIWSEC_SHA512RSA, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d)

// 2.16.840.1.101.3.4.2.1
DEFINE_BLOB(OID_MD_SHA256, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01)

// 2.16.840.1.101.3.4.2.2
DEFINE_BLOB(OID_MD_SHA384, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02)

// 2.16.840.1.101.3.4.2.2
DEFINE_BLOB(OID_MD_SHA512, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03)

// 1.3.14.3.2.29
DEFINE_BLOB(OID_OIWSEC_SHA1RSA, 0x2B, 0x0E, 0x03, 0x02, 0x1D)

// 1.3.14.3.2.15
DEFINE_BLOB(OID_OIWSEC_SHARSA, 0x2B, 0x0E, 0x03, 0x02, 0x0F)

// 1.3.14.3.2.3
DEFINE_BLOB(OID_OIWSEC_MD5RSA, 0x2B, 0x0E, 0x03, 0x02, 0x03)

// 1.2.840.113549.1.1.2
DEFINE_BLOB(OID_RSA_MD2RSA, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x02)

// 1.3.14.7.2.3.1
DEFINE_BLOB(OID_OIWDIR_MD2RSA, 0x2B, 0x0E, 0x07, 0x02, 0x03, 0x01)

#endif // _WC_OIDS_H_
