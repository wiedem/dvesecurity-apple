/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PKCS1Module"
 * 	found in "PKCS1.asn1"
 * 	`asn1c -S ./skeletons -fwide-types -no-gen-OER -no-gen-UPER -no-gen-APER -no-gen-example`
 */

#ifndef	_RSAPublicKey_H_
#define	_RSAPublicKey_H_


#include <asn_application.h>

/* Including external dependencies */
#include <INTEGER.h>
#include <constr_SEQUENCE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RSAPublicKey */
typedef struct RSAPublicKey {
	INTEGER_t	 modulus;
	INTEGER_t	 publicExponent;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} RSAPublicKey_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_RSAPublicKey;

#ifdef __cplusplus
}
#endif

#endif	/* _RSAPublicKey_H_ */
#include <asn_internal.h>
