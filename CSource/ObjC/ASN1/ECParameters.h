/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "X509PKIXModule"
 * 	found in "PKIX.asn1"
 * 	`asn1c -S ./skeletons -fwide-types -no-gen-OER -no-gen-UPER -no-gen-APER -no-gen-example`
 */

#ifndef	_ECParameters_H_
#define	_ECParameters_H_


#include <asn_application.h>

/* Including external dependencies */
#include <OBJECT_IDENTIFIER.h>
#include <constr_CHOICE.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dependencies */
typedef enum ECParameters_PR {
	ECParameters_PR_NOTHING,	/* No components present */
	ECParameters_PR_namedCurve
} ECParameters_PR;

/* ECParameters */
typedef struct ECParameters {
	ECParameters_PR present;
	union ECParameters_u {
		OBJECT_IDENTIFIER_t	 namedCurve;
	} choice;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} ECParameters_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_ECParameters;

#ifdef __cplusplus
}
#endif

#endif	/* _ECParameters_H_ */
#include <asn_internal.h>
