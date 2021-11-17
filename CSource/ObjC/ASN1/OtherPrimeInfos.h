/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "PKCS1Module"
 * 	found in "PKCS1.asn1"
 * 	`asn1c -S ./skeletons -fwide-types -no-gen-OER -no-gen-UPER -no-gen-APER`
 */

#ifndef	_OtherPrimeInfos_H_
#define	_OtherPrimeInfos_H_


#include <asn_application.h>

/* Including external dependencies */
#include <asn_SEQUENCE_OF.h>
#include <constr_SEQUENCE_OF.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
struct OtherPrimeInfo;

/* OtherPrimeInfos */
typedef struct OtherPrimeInfos {
	A_SEQUENCE_OF(struct OtherPrimeInfo) list;
	
	/* Context for parsing across buffer boundaries */
	asn_struct_ctx_t _asn_ctx;
} OtherPrimeInfos_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_OtherPrimeInfos;
extern asn_SET_OF_specifics_t asn_SPC_OtherPrimeInfos_specs_1;
extern asn_TYPE_member_t asn_MBR_OtherPrimeInfos_1[1];

#ifdef __cplusplus
}
#endif

/* Referred external types */
#include "OtherPrimeInfo.h"

#endif	/* _OtherPrimeInfos_H_ */
#include <asn_internal.h>
