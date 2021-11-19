/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "X509PKIXModule"
 * 	found in "PKIX.asn1"
 * 	`asn1c -S ./skeletons -fwide-types -no-gen-OER -no-gen-UPER -no-gen-APER -no-gen-example`
 */

#include "ECParameters.h"

static asn_TYPE_member_t asn_MBR_ECParameters_1[] = {
	{ ATF_NOFLAGS, 0, offsetof(struct ECParameters, choice.namedCurve),
		(ASN_TAG_CLASS_UNIVERSAL | (6 << 2)),
		0,
		&asn_DEF_OBJECT_IDENTIFIER,
		0,
		{
#if !defined(ASN_DISABLE_OER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
			0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
			0
		},
		0, 0, /* No default value */
		"namedCurve"
		},
};
static const asn_TYPE_tag2member_t asn_MAP_ECParameters_tag2el_1[] = {
    { (ASN_TAG_CLASS_UNIVERSAL | (6 << 2)), 0, 0, 0 } /* namedCurve */
};
static asn_CHOICE_specifics_t asn_SPC_ECParameters_specs_1 = {
	sizeof(struct ECParameters),
	offsetof(struct ECParameters, _asn_ctx),
	offsetof(struct ECParameters, present),
	sizeof(((struct ECParameters *)0)->present),
	asn_MAP_ECParameters_tag2el_1,
	1,	/* Count of tags in the map */
	0, 0,
	-1	/* Extensions start */
};
asn_TYPE_descriptor_t asn_DEF_ECParameters = {
	"ECParameters",
	"ECParameters",
	&asn_OP_CHOICE,
	0,	/* No effective tags (pointer) */
	0,	/* No effective tags (count) */
	0,	/* No tags (pointer) */
	0,	/* No tags (count) */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		CHOICE_constraint
	},
	asn_MBR_ECParameters_1,
	1,	/* Elements count */
	&asn_SPC_ECParameters_specs_1	/* Additional specs */
};

