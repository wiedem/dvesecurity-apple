// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

#import "DVEASN1Coder.h"
#import "DVEASN1CoderError.h"
#import "DVEASN1RSAPublicKey+Internal.h"
#import "DVEASN1RSAPrivateKey+Internal.h"
#include "SubjectPublicKeyInfo.h"
#include "RSAPrivateKey.h"
#include "RSAPublicKey.h"

NSString *const DVEASN1CoderErrorDomain = @"com.diva-e.DVESecurity.ASN1CoderErrorDomain";
// https://tools.ietf.org/html/rfc8017
const asn_oid_arc_t rsaEncryptionArcs[] = { 1, 2, 840, 113549, 1, 1, 1 };
// https://tools.ietf.org/html/rfc3279#section-2.3.5
// https://tools.ietf.org/html/rfc5480#section-2.1.1
const asn_oid_arc_t idEcPublicKeyArcs[] = { 1, 2, 840, 10045, 2, 1 };

@implementation DVEASN1Coder

static int writeToData(const void *buffer, size_t size, void *nsData) {
    NSMutableData *data = (__bridge NSMutableData *)(nsData);
    [data appendBytes:buffer length:size];
    return 0;
}

+ (NSError *)createEncoderErrorForResult:(asn_enc_rval_t *)result code:(int)code {
    /*
     Possible error codes:

     EINVAL Incorrect parameters to the function, such as NULLs
     ENOENT Encoding transfer syntax is not defined (forthistype)
     EBADF The structure has invalid form or content constraint failed
     EIO The callback has returned negative value during encoding
     */
    NSDictionary *userInfo = nil;
    if (result->failed_type) {
        NSString *errorDescription = [NSString stringWithCString:result->failed_type->name encoding:NSUTF8StringEncoding];
        userInfo = @{ NSLocalizedDescriptionKey : errorDescription };
    }
    return [DVEASN1CoderError errorWithDomain:DVEASN1CoderErrorDomain code:code userInfo:userInfo];
}

+ (NSError *)createDecoderErrorForResult:(asn_dec_rval_t *)result {
    NSString *errorDescription = [NSString stringWithFormat:@"Broken encoding at byte %ld", result->consumed];
    NSDictionary *userInfo = @{ NSLocalizedDescriptionKey : errorDescription };
    return [DVEASN1CoderError errorWithDomain:DVEASN1CoderErrorDomain code:1 userInfo:userInfo];
}

+ (NSData *)createX509SubjectPublicKeyInfo:(NSData *)rsaPublicKey error:(NSError **)error {
    SubjectPublicKeyInfo_t *publicKeyInfo = NULL;
    publicKeyInfo = calloc(1, sizeof(SubjectPublicKeyInfo_t));

    OBJECT_IDENTIFIER_set_arcs(&publicKeyInfo->algorithm.algorithm,
                               (const asn_oid_arc_t *)&rsaEncryptionArcs,
                               sizeof(rsaEncryptionArcs) / sizeof(rsaEncryptionArcs[0]));

    uint8_t *keyBuf = calloc(rsaPublicKey.length, sizeof(*keyBuf));
    [rsaPublicKey getBytes:keyBuf length:rsaPublicKey.length];

    publicKeyInfo->subjectPublicKey.buf = keyBuf;
    publicKeyInfo->subjectPublicKey.size = rsaPublicKey.length;

    NSMutableData *outputData = [NSMutableData data];

    asn_enc_rval_t result;

    result = asn_encode(0, ATS_DER, &asn_DEF_SubjectPublicKeyInfo, publicKeyInfo, writeToData, (__bridge void *)(outputData));
    if (result.encoded == -1) {
        if (error != nil) {
            *error = [self createEncoderErrorForResult:&result code:errno];
        }
    }

    ASN_STRUCT_FREE(asn_DEF_SubjectPublicKeyInfo, publicKeyInfo);

    return outputData;
}

+ (NSData *)extractX509SubjectPublicKey:(NSData *)x509SubjectPublicKeyInfo error:(NSError **)error {
    asn_dec_rval_t result;
    SubjectPublicKeyInfo_t *publicKeyInfo = NULL;

    result = asn_decode(0, ATS_DER, &asn_DEF_SubjectPublicKeyInfo, (void **)&publicKeyInfo, x509SubjectPublicKeyInfo.bytes, x509SubjectPublicKeyInfo.length);
    if (result.code != RC_OK) {
        if (error != nil) {
            *error = [self createDecoderErrorForResult:&result];
        }
        return nil;
    }

    NSData *subjecPublicKey = [NSData dataWithBytes:publicKeyInfo->subjectPublicKey.buf length:publicKeyInfo->subjectPublicKey.size];
    ASN_STRUCT_FREE(asn_DEF_SubjectPublicKeyInfo, publicKeyInfo);
    return subjecPublicKey;
}

+ (DVEASN1RSAPrivateKey *)decodeRSAPrivateKey:(NSData *)asn1Data error:(NSError **)error {
    asn_dec_rval_t result;
    RSAPrivateKey_t *asn1RSAPrivateKey = NULL;

    result = asn_decode(0, ATS_DER, &asn_DEF_RSAPrivateKey, (void **)&asn1RSAPrivateKey, asn1Data.bytes, asn1Data.length);
    if (result.code != RC_OK) {
        if (error != nil) {
            *error = [self createDecoderErrorForResult:&result];
        }
        return nil;
    }
    
    DVEASN1RSAPrivateKey *dveRSAPrivateKey = [[DVEASN1RSAPrivateKey alloc] initWithRSAPrivateKey:asn1RSAPrivateKey];
    ASN_STRUCT_FREE(asn_DEF_RSAPrivateKey, asn1RSAPrivateKey);
    return dveRSAPrivateKey;
}

+ (NSData *)encodeRSAPrivateKey:(DVEASN1RSAPrivateKey *)privateKey error:(NSError **)error {
    NSMutableData *outputData = [NSMutableData data];

    asn_enc_rval_t result;

    RSAPrivateKey_t *asn1RSAPrivateKey = privateKey.asn1RSAPrivateKey;
    result = asn_encode(0, ATS_DER, &asn_DEF_RSAPrivateKey, asn1RSAPrivateKey, writeToData, (__bridge void *)(outputData));
    ASN_STRUCT_FREE(asn_DEF_RSAPrivateKey, asn1RSAPrivateKey);

    if (result.encoded == -1) {
        if (error != nil) {
            *error = [self createEncoderErrorForResult:&result code:errno];
        }

    }
    return outputData;
}

+ (DVEASN1RSAPublicKey *)decodeRSAPublicKey:(NSData *)asn1Data error:(NSError **)error {
    asn_dec_rval_t result;
    RSAPublicKey_t *asn1RSAPublicKey = NULL;

    result = asn_decode(0, ATS_DER, &asn_DEF_RSAPublicKey, (void **)&asn1RSAPublicKey, asn1Data.bytes, asn1Data.length);
    if (result.code != RC_OK) {
        if (error != nil) {
            *error = [self createDecoderErrorForResult:&result];
        }
        return nil;
    }

    DVEASN1RSAPublicKey *dveRSAPublicKey = [[DVEASN1RSAPublicKey alloc] initWithRSAPublicKey:asn1RSAPublicKey];
    ASN_STRUCT_FREE(asn_DEF_RSAPublicKey, asn1RSAPublicKey);
    return dveRSAPublicKey;
}

+ (NSData *)encodeRSAPublicKey:(DVEASN1RSAPublicKey *)publicKey error:(NSError **)error {
    NSMutableData *outputData = [NSMutableData data];

    asn_enc_rval_t result;

    RSAPublicKey_t *asn1RSAPublicKey = publicKey.asn1RSAPublicKey;
    result = asn_encode(0, ATS_DER, &asn_DEF_RSAPublicKey, asn1RSAPublicKey, writeToData, (__bridge void *)(outputData));
    ASN_STRUCT_FREE(asn_DEF_RSAPublicKey, asn1RSAPublicKey);

    if (result.encoded == -1) {
        if (error != nil) {
            *error = [self createEncoderErrorForResult:&result code:errno];
        }

    }
    return outputData;
}

@end
