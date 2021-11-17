// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

#import "DVEASN1RSAPublicKey.h"
#import "DVEASN1+Internal.h"
#import "DVEASN1Coder.h"
#import "DVEASN1RSAPrivateKey+Internal.h"
#include "RSAPublicKey.h"

@interface DVEASN1RSAPublicKey()
@property (nonatomic, readwrite) NSData *modulus;
@property (nonatomic, readwrite) NSData *publicExponent;
@end

#pragma mark -
@implementation DVEASN1RSAPublicKey

- (instancetype)initWithModulus:(NSData *)modulus publicExponent:(NSData *)publicExponent {
    if (self = [super init]) {
        _modulus = modulus;
        _publicExponent = publicExponent;
    }
    return self;
}

- (instancetype)initWithPrivateKey:(DVEASN1RSAPrivateKey *)privateKey {
    return [self initWithModulus:privateKey.modulus publicExponent:privateKey.publicExponent];
}

- (instancetype)initWithPKCS1Data:(NSData *)pkcs1Data error:(NSError **)error {
    return [DVEASN1Coder decodeRSAPublicKey:pkcs1Data error:error];
}

- (instancetype)initWithRSAPublicKey:(RSAPublicKey_t *)rsaPublicKey {
    if (self = [super init]) {
        _modulus = [NSData dataWithBytes:rsaPublicKey->modulus.buf length:rsaPublicKey->modulus.size];
        _publicExponent = [NSData dataWithBytes:rsaPublicKey->publicExponent.buf length:rsaPublicKey->publicExponent.size];
    }
    return self;
}

- (BOOL)isEqual:(id)object {
    if (object == nil) {
        return NO;
    }

    if ([object isKindOfClass:[DVEASN1RSAPublicKey class]] == NO) {
        return [super isEqual:object];
    }

    return [self isEqualToRSAPublicKey:(DVEASN1RSAPublicKey *)object];
}

- (BOOL)isEqualToRSAPublicKey:(DVEASN1RSAPublicKey *)rsaPublicKey {
    return [self.modulus isEqualToData:rsaPublicKey.modulus] &&
        [self.publicExponent isEqualToData:rsaPublicKey.publicExponent];
}

- (NSString *)debugDescription {
    return self.asn1DebugDescription;
}

- (RSAPublicKey_t *)asn1RSAPublicKey {
    RSAPublicKey_t *asn1RSAPublicKey = calloc(1, sizeof(*asn1RSAPublicKey));

    copyData(self.modulus, &asn1RSAPublicKey->modulus);
    copyData(self.publicExponent, &asn1RSAPublicKey->publicExponent);

    return asn1RSAPublicKey;
}

- (NSString *)asn1DebugDescription {
    char *buffer = NULL;
    size_t bufferSize = 0;
    FILE *memoryStream = open_memstream(&buffer, &bufferSize);

    RSAPublicKey_t *asn1RSAPublicKey = self.asn1RSAPublicKey;
    asn_fprint(memoryStream, &asn_DEF_RSAPublicKey, asn1RSAPublicKey);
    ASN_STRUCT_FREE(asn_DEF_RSAPublicKey, asn1RSAPublicKey);
    fclose(memoryStream);

    NSData *data = [NSData dataWithBytesNoCopy:buffer length:bufferSize freeWhenDone:YES];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (NSString *)x693BasicXerString {
    char *buffer = NULL;
    size_t bufferSize = 0;
    FILE *memoryStream = open_memstream(&buffer, &bufferSize);

    RSAPublicKey_t *asn1RSAPublicKey = self.asn1RSAPublicKey;
    xer_fprint(memoryStream, &asn_DEF_RSAPublicKey, asn1RSAPublicKey);
    ASN_STRUCT_FREE(asn_DEF_RSAPublicKey, asn1RSAPublicKey);
    fclose(memoryStream);

    NSData *data = [NSData dataWithBytesNoCopy:buffer length:bufferSize freeWhenDone:YES];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

@end
