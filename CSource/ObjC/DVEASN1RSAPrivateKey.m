// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

#import "DVEASN1RSAPrivateKey.h"
#import "DVEASN1+Internal.h"
#import "DVEASN1Coder.h"
#import "DVEASN1RSAPublicKey+Internal.h"
#include "RSAPrivateKey.h"
#include "DVEASN1RSAOtherPrimeInfo+Internal.h"

@interface DVEASN1RSAPrivateKey()
@property (nonatomic, readwrite) NSData *version;
@property (nonatomic, readwrite) NSData *modulus;
@property (nonatomic, readwrite) NSData *publicExponent;
@property (nonatomic, readwrite) NSData *privateExponent;
@property (nonatomic, readwrite) NSData *prime1;
@property (nonatomic, readwrite) NSData *prime2;
@property (nonatomic, readwrite) NSData *exponent1;
@property (nonatomic, readwrite) NSData *exponent2;
@property (nonatomic, readwrite) NSData *coefficient;
@property (nonatomic, readwrite) NSArray<DVEASN1RSAOtherPrimeInfo *>* otherPrimeInfos;
@end

#pragma mark -
@implementation DVEASN1RSAPrivateKey

- (instancetype)initWithPKCS1Data:(NSData *)pkcs1Data error:(NSError **)error {
    return [DVEASN1Coder decodeRSAPrivateKey:pkcs1Data error:error];
}

- (instancetype)initWithRSAPrivateKey:(RSAPrivateKey_t *)rsaPrivateKey {
    if (self = [super init]) {
        _version = [NSData dataWithBytes:rsaPrivateKey->version.buf length:rsaPrivateKey->version.size];
        _modulus = [NSData dataWithBytes:rsaPrivateKey->modulus.buf length:rsaPrivateKey->modulus.size];
        _publicExponent = [NSData dataWithBytes:rsaPrivateKey->publicExponent.buf length:rsaPrivateKey->publicExponent.size];
        _privateExponent = [NSData dataWithBytes:rsaPrivateKey->privateExponent.buf length:rsaPrivateKey->privateExponent.size];
        _prime1 = [NSData dataWithBytes:rsaPrivateKey->prime1.buf length:rsaPrivateKey->prime1.size];
        _prime2 = [NSData dataWithBytes:rsaPrivateKey->prime2.buf length:rsaPrivateKey->prime2.size];
        _exponent1 = [NSData dataWithBytes:rsaPrivateKey->exponent1.buf length:rsaPrivateKey->exponent1.size];
        _exponent2 = [NSData dataWithBytes:rsaPrivateKey->exponent2.buf length:rsaPrivateKey->exponent2.size];
        _coefficient = [NSData dataWithBytes:rsaPrivateKey->coefficient.buf length:rsaPrivateKey->coefficient.size];

        NSMutableArray<DVEASN1RSAOtherPrimeInfo *> *otherPrimeInfos = [NSMutableArray array];
        if (rsaPrivateKey->otherPrimeInfos != NULL) {
            for (NSUInteger i=0; i<rsaPrivateKey->otherPrimeInfos->list.count; ++i) {
                DVEASN1RSAOtherPrimeInfo *otherPrimeInfo = [[DVEASN1RSAOtherPrimeInfo alloc] init:rsaPrivateKey->otherPrimeInfos->list.array[i]];
                [otherPrimeInfos addObject:otherPrimeInfo];
            }
        }
        _otherPrimeInfos = [NSArray arrayWithArray:otherPrimeInfos];
    }
    return self;
}

- (BOOL)isEqual:(id)object {
    if (object == nil) {
        return NO;
    }

    if ([object isKindOfClass:[DVEASN1RSAPrivateKey class]] == NO) {
        return [super isEqual:object];
    }

    return [self isEqualToRSAPrivateKey:(DVEASN1RSAPrivateKey *)object];
}

- (BOOL)isEqualToRSAPrivateKey:(DVEASN1RSAPrivateKey *)rsaPrivateKey {
    return [self.version isEqualToData:rsaPrivateKey.version] &&
        [self.modulus isEqualToData:rsaPrivateKey.modulus] &&
        [self.publicExponent isEqualToData:rsaPrivateKey.publicExponent] &&
        [self.privateExponent isEqualToData:rsaPrivateKey.privateExponent] &&
        [self.prime1 isEqualToData:rsaPrivateKey.prime1] &&
        [self.prime2 isEqualToData:rsaPrivateKey.prime2] &&
        [self.exponent1 isEqualToData:rsaPrivateKey.exponent1] &&
        [self.exponent2 isEqualToData:rsaPrivateKey.exponent2] &&
        [self.coefficient isEqualToData:rsaPrivateKey.coefficient] &&
        [self.otherPrimeInfos isEqualToArray:rsaPrivateKey.otherPrimeInfos];
}

- (DVEASN1RSAPublicKey *)publicKey {
    return [[DVEASN1RSAPublicKey alloc] initWithPrivateKey:self];
}

- (NSString *)debugDescription {
    return self.asn1DebugDescription;
}

- (RSAPrivateKey_t *)asn1RSAPrivateKey {
    RSAPrivateKey_t *asn1RSAPrivateKey = calloc(1, sizeof(*asn1RSAPrivateKey));

    copyData(self.version, &asn1RSAPrivateKey->version);
    copyData(self.modulus, &asn1RSAPrivateKey->modulus);
    copyData(self.publicExponent, &asn1RSAPrivateKey->publicExponent);
    copyData(self.privateExponent, &asn1RSAPrivateKey->privateExponent);
    copyData(self.prime1, &asn1RSAPrivateKey->prime1);
    copyData(self.prime2, &asn1RSAPrivateKey->prime2);
    copyData(self.exponent1, &asn1RSAPrivateKey->exponent1);
    copyData(self.exponent2, &asn1RSAPrivateKey->exponent2);
    copyData(self.coefficient, &asn1RSAPrivateKey->coefficient);

    if (_otherPrimeInfos.count > 0) {
        OtherPrimeInfos_t *otherPrimeInfos = calloc(1, sizeof(*otherPrimeInfos));

        for (DVEASN1RSAOtherPrimeInfo *otherPrimeInfo in _otherPrimeInfos) {
            OtherPrimeInfo_t *listItem = calloc(1, sizeof(*listItem));
            copyData(otherPrimeInfo.prime, &listItem->prime);
            copyData(otherPrimeInfo.exponent, &listItem->exponent);
            copyData(otherPrimeInfo.coefficient, &listItem->coefficient);
            ASN_SEQUENCE_ADD(otherPrimeInfos, listItem);
        }

        asn1RSAPrivateKey->otherPrimeInfos = otherPrimeInfos;
    } else {
        asn1RSAPrivateKey->otherPrimeInfos = NULL;
    }

    return asn1RSAPrivateKey;
}

- (NSString *)asn1DebugDescription {
    char *buffer = NULL;
    size_t bufferSize = 0;
    FILE *memoryStream = open_memstream(&buffer, &bufferSize);

    RSAPrivateKey_t *asn1RSAPrivateKey = self.asn1RSAPrivateKey;
    asn_fprint(memoryStream, &asn_DEF_RSAPrivateKey, asn1RSAPrivateKey);
    ASN_STRUCT_FREE(asn_DEF_RSAPrivateKey, asn1RSAPrivateKey);
    fclose(memoryStream);

    NSData *data = [NSData dataWithBytesNoCopy:buffer length:bufferSize freeWhenDone:YES];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

- (NSString *)x693BasicXerString {
    char *buffer = NULL;
    size_t bufferSize = 0;
    FILE *memoryStream = open_memstream(&buffer, &bufferSize);

    RSAPrivateKey_t *asn1RSAPrivateKey = self.asn1RSAPrivateKey;
    xer_fprint(memoryStream, &asn_DEF_RSAPrivateKey, asn1RSAPrivateKey);
    ASN_STRUCT_FREE(asn_DEF_RSAPrivateKey, asn1RSAPrivateKey);
    fclose(memoryStream);

    NSData *data = [NSData dataWithBytesNoCopy:buffer length:bufferSize freeWhenDone:YES];
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}

@end
