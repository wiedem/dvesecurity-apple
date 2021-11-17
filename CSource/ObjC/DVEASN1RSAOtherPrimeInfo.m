// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

#import "DVEASN1RSAOtherPrimeInfo.h"
#include "OtherPrimeInfo.h"

@interface DVEASN1RSAOtherPrimeInfo()

@property (nonatomic, readwrite) NSData *prime;
@property (nonatomic, readwrite) NSData *exponent;
@property (nonatomic, readwrite) NSData *coefficient;

- (instancetype)init:(struct OtherPrimeInfo *)otherPrimeInfo;

@end

#pragma mark -
@implementation DVEASN1RSAOtherPrimeInfo

- (instancetype)initWithPrime:(NSData *)prime exponent:(NSData *)exponent coefficient:(NSData *)coefficient {
    if (self = [super init]) {
        _prime = prime;
        _exponent = exponent;
        _coefficient = coefficient;
    }
    return self;
}

- (instancetype)init:(OtherPrimeInfo_t *)otherPrimeInfo {
    if (self = [super init]) {
        _prime = [NSData dataWithBytes:otherPrimeInfo->prime.buf length:otherPrimeInfo->prime.size];
        _exponent = [NSData dataWithBytes:otherPrimeInfo->exponent.buf length:otherPrimeInfo->exponent.size];
        _coefficient = [NSData dataWithBytes:otherPrimeInfo->coefficient.buf length:otherPrimeInfo->coefficient.size];
    }
    return self;
}

- (BOOL)isEqual:(id)object {
    if (object == nil) {
        return NO;
    }

    if ([object isKindOfClass:[DVEASN1RSAOtherPrimeInfo class]] == NO) {
        return [super isEqual:object];
    }

    return [self isEqualToRSAOtherPrimeInfo:(DVEASN1RSAOtherPrimeInfo *)object];
}

- (BOOL)isEqualToRSAOtherPrimeInfo:(DVEASN1RSAOtherPrimeInfo *)rsaOtherPrimeInfo {
    return [self.prime isEqualToData:rsaOtherPrimeInfo.prime] &&
        [self.exponent isEqualToData:rsaOtherPrimeInfo.exponent] &&
        [self.coefficient isEqualToData:rsaOtherPrimeInfo.coefficient];
}

@end
