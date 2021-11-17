// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@import Foundation;

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(ASN1.RSAOtherPrimeInfo)
@interface DVEASN1RSAOtherPrimeInfo : NSObject

@property (nonatomic, readonly) NSData *prime;
@property (nonatomic, readonly) NSData *exponent;
@property (nonatomic, readonly) NSData *coefficient;

- (BOOL)isEqualToRSAOtherPrimeInfo:(DVEASN1RSAOtherPrimeInfo *)rsaOtherPrimeInfo;

@end

NS_ASSUME_NONNULL_END
