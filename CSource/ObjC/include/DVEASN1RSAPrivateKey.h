// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@import Foundation;

@class DVEASN1RSAOtherPrimeInfo;
@class DVEASN1RSAPublicKey;

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(ASN1.RSAPrivateKey)
@interface DVEASN1RSAPrivateKey : NSObject

@property (nonatomic, readonly) NSData *version;
@property (nonatomic, readonly) NSData *modulus;
@property (nonatomic, readonly) NSData *publicExponent;
@property (nonatomic, readonly) NSData *privateExponent;
@property (nonatomic, readonly) NSData *prime1;
@property (nonatomic, readonly) NSData *prime2;
@property (nonatomic, readonly) NSData *exponent1;
@property (nonatomic, readonly) NSData *exponent2;
@property (nonatomic, readonly) NSData *coefficient;
@property (nonatomic, readonly) NSArray<DVEASN1RSAOtherPrimeInfo *>* otherPrimeInfos;
@property (nonatomic, readonly) DVEASN1RSAPublicKey *publicKey;
@property (nonatomic, readonly) NSString *x693BasicXerString;

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithPKCS1Data:(NSData *)pkcs1Data error:(NSError *_Nullable *_Nullable)error NS_REFINED_FOR_SWIFT;

- (BOOL)isEqualToRSAPrivateKey:(DVEASN1RSAPrivateKey *)rsaPrivateKey;

@end

NS_ASSUME_NONNULL_END
