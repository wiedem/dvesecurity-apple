// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@import Foundation;

@class DVEASN1RSAPrivateKey;

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(ASN1.RSAPublicKey)
@interface DVEASN1RSAPublicKey : NSObject

@property (nonatomic, readonly) NSData *modulus;
@property (nonatomic, readonly) NSData *publicExponent;
@property (nonatomic, readonly) NSString *x693BasicXerString;

- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithModulus:(NSData *)modulus publicExponent:(NSData *)publicExponent;
- (instancetype)initWithPrivateKey:(DVEASN1RSAPrivateKey *)privateKey;
- (instancetype)initWithPKCS1Data:(NSData *)pkcs1Data error:(NSError *_Nullable *_Nullable)error NS_REFINED_FOR_SWIFT;

- (BOOL)isEqualToRSAPublicKey:(DVEASN1RSAPublicKey *)rsaPublicKey;

@end

NS_ASSUME_NONNULL_END
