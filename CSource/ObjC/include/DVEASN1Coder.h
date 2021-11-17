// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

@import Foundation;

@class DVEASN1RSAPrivateKey;
@class DVEASN1RSAPublicKey;

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(ASN1.Coder)
@interface DVEASN1Coder : NSObject

+ (NSData * _Nullable)createX509SubjectPublicKeyInfo:(NSData *)rsaPublicKey error:(NSError *_Nullable *_Nullable)error NS_REFINED_FOR_SWIFT;
+ (NSData * _Nullable)extractX509SubjectPublicKey:(NSData *)x509SubjectPublicKeyInfo error:(NSError *_Nullable *_Nullable)error NS_REFINED_FOR_SWIFT;

+ (nullable DVEASN1RSAPrivateKey *)decodeRSAPrivateKey:(NSData *)asn1Data error:(NSError *_Nullable *_Nullable)error NS_REFINED_FOR_SWIFT;
+ (nullable NSData *)encodeRSAPrivateKey:(DVEASN1RSAPrivateKey *)privateKey error:(NSError *_Nullable *_Nullable)error;

+ (nullable DVEASN1RSAPublicKey *)decodeRSAPublicKey:(NSData *)asn1Data error:(NSError *_Nullable *_Nullable)error NS_REFINED_FOR_SWIFT;
+ (nullable NSData *)encodeRSAPublicKey:(DVEASN1RSAPublicKey *)publicKey error:(NSError *_Nullable *_Nullable)error;

@end

NS_ASSUME_NONNULL_END
