// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

#import "DVESecurity.h"
#include "RSAPublicKey.h"

@interface DVEASN1RSAPublicKey(Internal)
- (instancetype)initWithRSAPublicKey:(RSAPublicKey_t *)rsaPublicKey;
- (RSAPublicKey_t *)asn1RSAPublicKey;
- (NSString *)asn1DebugDescription;
@end
