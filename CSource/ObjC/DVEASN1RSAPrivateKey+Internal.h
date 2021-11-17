// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

#import "DVESecurity.h"
#include "RSAPrivateKey.h"

@interface DVEASN1RSAPrivateKey(Internal)
- (instancetype)initWithRSAPrivateKey:(RSAPrivateKey_t *)rsaPrivateKey;
- (RSAPrivateKey_t *)asn1RSAPrivateKey;
- (NSString *)asn1DebugDescription;
@end
