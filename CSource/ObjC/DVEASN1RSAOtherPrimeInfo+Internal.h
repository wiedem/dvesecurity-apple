// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

#import "DVESecurity.h"
#include "OtherPrimeInfo.h"

@interface DVEASN1RSAOtherPrimeInfo(Internal)
- (instancetype)initWithPrime:(NSData *)prime exponent:(NSData *)exponent coefficient:(NSData *)coefficient;
- (instancetype)init:(OtherPrimeInfo_t *)otherPrimeInfo;
@end
