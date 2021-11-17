// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

#import "DVEASN1.h"
#include <INTEGER.h>

void copyData(NSData *data, INTEGER_t *destination) {
    uint8_t *buf = malloc(data.length);
    [data getBytes:buf length:data.length];
    destination->buf = buf;
    destination->size = data.length;
}

@implementation DVEASN1
@end
