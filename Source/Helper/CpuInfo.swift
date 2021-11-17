// Copyright (c) diva-e NEXT GmbH. All rights reserved.
// Licensed under the MIT License.

import Foundation

func getProcCpuType() -> cpu_type_t {
    var cpuType: cpu_type_t = 0
    var cpuTypeMemorySize = MemoryLayout.size(ofValue: cpuType)

    guard sysctlbyname("sysctl.proc_cputype", &cpuType, &cpuTypeMemorySize, nil, 0) != -1 else {
        fatalError("Error getting CPU type of process")
    }
    return cpuType
}
