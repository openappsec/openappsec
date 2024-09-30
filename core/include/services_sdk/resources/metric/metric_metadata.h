// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __METRIC_METADATA_H__
#define __METRIC_METADATA_H__

#ifndef __GENERIC_METRIC_H__
#error metric/metric_metadata.h should not be included directly
#endif // __GENERIC_METRIC_H_

#include <string>

namespace MetricMetadata
{

struct DotName
{
    std::string val;
};

struct Units
{
    std::string val;
};

struct Description
{
    std::string val;
};

} //MetricMetadata

#endif // __METRIC_METADATA_H__
