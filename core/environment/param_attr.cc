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

#include "context.h"

bool
EnvKeyAttr::ParamAttr::doesMatch(const EnvKeyAttr::ParamAttr &param) const
{
    if (param.log_section != LogSection::NONE && param.log_section != log_section) return false;
    if (param.verbosity_level != Verbosity::NONE && param.verbosity_level != verbosity_level) return false;

    return true;
}
