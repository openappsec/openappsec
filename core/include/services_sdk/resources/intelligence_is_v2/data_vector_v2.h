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

#ifndef __DATA_VECTOR_V2_H__
#define __DATA_VECTOR_V2_H__

#include <vector>
#include <string>
#include <sstream>
#include <iterator>
#include <iostream>

#include "common.h"

class DataVector
{
public:
    DataVector() {}
    DataVector(const DataVector &_data) : data(_data.data) {}

    template <typename Archive>
    void
    serialize(Archive &ar, const std::string &key)
    {
        ar(cereal::make_nvp(key, data));
    }

    std::string
    toString() const
    {
        return "[" + makeSeparatedStr(data, ", ") + "]";
    }

    const std::vector<std::string> &
    getVectorData() const
    {
        return data;
    }

private:
    std::vector<std::string> data = {};
};

#endif // __DATA_VECTOR_V2_H__
