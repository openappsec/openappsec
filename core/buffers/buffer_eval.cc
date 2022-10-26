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

#include "buffer.h"
#include "environment/evaluator_templates.h"

using namespace EnvironmentHelper;

class ConstantBuffer : public Constant<Buffer>
{
public:
    ConstantBuffer(const std::vector<std::string> &params)
            :
        Constant<Buffer>(
            [] (const std::string &str) { return Buffer(str); },
            params
        ) {}
    static std::string getName() { return Constant<Buffer>::getName() + "Buffer"; }
};

class EqualBuffer : public Equal<Buffer>
{
public:
    EqualBuffer(const std::vector<std::string> &params) : Equal<Buffer>(params) {}
    static std::string getName() { return Equal<Buffer>::getName() + "Buffer"; }
};

void
Buffer::preload()
{
    addMatcher<ConstantBuffer>();
    addMatcher<EqualBuffer>();
}
