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

#ifndef __CP_TEST_BASIC_H__
#define __CP_TEST_BASIC_H__

#include "gtest/gtest.h"
#include "gmock/gmock.h"

// Before EXPECT_DEATH, call this to do all necessary preparations.
void cptestPrepareToDie();

// Path to a file in the UT directory
std::string cptestFnameInExeDir(const std::string &name);
std::string cptestFnameInSrcDir(const std::string &name);

ACTION_TEMPLATE(
    SaveVoidArgPointee,
    HAS_2_TEMPLATE_PARAMS(int, k, typename, T),
    AND_1_VALUE_PARAMS(output)
)
{
    *output = *static_cast<T *>(::testing::get<k>(args));
}

#endif // __CP_TEST_BASIC_H__
