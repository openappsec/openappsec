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

#ifndef __CP_TEST_SINGLETON_H__
#define __CP_TEST_SINGLETON_H__

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "singleton.h"

// Mock objects should use Singleton::Provide<I_Face>::From<MockProvider> with the interface they mock.
template<typename I_Face>
class MockProvider : Singleton::Provide<I_Face>
{};

#endif // __CP_TEST_SINGLETON_H__

