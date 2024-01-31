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

#ifndef __BASE64_H__
#define __BASE64_H__

#include <string>

class Base64
{
public:
    static std::string encodeBase64(const std::string &input);
    static std::string decodeBase64(const std::string &input);

private:
    static const std::string base64_base;
};

#endif // __BASE64_H__
