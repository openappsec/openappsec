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

#ifndef __CPTEST_FILE_H__
#define __CPTEST_FILE_H__

// Create a temporary file with some content. Delete on destruction.
class CPTestTempfile
{
public:
    explicit CPTestTempfile(const std::vector<std::string> &lines);
    explicit CPTestTempfile();
    ~CPTestTempfile();

    std::string readFile() const;

    std::string fname;

    // Not copiable (would delete the file twice), but movable
    CPTestTempfile(const CPTestTempfile &other)             = delete;
    CPTestTempfile(CPTestTempfile &&other)                  = default;
    CPTestTempfile & operator=(const CPTestTempfile &other) = delete;
    CPTestTempfile & operator=(CPTestTempfile &&other)      = default;
};


#endif // __CPTEST_FILE_H__
