// Copyright (C) 2022 Check Point Software Technologies Ltd. All rights reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __WAAP_HYPERSCAN_ENGINE_H__
#define __WAAP_HYPERSCAN_ENGINE_H__

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>

class Signatures;
class SampleValue;
struct Waf2ScanResult;

class WaapHyperscanEngine {
public:

    WaapHyperscanEngine();
    ~WaapHyperscanEngine();

    // Initialize with patterns from Signatures
    bool initialize(const std::shared_ptr<Signatures>& signatures);

    // Main scanning function - same interface as performStandardRegexChecks
    void scanSample(const SampleValue& sample,
        Waf2ScanResult& res,
        bool longTextFound,
        bool binaryDataFound,
        bool includeKeywordRegex,
        bool includePatternRegex) const;

    // Check if the engine is ready to use
    bool isInitialized() const;

    // Get statistics
    size_t getPatternCount() const;
    size_t getCompiledPatternCount() const;
    size_t getFailedPatternCount() const;

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __WAAP_HYPERSCAN_ENGINE_H__
