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

#ifndef __WAAP_SCANNER_H__
#define __WAAP_SCANNER_H__

#include "ParserBase.h"
#include "ScanResult.h"
#include "i_transaction.h"
#include "WaapAssetState.h"
#include <memory>

namespace Waap {
    class Scanner :     public IParserReceiver
    {
    public:
        Scanner(IWaf2Transaction *transaction)
        :
            m_lastScanResult(),
            m_transaction(transaction),
            m_antibotCookie(),
            m_bIgnoreOverride(false)
        {
        }


        bool suspiciousHit(Waf2ScanResult &res, DeepParser &dp,
                const std::string &location, const std::string &param_name, const std::string &key);
        int onKv(const char* k, size_t k_len, const char* v, size_t v_len, int flags, size_t parser_depth) override;

        const std::string &getAntibotCookie() const { return m_antibotCookie; }
        bool getIgnoreOverride() { return m_bIgnoreOverride; };
        const Waf2ScanResult &getLastScanResult() const { return m_lastScanResult; }

        static const std::string xmlEntityAttributeId;
    private:
        double getScoreData(Waf2ScanResult& res, const std::string &poolName);
        bool shouldIgnoreOverride(const Waf2ScanResult &res);
        bool isKeyCspReport(const std::string &key, Waf2ScanResult &res, DeepParser &dp);
        
        Waf2ScanResult m_lastScanResult;
        IWaf2Transaction *m_transaction;
        std::string m_antibotCookie;
        bool m_bIgnoreOverride;
    };
}

#endif // __WAAP_SCANNER_H__
