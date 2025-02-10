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

#ifndef __METRIC_SCRAPER_H__
#define __METRIC_SCRAPER_H__

#include <string>
#include <fstream>
#include <vector>
#include <streambuf>

#include "singleton.h"
#include "debug.h"
#include "component.h"
#include "event.h"
#include "i_rest_api.h"
#include "generic_metric.h"

class MetricScraper
        :
    public Component,
    Singleton::Consume<I_RestApi>
{
public:
    MetricScraper();
    ~MetricScraper();

    void init();

private:
    class Impl;
    std::unique_ptr<Impl> pimpl;
};

#endif // __METRIC_SCRAPER_H__
