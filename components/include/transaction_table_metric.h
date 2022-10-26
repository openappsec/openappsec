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

#ifndef __TRANSACTION_TABLE_METRIC_H__
#define __TRANSACTION_TABLE_METRIC_H__

#include "generic_metric.h"

class TransactionTableEvent : public Event<TransactionTableEvent>
{
public:
    void
    setTransactionTableSize(uint64_t _value)
    {
        transaction_table_size = _value;
    }

    uint64_t
    getTransactionTableSize() const
    {
        return transaction_table_size;
    }

private:
    uint64_t transaction_table_size = 0;
};

class TransactionTableMetric
        :
    public GenericMetric,
    public Listener<TransactionTableEvent>
{
public:
    void
    upon(const TransactionTableEvent &event) override
    {
        max_transaction_table_size.report(event.getTransactionTableSize());
        avg_transaction_table_size.report(event.getTransactionTableSize());
        last_report_transaction_handler_size.report(event.getTransactionTableSize());
    }

private:
    MetricCalculations::Max<uint64_t> max_transaction_table_size{this, "maxTransactionTableSizeSample", 0};
    MetricCalculations::Average<double> avg_transaction_table_size{this, "averageTransactionTableSizeSample"};
    MetricCalculations::LastReportedValue<uint64_t> last_report_transaction_handler_size{
        this,
        "lastReportTransactionTableSizeSample"
    };
};

#endif // __TRANSACTION_TABLE_METRIC_H__
