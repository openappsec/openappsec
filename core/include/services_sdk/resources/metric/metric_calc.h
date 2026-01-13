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

#ifndef __METRIC_CALC_H__
#define __METRIC_CALC_H__

#ifndef __GENERIC_METRIC_H__
#error metric/metric_calc.h should not be included directly
#endif // __GENERIC_METRIC_H_

#include <cmath>
#include <cereal/archives/json.hpp>

#include "report/report.h"
#include "customized_cereal_map.h"
#include "compression_utils.h"
#include "i_encryptor.h"
#include "event.h"

USE_DEBUG_FLAG(D_METRICS);

class GenericMetric;

enum class MetricType { GAUGE, COUNTER };

struct PrometheusData
{
    template <typename Archive>
    void
    serialize(Archive &ar)
    {
        try {
            ar(cereal::make_nvp("metric_name", name));
            ar(cereal::make_nvp("unique_name", unique_name));
            ar(cereal::make_nvp("metric_type", type));
            ar(cereal::make_nvp("metric_description", description));
            ar(cereal::make_nvp("labels", label));
            ar(cereal::make_nvp("value", value));
        } catch (const cereal::Exception &e) {
            dbgTrace(D_METRICS) << "Error in serialize Prometheus data: " << e.what();
        }
    }

    std::string name;
    std::string unique_name;
    std::string type;
    std::string description;
    std::string label;
    std::string value;
};

class MetricScrapeEvent : public Event<MetricScrapeEvent, std::vector<PrometheusData>>
{
public:
    MetricScrapeEvent() {}

};

class AiopsMetricData
{
public:
    AiopsMetricData(
        const std::string &_name,
        const std::string &_type,
        const std::string &_units,
        const std::string &_description,
        std::map<std::string, std::string> _resource_attributes,
        float _value)
            :
        name(_name),
        type(_type),
        units(_units),
        description(_description),
        resource_attributes(_resource_attributes),
        value(_value)
    {
        timestamp = Singleton::Consume<I_TimeGet>::by<GenericMetric>()->getWalltimeStr();
        // convert timestamp to RFC 3339 format
        std::size_t pos = timestamp.find('.');
        if (pos != std::string::npos) {
            timestamp = timestamp.substr(0, pos) + "Z";
        }
        asset_id = Singleton::Consume<I_AgentDetails>::by<GenericMetric>()->getAgentId();
    }

    void
    serialize(cereal::JSONOutputArchive &ar) const
    {
        ar(cereal::make_nvp("Timestamp", timestamp));
        ar(cereal::make_nvp("MetricName", name));
        ar(cereal::make_nvp("MetricType", type));
        ar(cereal::make_nvp("MetricUnit", units));
        ar(cereal::make_nvp("MetricDescription", description));
        ar(cereal::make_nvp("MetricValue", value));
        ar(cereal::make_nvp("ResourceAttributes", resource_attributes));
        ar(cereal::make_nvp("MetricAttributes", metric_attributes));
        ar(cereal::make_nvp("AssetID", asset_id));
    }

    std::string
    toString() const
    {
        std::stringstream ss;
        {
            cereal::JSONOutputArchive ar(ss);
            serialize(ar);
        }
        return ss.str();
    }

    void
    addMetricAttribute(const std::string &label, const std::string &value)
    {
        metric_attributes[label] = value;
    }

private:
    std::string timestamp = "";
    std::string asset_id = "";
    std::string name;
    std::string type;
    std::string units;
    std::string description;
    std::map<std::string, std::string> resource_attributes;
    std::map<std::string, std::string> metric_attributes;
    float value = 0;
};

class AiopsMetricList
{
public:
    void
    addMetrics(const std::vector<AiopsMetricData> &_metrics)
    {
        metrics.insert(metrics.end(), _metrics.begin(), _metrics.end());
    }

    void
    serialize(cereal::JSONOutputArchive &ar) const
    {
        ar(cereal::make_nvp("Metrics", metrics));
    }

// LCOV_EXCL_START Reason: Tested in unit test (testAIOPSMapMetric), but not detected by coverage
    Maybe<std::string>
    toString() const
    {
        std::stringstream ss;
        {
            cereal::JSONOutputArchive ar(ss);
            serialize(ar);
        }
        auto res = compressAndEncodeData(ss.str());
        if (!res.ok()) {
            return genError("Failed to compress and encode the data");
        }
        return res.unpack();
    }
// LCOV_EXCL_STOP

private:
    Maybe<std::string>
    compressAndEncodeData(const std::string &unhandled_data) const
    {
        std::string data_holder = unhandled_data;
        auto compression_stream = initCompressionStream();
        CompressionResult compression_response = compressData(
            compression_stream,
            CompressionType::GZIP,
            data_holder.size(),
            reinterpret_cast<const unsigned char *>(data_holder.c_str()),
            true
        );
        finiCompressionStream(compression_stream);
        if (!compression_response.ok) {
            // send log to Kibana
            return genError("Failed to compress(gzip) data");
        }

        std::string compressed_data =
            std::string((const char *)compression_response.output, compression_response.num_output_bytes);

        auto encryptor = Singleton::Consume<I_Encryptor>::by<GenericMetric>();
        Maybe<std::string> handled_data = encryptor->base64Encode(compressed_data);

        if (compression_response.output) free(compression_response.output);
        compression_response.output = nullptr;
        compression_response.num_output_bytes = 0;
        return handled_data;
    }

    std::vector<AiopsMetricData> metrics;
};

class CompressAndEncodeAIOPSMetrics
{
public:
    CompressAndEncodeAIOPSMetrics(const AiopsMetricList &_aiops_metrics) : aiops_metrics(_aiops_metrics) {}

    void
    serialize(cereal::JSONOutputArchive &ar) const
    {
        auto metric_str = aiops_metrics.toString();
        if (!metric_str.ok()) {
            return;
        }
        ar(cereal::make_nvp("records", metric_str.unpack()));
    }

// LCOV_EXCL_START Reason: Tested in unit test (testAIOPSMapMetric), but not detected by coverage
    Maybe<std::string>
    toString() const
    {
        std::stringstream ss;
        {
            cereal::JSONOutputArchive ar(ss);
            serialize(ar);
        }
        return ss.str();
    }
// LCOV_EXCL_STOP

private:
    AiopsMetricList aiops_metrics;
};

class MetricCalc
{
public:
    template<typename ... Args>
    MetricCalc(GenericMetric *metric, const std::string &calc_title, const Args & ... args)
    {
        setMetricName(calc_title);
        addMetric(metric);
        parseMetadata(args ...);
    }

    virtual void reset() = 0;
    virtual void save(cereal::JSONOutputArchive &) const = 0;
    virtual LogField getLogField() const = 0;

    std::string getMetricName() const { return getMetadata("BaseName"); }
    std::string getMetricDotName() const { return getMetadata("DotName"); }
    std::string getMetircUnits() const { return getMetadata("Units"); }
    std::string getMetircDescription() const { return getMetadata("Description"); }
    std::string getMetadata(const std::string &metadata) const;
    virtual MetricType getMetricType() const { return MetricType::GAUGE; }
    virtual std::vector<PrometheusData> getPrometheusMetrics(
        const std::string &metric_name,
        const std::string &asset_id = ""
    ) const;
    virtual float getValue() const = 0;
    virtual std::vector<AiopsMetricData> getAiopsMetrics() const;

    void setMetricName(const std::string &name) { setMetadata("BaseName", name); }
    void setMetricDotName(const std::string &name) { setMetadata("DotName", name); }
    void setMetircUnits(const std::string &units) { setMetadata("Units", units); }
    void setMetircDescription(const std::string &description) { setMetadata("Description", description); }
    void setMetadata(const std::string &metadata, const std::string &value);

protected:
    void addMetric(GenericMetric *metric);
    std::map<std::string, std::string> getBasicLabels(
        const std::string &metric_name,
        const std::string &asset_id = ""
    ) const;

    template <typename Metadata, typename ... OtherMetadata>
    void
    parseMetadata(const Metadata &metadata, const OtherMetadata & ... other_metadata)
    {
        parseMetadata(metadata);
        parseMetadata(other_metadata ...);
    }

    void parseMetadata(const MetricMetadata::DotName &name) { setMetricDotName(name.val); }
    void parseMetadata(const MetricMetadata::Units &units) { setMetircUnits(units.val); }
    void parseMetadata(const MetricMetadata::Description &description) { setMetircDescription(description.val); }
    void parseMetadata() {}

private:
    std::map<std::string, std::string> metadata;
};

#endif // __METRIC_CALC_H__
