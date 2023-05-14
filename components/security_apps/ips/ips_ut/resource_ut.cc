#include "ips_signatures.h"
#include "cptest.h"
#include "environment.h"
#include "config_component.h"

using namespace std;
using namespace testing;

static const string basic_resource =
    "{"
        "\"IPS\": {"
            "\"VersionId\": \"1234567\","
            "\"protections\": ["
                "{"
                    "\"protectionMetadata\": {"
                        "\"protectionName\": \"Null HTTP Encodings\","
                        "\"severity\": \"Medium\","
                        "\"confidenceLevel\": \"High\","
                        "\"performanceImpact\": \"Medium\","
                        "\"lastUpdate\": \"20130101\","
                        "\"maintrainId\": \"8576967832\","
                        "\"tags\": [],"
                        "\"cveList\": [],"
                        "\"silent\": false"
                    "},"
                    "\"detectionRules\": {"
                        "\"type\": \"simple\","
                        "\"SSM\": \"aaaa\","
                        "\"keywords\": \"\","
                        "\"context\": ["
                                "\"HTTP_COMPLETE_URL_ENCODED\""
                        "]"
                    "}"
                "},"
                "{"
                    "\"protectionMetadata\": {"
                        "\"protectionName\": \"Null HTTP Encodings\","
                        "\"severity\": \"Medium\","
                        "\"confidenceLevel\": \"High\","
                        "\"performanceImpact\": \"Medium\","
                        "\"lastUpdate\": \"20130101\","
                        "\"maintrainId\": \"8576967832\","
                        "\"tags\": [],"
                        "\"cveList\": [],"
                        "\"silent\": false"
                    "},"
                    "\"detectionRules\": {"
                        "\"type\": \"simple\","
                        "\"SSM\": \"bbbbb\","
                        "\"keywords\": \"\","
                        "\"context\": ["
                                "\"HTTP_COMPLETE_URL_ENCODED\""
                        "]"
                    "}"
                "}"
            "]"
        "}"
    "}";

TEST(resources, basic_resource)
{
    ConfigComponent conf;
    ::Environment env;

    conf.preload();

    registerExpectedSetting<IPSSignaturesResource>("IPS", "protections");
    registerExpectedSetting<string>("IPS", "VersionId");
    stringstream resource;
    resource << basic_resource;
    Singleton::Consume<Config::I_Config>::from(conf)->loadConfiguration(resource);

    auto loaded_resources = getSettingWithDefault(IPSSignaturesResource(), "IPS", "protections");
    EXPECT_EQ(loaded_resources.getSignatures().size(), 2);
    auto version = getSettingWithDefault<string>("", "IPS", "VersionId");
    EXPECT_EQ(version, "1234567");
}
