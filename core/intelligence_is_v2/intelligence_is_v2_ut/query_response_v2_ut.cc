#include "intelligence_is_v2/query_response_v2.h"
#include "intelligence_is_v2/asset_source_v2.h"
#include "intelligence_is_v2/intelligence_types_v2.h"
#include "intelligence_is_v2/data_string_v2.h"

#include "cptest.h"
#include "debug.h"
#include "intelligence_comp_v2.h"
#include "read_attribute_v2.h"
#include "mock/mock_mainloop.h"
#include "mock/mock_time_get.h"

using namespace std;
using namespace testing;
using namespace Intelligence_IS_V2;

USE_DEBUG_FLAG(D_INTELLIGENCE);

class stringData1
{
public:
    stringData1() {}

    DataString getData() const{ return data;}
    DataString getData1() const{ return data1;}

    template <typename Archive>
    void
    serialize(Archive &ar)
    {
        try{
            ReadAttribute<DataString>("color", data).serialize(ar);
        } catch (exception &e) {
            dbgError(D_INTELLIGENCE) << "Requested attribute was not found: color";
        }
        try {
            ReadAttribute<DataString>("user", data1).serialize(ar);
        } catch (const exception &e) {
            dbgError(D_INTELLIGENCE) << "Requested attribute was not found: user";
        }
    }

private:
    DataString data;
    DataString data1;
};

TEST(QueryResponseTestV2, ReadAttributeTest)
{
    StrictMock<MockMainLoop> mock_ml;
    NiceMock<MockTimeGet> time_get;
    IntelligenceComponentV2 new_intelligence;
    DataString data;
    ReadAttribute<DataString> obj("user", data);

    string data_str(
        "{"
        "    \"net\": \"7.7.7.0/24\","
        "    \"user\": \"Omry\""
        "}"
    );

    stringstream ss(data_str);
    {
        cereal::JSONInputArchive ar(ss);
        obj.serialize(ar);
    }
    EXPECT_EQ(obj.getData().toString(), "Omry");
}

TEST(QueryResponseTestV2, stringData1Test)
{
    StrictMock<MockMainLoop> mock_ml;
    NiceMock<MockTimeGet> time_get;
    IntelligenceComponentV2 new_intelligence;
    DataString data;
    stringData1 obj;
    string data_str(
        "{\n"
        "    \"color\": \"red\",\n"
        "    \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] },\n"
        "    \"user\": \"Omry\"\n"
        "}"
    );


    stringstream ss(data_str);
    {
        cereal::JSONInputArchive ar(ss);
        obj.serialize(ar);
    }
    EXPECT_EQ(obj.getData().toString(), "red");
    EXPECT_EQ(obj.getData1().toString(), "Omry");
}

TEST(QueryResponseTestV2, QueryResponseTestV2)
{
    StrictMock<MockMainLoop> mock_ml;
    NiceMock<MockTimeGet> time_get;
    IntelligenceComponentV2 new_intelligence;
    DataString data;
    IntelligenceQueryResponse<stringData1> obj;
    string data_str(
        "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-ip\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"some-group-id\",\n"
        "      \"name\": \"[1.1.1.1]\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"ip\",\n"
        "      \"group\": \"\",\n"
        "      \"order\": \"\",\n"
        "      \"kind\": \"\",\n"
        "      \"mainAttributes\": {\n"
        "        \"ipv4Addresses\": [\n"
        "          \"1.1.1.1\",\n"
        "          \"2.2.2.2\"\n"
        "        ],\n"
        "        \"phase\": \"testing\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"color\": \"red\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        },\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229bb11\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7bbb11\",\n"
        "          \"assetId\": \"cb068860528cb6bfb000cc35e79f11aeefed2\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 600,\n"
        "          \"attributes\": {\n"
        "            \"color\": \"white\",\n"
        "            \"user\": \"Max\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 2,\n"
        "  \"cursor\": \"start\"\n"
        "}\n"
    );

    stringstream ss(data_str);
    {
        cereal::JSONInputArchive ar(ss);
        obj.loadFromJson(ar);
    }

    EXPECT_EQ(obj.getAmountOfAssets(), 2);
    EXPECT_EQ(obj.getResponseStatus(), ResponseStatus::DONE);
    EXPECT_EQ(obj.getData().begin()->getAssetSchemaVersion(), 1);
    EXPECT_EQ(obj.getData().begin()->getAssetType(), "workload-cloud-ip");
    EXPECT_EQ(obj.getData().begin()->getAssetTypeSchemaVersion(), 1);
    EXPECT_EQ(obj.getData().begin()->getAssetPermissionGroupId(), "some-group-id");
    EXPECT_EQ(obj.getData().begin()->getAssetName(), "[1.1.1.1]");
    EXPECT_EQ(obj.getData().begin()->getAssetClass(), "workload");
    EXPECT_EQ(obj.getData().begin()->getAssetCategory(), "cloud");
    EXPECT_EQ(obj.getData().begin()->getAssetFamily(), "ip");
    EXPECT_EQ(obj.getData().begin()->getAssetGroup(), "");
    EXPECT_EQ(obj.getData().begin()->getAssetOrder(), "");
    EXPECT_EQ(obj.getData().begin()->getAssetKind(), "");

    map<string, vector<string>> attributes_map = obj.getData().begin()->getMainAttributes();
    vector<string>::const_iterator ipv4_it = attributes_map["ipv4Addresses"].begin();
    EXPECT_EQ(*ipv4_it, "1.1.1.1");

    ipv4_it++;
    EXPECT_EQ(*ipv4_it, "2.2.2.2");

    vector<string>::const_iterator phase_it = attributes_map["phase"].begin();
    EXPECT_EQ(*phase_it, "testing");

    vector<SerializableAssetSource<stringData1>>::const_iterator soucres_it =
        obj.getData().begin()->getSources().begin();
    EXPECT_EQ(soucres_it->getTenantId(), "175bb55c-e36f-4ac5-a7b1-7afa1229aa00");
    EXPECT_EQ(soucres_it->getSourceId(), "54d7de10-7b2e-4505-955b-cc2c2c7aaa00");
    EXPECT_EQ(soucres_it->getAssetId(), "50255c3172b4fb7fda93025f0bfaa7abefd1");
    EXPECT_EQ(soucres_it->getTTL(), chrono::seconds(120));
    EXPECT_EQ(soucres_it->getExpirationTime(), "2020-07-29T11:21:12.253Z");
    EXPECT_EQ(soucres_it->getConfidence(), 500);
    EXPECT_EQ(soucres_it->getAttributes().begin()->getData().toString(), "red");
    EXPECT_EQ(soucres_it->getAttributes().begin()->getData1().toString(), "Omry");

    soucres_it++;
    EXPECT_EQ(soucres_it->getTenantId(), "175bb55c-e36f-4ac5-a7b1-7afa1229bb11");
    EXPECT_EQ(soucres_it->getSourceId(), "54d7de10-7b2e-4505-955b-cc2c2c7bbb11");
    EXPECT_EQ(soucres_it->getAssetId(), "cb068860528cb6bfb000cc35e79f11aeefed2");
    EXPECT_EQ(soucres_it->getTTL(), chrono::seconds(120));
    EXPECT_EQ(soucres_it->getExpirationTime(), "2020-07-29T11:21:12.253Z");
    EXPECT_EQ(soucres_it->getConfidence(), 600);
    EXPECT_EQ(soucres_it->getAttributes().begin()->getData().toString(), "white");
    EXPECT_EQ(soucres_it->getAttributes().begin()->getData1().toString(), "Max");

    vector<AssetReply<stringData1>> asset_collections = obj.getData();
    EXPECT_EQ(asset_collections.size(), 1);
    vector<AssetReply<stringData1>>::const_iterator asset_collections_it = asset_collections.begin();
    vector<stringData1> asset_sources = asset_collections_it->getData();
    EXPECT_EQ(asset_sources.size(), 2);
    vector<stringData1>::iterator asset_sources_it = asset_sources.begin();

    EXPECT_EQ(asset_sources_it->getData().toString(), "red");
    EXPECT_EQ(asset_sources_it->getData1().toString(), "Omry");

    asset_sources_it++;
    EXPECT_EQ(asset_sources_it->getData().toString(), "white");
    EXPECT_EQ(asset_sources_it->getData1().toString(), "Max");
}

TEST(QueryResponseTestV2, MainAttributesTestV2)
{
    StrictMock<MockMainLoop> mock_ml;
    NiceMock<MockTimeGet> time_get;
    IntelligenceComponentV2 new_intelligence;
    DataString data;
    IntelligenceQueryResponse<stringData1> obj;
    string string_attribute(
        "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-ip\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"some-group-id\",\n"
        "      \"name\": \"[1.1.1.1]\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"ip\",\n"
        "      \"group\": \"\",\n"
        "      \"order\": \"\",\n"
        "      \"kind\": \"\",\n"
        "      \"mainAttributes\": {\n"
        "        \"team\": \"hapoel\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"color\": \"red\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 1,\n"
        "  \"cursor\": \"start\"\n"
        "}\n"
    );

    stringstream ss(string_attribute);
    {
        cereal::JSONInputArchive ar(ss);
        obj.loadFromJson(ar);
    }

    map<string, vector<string>> attributes_map = obj.getData().begin()->getMainAttributes();
    vector<string>::const_iterator team_it = attributes_map["team"].begin();
    EXPECT_EQ(*team_it, "hapoel");

    string many_strings_attribute(
        "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-ip\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"some-group-id\",\n"
        "      \"name\": \"[1.1.1.1]\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"ip\",\n"
        "      \"group\": \"\",\n"
        "      \"order\": \"\",\n"
        "      \"kind\": \"\",\n"
        "      \"mainAttributes\": {\n"
        "        \"team\": \"hapoel\",\n"
        "        \"city\": \"tel-aviv\",\n"
        "        \"color\": \"red\"\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"color\": \"red\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 1,\n"
        "  \"cursor\": \"start\"\n"
        "}\n"
    );

    stringstream ss2(many_strings_attribute);
    {
        cereal::JSONInputArchive ar(ss2);
        obj.loadFromJson(ar);
    }

    map<string, vector<string>> attributes_map2 = obj.getData().begin()->getMainAttributes();
    vector<string>::const_iterator team_it2 = attributes_map2["team"].begin();
    EXPECT_EQ(*team_it2, "hapoel");
    vector<string>::const_iterator city_it = attributes_map2["city"].begin();
    EXPECT_EQ(*city_it, "tel-aviv");
    vector<string>::const_iterator color_it = attributes_map2["color"].begin();
    EXPECT_EQ(*color_it, "red");

    string strings_vector_attribute(
        "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-ip\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"some-group-id\",\n"
        "      \"name\": \"[1.1.1.1]\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"ip\",\n"
        "      \"group\": \"\",\n"
        "      \"order\": \"\",\n"
        "      \"kind\": \"\",\n"
        "      \"mainAttributes\": {\n"
        "        \"team\": [\n"
        "          \"hapoel\",\n"
        "          \"tel-aviv\"\n"
        "        ]\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"color\": \"red\",\n"
        "            \"user\": \"Omry\",\n"
        "            \"owners\": { \"names\": [ { \"name1\": \"Bob\", \"name2\": \"Alice\" } ] }\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"done\",\n"
        "  \"totalNumAssets\": 1,\n"
        "  \"cursor\": \"start\"\n"
        "}\n"
    );

    stringstream ss3(strings_vector_attribute);
    {
        cereal::JSONInputArchive ar(ss3);
        obj.loadFromJson(ar);
    }

    map<string, vector<string>> attributes_map3 = obj.getData().begin()->getMainAttributes();
    vector<string>::const_iterator team_it3 = attributes_map3["team"].begin();
    EXPECT_EQ(*team_it3, "hapoel");

    team_it3++;
    EXPECT_EQ(*team_it3, "tel-aviv");
}

TEST(QueryResponseTestV2, IntelligenceFailTest)
{
    StrictMock<MockMainLoop> mock_ml;
    NiceMock<MockTimeGet> time_get;
    IntelligenceComponentV2 new_intelligence;
    DataString data;
    IntelligenceQueryResponse<stringData1> obj;
    string status_fail_data_str(
        "{\n"
        "  \"assetCollections\": [\n"
        "    {\n"
        "      \"schemaVersion\": 1,\n"
        "      \"assetType\": \"workload-cloud-ip\",\n"
        "      \"assetTypeSchemaVersion\": 1,\n"
        "      \"permissionType\": \"tenant\",\n"
        "      \"permissionGroupId\": \"fail-group-id\",\n"
        "      \"name\": \"[1.1.1.1]\",\n"
        "      \"class\": \"workload\",\n"
        "      \"category\": \"cloud\",\n"
        "      \"family\": \"ip\",\n"
        "      \"group\": \"\",\n"
        "      \"order\": \"\",\n"
        "      \"kind\": \"\",\n"
        "      \"mainAttributes\": {\n"
        "        \"team\": [\n"
        "          \"FAIL\"\n"
        "        ]\n"
        "      },\n"
        "      \"sources\": [\n"
        "        {\n"
        "          \"tenantId\": \"175bb55c-e36f-4ac5-a7b1-7afa1229aa00\",\n"
        "          \"sourceId\": \"54d7de10-7b2e-4505-955b-cc2c2c7aaa00\",\n"
        "          \"assetId\": \"50255c3172b4fb7fda93025f0bfaa7abefd1\",\n"
        "          \"ttl\": 120,\n"
        "          \"expirationTime\": \"2020-07-29T11:21:12.253Z\",\n"
        "          \"confidence\": 500,\n"
        "          \"attributes\": {\n"
        "            \"color\": \"status\",\n"
        "            \"user\": \"fail\"\n"
        "          }\n"
        "        }\n"
        "      ]\n"
        "    }\n"
        "  ],\n"
        "  \"status\": \"ERROR!!!\",\n"
        "  \"totalNumAssets\": 1,\n"
        "  \"cursor\": \"start\"\n"
        "}\n"
    );

    string error_str = "Received illegal Response Status. Status: ERROR!!!";
    stringstream ss(status_fail_data_str);
    {
        cereal::JSONInputArchive ar(ss);
        try {
            obj.loadFromJson(ar);
        } catch (exception &e) {
            EXPECT_EQ(e.what(), error_str);
        }
    }
}
